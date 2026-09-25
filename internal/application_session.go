// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/NeoTecDigital/LumberJack/internal/core"
	"net/http"
	"strings"
	"time"
)

// Browser activity extends the idle window, never the absolute lifetime.
const applicationSessionTTL = 24 * 3600
const applicationSessionIdleTTL = 60 * 60

func applicationSessionDeadline(session core.ApplicationSession) int64 {
	last := session.LastActiveAt
	if last == 0 {
		last = session.CreatedAt
	}
	return min(session.ExpiresAt, session.CreatedAt+applicationSessionTTL, last+applicationSessionIdleTTL)
}

func (s *Server) sessionHash(token string) string {
	h := hmac.New(sha256.New, s.jwtConfig.SecretKey)
	h.Write([]byte(token))
	return hex.EncodeToString(h.Sum(nil))
}

func (s *Server) applicationSession(token string) (core.ApplicationSession, bool) {
	key := s.sessionKeyFromBearer(token)
	return s.registeredSession(key)
}

func (s *Server) registeredSession(key string) (core.ApplicationSession, bool) {
	var session core.ApplicationSession
	valid := false
	s.readForest(func() {
		session, valid = s.registeredSessionLocked(key, time.Now().Unix())
	})
	return session, valid
}

// registeredSessionLocked is the single validity predicate for reads and
// renewal. The caller must hold the forest read or write lock throughout it.
func (s *Server) registeredSessionLocked(key string, now int64) (core.ApplicationSession, bool) {
	session, exists := s.forest.ApplicationSessions[key]
	if !exists {
		return core.ApplicationSession{}, false
	}
	profile, err := s.forest.GetUserProfile(session.UserID)
	if err != nil || profile.LockedUntil > now || applicationSessionDeadline(session) <= now || !epochIsCurrent(session.CredentialEpoch, profile.CredentialEpoch) {
		return core.ApplicationSession{}, false
	}
	if requireAccountMFA() && (session.MFAAt <= 0 || len(securityMethods(s.forest.AccountSecurity[session.UserID], profile)) == 0) {
		return core.ApplicationSession{}, false
	}
	return session, true
}

func (s *Server) serveApplicationSession(next http.HandlerFunc, w http.ResponseWriter, r *http.Request, token string) {
	session, ok := s.applicationSession(token)
	if !ok {
		http.Error(w, "Session expired or signed out", 401)
		return
	}
	ctx := context.WithValue(r.Context(), "user_id", session.UserID)
	ctx, cancel := context.WithDeadline(ctx, time.Unix(applicationSessionDeadline(session), 0))
	defer cancel()
	next(w, r.WithContext(ctx))
}

// mintApplicationSession creates the ms_ bearer and stores its hash, and is FACTORED OUT of
// handleApplicationSession so that the second step at /session/mfa reaches exactly the same mint.
// Two copies of this block would be two places a session's lifetime, its per-account cap and its
// sweep could drift apart — and the MFA path is the one that must not be the weaker of the two.
//
// It returns the token and the expiry, so the caller can answer without re-reading the store.
func (s *Server) mintApplicationSession(userID string) (string, int64, error) {
	return s.mintApplicationSessionAtEpoch(userID, nil)
}

func (s *Server) mintApplicationSessionAtEpoch(userID string, expected *int64) (string, int64, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", 0, apiErrorf(500, "Session unavailable")
	}
	token := "ms_" + hex.EncodeToString(raw)
	var expiresAt int64
	err := s.changeForest(func() error {
		profile, err := s.forest.GetUserProfile(userID)
		if err != nil || profile.LockedUntil > time.Now().Unix() || (expected != nil && !epochIsCurrent(*expected, profile.CredentialEpoch)) {
			return apiErrorf(401, "Account unavailable")
		}
		if s.forest.ApplicationSessions == nil {
			s.forest.ApplicationSessions = map[string]core.ApplicationSession{}
		}
		now := time.Now().Unix()
		count := 0
		oldestKey := ""
		var oldest int64
		for key, item := range s.forest.ApplicationSessions {
			if applicationSessionDeadline(item) <= now {
				delete(s.forest.ApplicationSessions, key)
				continue
			}
			if item.UserID == userID {
				count++
				if oldestKey == "" || item.CreatedAt < oldest {
					oldestKey, oldest = key, item.CreatedAt
				}
			}
		}
		if count >= 20 {
			delete(s.forest.ApplicationSessions, oldestKey)
		}
		expiresAt = now + applicationSessionTTL
		// STAMPED UNDER THE SAME HOLD THAT READ IT. The epoch is taken from the profile above and
		// written here without the lock being released in between, so an enrolment landing at the same
		// moment either precedes this whole block — and the session is born stale — or follows it, and
		// retires the session on its next request. There is no ordering in which it survives.
		s.forest.ApplicationSessions[s.sessionHash(token)] = core.ApplicationSession{
			UserID: userID, CreatedAt: now, LastActiveAt: now, ExpiresAt: expiresAt, CredentialEpoch: profile.CredentialEpoch, MFAAt: now,
		}
		return nil
	})
	if err != nil {
		return "", 0, err
	}
	return token, min(expiresAt, time.Now().Unix()+applicationSessionIdleTTL), nil
}

func (s *Server) handleApplicationSession(w http.ResponseWriter, r *http.Request) {
	s.handleBrowserSession(w, r, false)
}

func (s *Server) handleApplicationActivity(w http.ResponseWriter, r *http.Request) {
	s.handleBrowserSession(w, r, true)
}

func (s *Server) handleBrowserSession(w http.ResponseWriter, r *http.Request, activity bool) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if r.Method == "POST" && !activity {
		var input struct {
			Username string `json:"username"`
			Password string `json:"password"`
			// PhoneLast4 is the pre-send ownership gate, read exactly as /login reads it: the last four
			// digits of the number a code would go to, proving the caller holds the phone before one is
			// sent. It is consulted only when the account carries MFA, and ignored otherwise.
			PhoneLast4 string `json:"phone_last4"`
		}
		if json.NewDecoder(r.Body).Decode(&input) != nil {
			http.Error(w, "Invalid credentials", 400)
			return
		}
		// The SAME credential check /login runs — lockout counter, constant-cost unknown-user compare
		// and ownership gate included. Two implementations of one security decision is two places the
		// weaker one is the real one, and this door used to be the weaker one.
		user, err := s.authenticateCredential(input.Username, input.Password, input.PhoneLast4)
		if err != nil {
			writeAPIError(w, err)
			return
		}
		// THE BYPASS THIS CLOSES. This route minted a session for any account whose password verified,
		// MFA or not — /login had the second factor and /session did not, so the whole gate was optional
		// for every browser client. A verified password on an MFA account now answers a CHALLENGE and
		// nothing else: no token in the body, no session in the store, nothing to authenticate with
		// until /session/mfa verifies a code.
		//
		// A missing or wrong last-four is refused with the SAME 401 a wrong password gets, so the
		// surface carries no MFA-status oracle: a caller holding a stolen password cannot learn whether
		// the account has a second factor, or anything about the number, and triggers no delivery. That
		// uniformity is why the CLIENT always shows the last-four field.
		challenge, err := s.beginAccountLogin(user, input.PhoneLast4)
		if err != nil {
			writeAPIError(w, err)
			return
		}
		if challenge != nil {
			securityJSON(w, challenge)
			return
		}

		minted, _, err := s.mintApplicationSessionAtEpoch(user.ID, &user.CredentialEpoch)
		if err != nil {
			writeAPIError(w, err)
			return
		}
		token = minted
	}
	if r.Method == "DELETE" {
		if err := s.changeForest(func() error { delete(s.forest.ApplicationSessions, s.sessionKeyFromBearer(token)); return nil }); err != nil {
			writeAPIError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"signed_out":true}`))
		return
	}
	session, ok := s.applicationSession(token)
	if !ok {
		http.Error(w, "Session expired or signed out", 401)
		return
	}
	// Session inspection is read-only. Only the explicit activity operation can
	// renew the idle deadline; background reads and streams cannot do so.
	if activity {
		var err error
		session, err = s.renewApplicationSession(s.sessionKeyFromBearer(token))
		if err != nil {
			writeAPIError(w, err)
			return
		}
	}
	s.readForest(func() {
		// A concurrent invalidation during persistence must not produce a valid
		// descriptor after the renewal transaction has released its lock.
		session, ok = s.registeredSessionLocked(s.sessionKeyFromBearer(token), time.Now().Unix())
		if !ok {
			http.Error(w, "Session expired or signed out", 401)
			return
		}
		profile, err := s.forest.GetUserProfile(session.UserID)
		if err != nil {
			http.Error(w, "Account unavailable", 401)
			return
		}
		result := map[string]interface{}{"id": profile.ID, "username": profile.Username, "expires_at": applicationSessionDeadline(session), "absolute_expires_at": min(session.ExpiresAt, session.CreatedAt+applicationSessionTTL)}
		if r.Method == "POST" && !activity {
			result["token"] = token
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	})
}

// handleApplicationSessionMFA is POST /session/mfa: the second half of the exchange /session now
// stops halfway through. It takes the challenge the first step handed back and the code that reached
// the phone, and mints the session the first step withheld — answering the SAME shape /session
// answered in one step, so the relay sets its cookie from one place either way.
//
// It carries NO principal, for the same reason /mfa/verify does not: the session is what this step
// exists to obtain, so demanding one is circular. The challenge bearer IS the authority, and
// consumeMFAChallenge validates it — signature, type, liveness, attempt budget and a constant-time
// code compare — before this ever sees a user. authMiddleware would refuse that bearer as not a
// session, which is why the dispatch in application.go routes here directly.
func (s *Server) handleApplicationSessionMFA(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Challenge string `json:"challenge"`
		Code      string `json:"code"`
	}
	if json.NewDecoder(r.Body).Decode(&input) != nil {
		http.Error(w, "Invalid request", 400)
		return
	}
	user, err := s.consumeMFAChallenge(input.Challenge, input.Code)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	token, expiresAt, err := s.mintApplicationSessionAtEpoch(user.ID, &user.CredentialEpoch)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id": user.ID, "username": user.Username, "expires_at": expiresAt, "token": token, "absolute_expires_at": time.Now().Unix() + applicationSessionTTL,
	})
}

// renewApplicationSession is the activity write shared by the HTTP handler and
// deterministic tests that invalidate an account after a successful read.
func (s *Server) renewApplicationSession(key string) (core.ApplicationSession, error) {
	var session core.ApplicationSession
	err := s.changeForest(func() error {
		now := time.Now().Unix()
		held, valid := s.registeredSessionLocked(key, now)
		if !valid {
			return apiErrorf(401, "Session expired or signed out")
		}
		held.LastActiveAt = now
		s.forest.ApplicationSessions[key] = held
		session = held
		return nil
	})
	if err != nil {
		return core.ApplicationSession{}, err
	}
	return session, nil
}
