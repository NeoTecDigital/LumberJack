// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/NeoTecDigital/LumberJack/core"
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
	token, err := newSessionToken()
	if err != nil {
		return "", 0, err
	}
	var session core.ApplicationSession
	err = s.changeForest(func() error {
		var err error
		session, err = s.registerSessionLocked(userID, expected, token)
		return err
	})
	if err != nil {
		return "", 0, err
	}
	return token, min(session.ExpiresAt, time.Now().Unix()+applicationSessionIdleTTL), nil
}

// newSessionToken is a fresh ms_ bearer.
func newSessionToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", apiErrorf(500, "Session unavailable")
	}
	return "ms_" + hex.EncodeToString(raw), nil
}

// registerSessionLocked stores a bearer's hash as a session of the account, under the exclusive
// hold, refusing an account that is gone, shut, or no longer on the epoch the caller verified it
// under.
//
// STAMPED UNDER THE SAME HOLD THAT READ IT. The epoch is taken from the profile and written without
// the lock being released in between, so an enrolment landing at the same moment either precedes
// this whole block — and the session is born stale — or follows it, and retires the session on its
// next request. There is no ordering in which it survives.
func (s *Server) registerSessionLocked(userID string, expected *int64, token string) (core.ApplicationSession, error) {
	profile, err := s.forest.GetUserProfile(userID)
	if err != nil || profile.LockedUntil > time.Now().Unix() || (expected != nil && !epochIsCurrent(*expected, profile.CredentialEpoch)) {
		return core.ApplicationSession{}, apiErrorf(401, "Account unavailable")
	}
	now := time.Now().Unix()
	s.sweepApplicationSessionsLocked(userID, now)
	session := core.ApplicationSession{
		UserID: userID, CreatedAt: now, LastActiveAt: now, ExpiresAt: now + applicationSessionTTL, CredentialEpoch: profile.CredentialEpoch, MFAAt: now,
	}
	s.forest.ApplicationSessions[s.sessionHash(token)] = session
	return session, nil
}

// sweepApplicationSessionsLocked drops what has expired and makes room for one more of userID's.
func (s *Server) sweepApplicationSessionsLocked(userID string, now int64) {
	if s.forest.ApplicationSessions == nil {
		s.forest.ApplicationSessions = map[string]core.ApplicationSession{}
	}
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
		username, password, login, err := decodeLogin(r, "browser")
		if err != nil {
			http.Error(w, "Invalid credentials", 400)
			return
		}
		// The SAME credential check /login runs — lockout counter and constant-cost unknown-user
		// compare included. Two implementations of one security decision is two places the weaker one
		// is the real one, and this door used to be the weaker one.
		user, err := s.authenticateCredential(username, password)
		if err != nil {
			writeAPIError(w, err)
			return
		}
		// THE BYPASS THIS CLOSES. This route once minted a session for any account whose password
		// verified, second factor or not. It now asks the same question /login does: a registered
		// SecondFactor's challenge is answered in place of a session, and without one an enrolled
		// account fails closed.
		challenge, err := s.passwordVerified(r.Context(), user, login)
		if err != nil {
			writeAPIError(w, err)
			return
		}
		if challenge != nil {
			writeChallenge(w, challenge)
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
		if err := s.changeForest(func() error { s.endApplicationSessionLocked(s.sessionKeyFromBearer(token)); return nil }); err != nil {
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

// endApplicationSessionLocked forgets a session. A delegated one takes the rest of its family with
// it: renewal leaves the previous lease running for a stream still using it, so sign-out has to end
// every lease its source session holds or it would end only the newest.
func (s *Server) endApplicationSessionLocked(key string) {
	session, exists := s.forest.ApplicationSessions[key]
	delete(s.forest.ApplicationSessions, key)
	if !exists || !session.Delegated {
		return
	}
	for other, held := range s.forest.ApplicationSessions {
		if held.Delegated && held.UserID == session.UserID && held.SourceSession == session.SourceSession {
			delete(s.forest.ApplicationSessions, other)
		}
	}
}
