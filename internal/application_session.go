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

// applicationSessionTTL is how long a minted ms_ bearer lives. It is a named constant because BOTH
// mints — the password-only one and the second-factor one — read it, and because the relay's cookie
// max-age has to be told the same number.
//
// A DAY, not the thirty it was. Thirty days was inherited rather than chosen, and a browser session
// that outlives a stolen laptop by a month is a credential nobody remembers issuing; a day is long
// enough that a working day never asks twice and short enough that a lost device stops mattering by
// tomorrow. The refresh path is where a longer life is earned, and it re-checks the account.
const applicationSessionTTL = 24 * 3600

func (s *Server) sessionHash(token string) string {
	h := hmac.New(sha256.New, s.jwtConfig.SecretKey)
	h.Write([]byte(token))
	return hex.EncodeToString(h.Sum(nil))
}

func (s *Server) applicationSession(token string) (core.ApplicationSession, bool) {
	var session core.ApplicationSession
	valid := false
	s.readForest(func() {
		session, valid = s.forest.ApplicationSessions[s.sessionHash(token)]
		if valid {
			profile, err := s.forest.GetUserProfile(session.UserID)
			// The epoch comes off the profile this read ALREADY had to fetch, so withdrawing a cookie
			// an administrator has superseded costs one integer comparison and no extra work: a session
			// opened while the account was password-only stops the moment it carries a second factor.
			valid = err == nil &&
				session.ExpiresAt > time.Now().Unix() &&
				epochIsCurrent(session.CredentialEpoch, profile.CredentialEpoch)
		}
	})
	return session, valid
}

func (s *Server) serveApplicationSession(next http.HandlerFunc, w http.ResponseWriter, r *http.Request, token string) {
	session, ok := s.applicationSession(token)
	if !ok {
		http.Error(w, "Session expired or signed out", 401)
		return
	}
	ctx := context.WithValue(r.Context(), "user_id", session.UserID)
	ctx, cancel := context.WithDeadline(ctx, time.Unix(session.ExpiresAt, 0))
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
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", 0, apiErrorf(500, "Session unavailable")
	}
	token := "ms_" + hex.EncodeToString(raw)
	var expiresAt int64
	err := s.changeForest(func() error {
		profile, err := s.forest.GetUserProfile(userID)
		if err != nil {
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
			if item.ExpiresAt <= now {
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
			UserID: userID, CreatedAt: now, ExpiresAt: expiresAt, CredentialEpoch: profile.CredentialEpoch,
		}
		return nil
	})
	if err != nil {
		return "", 0, err
	}
	return token, expiresAt, nil
}

func (s *Server) handleApplicationSession(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if r.Method == "POST" {
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
		if user.MFAEnabled {
			challenge, err := s.beginMFAChallenge(user)
			if err != nil {
				writeAPIError(w, err)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"mfa_required": true, "challenge": challenge})
			return
		}
		minted, _, err := s.mintApplicationSession(user.ID)
		if err != nil {
			writeAPIError(w, err)
			return
		}
		token = minted
	}
	if r.Method == "DELETE" {
		if err := s.changeForest(func() error { delete(s.forest.ApplicationSessions, s.sessionHash(token)); return nil }); err != nil {
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
	s.readForest(func() {
		profile, err := s.forest.GetUserProfile(session.UserID)
		if err != nil {
			http.Error(w, "Account unavailable", 401)
			return
		}
		result := map[string]interface{}{"id": profile.ID, "username": profile.Username, "expires_at": session.ExpiresAt}
		if r.Method == "POST" {
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
	token, expiresAt, err := s.mintApplicationSession(user.ID)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id": user.ID, "username": user.Username, "expires_at": expiresAt, "token": token,
	})
}
