package internal

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/NeoTecDigital/LumberJack/internal/core"
	"github.com/golang-jwt/jwt"
)

// The second factor, and where its authority sits: entirely in Go. A verified password mints a
// short-lived "mfa_pending" challenge and nothing else; only handleMfaVerify — comparing a code
// against a keyed hash on the forest, under the exclusive hold, attempt-limited and TTL-swept —
// reaches generateTokenPair. The code is generated here, hashed before it is stored, handed to the
// external outbox in plaintext for delivery, and never returned to the caller or written to a log.

const (
	// mfaCodeTTL is how long a challenge and its code live. Short, because the code is a bearer
	// secret in flight and an unfinished login should not outlast the attention that started it.
	mfaCodeTTL = 5 * time.Minute
	// mfaMaxAttempts is the per-challenge guess budget. On the Nth wrong code the challenge is
	// destroyed, so a stolen challenge token cannot be brute-forced against a six-digit space.
	mfaMaxAttempts = 5
	// mfaChallengeCap bounds how many live challenges one account may hold, so a flood of logins
	// cannot grow the forest without limit; the oldest is evicted first, exactly as sessions are.
	mfaChallengeCap = 20
	// mfaCodeDigits is the code's length; 000000..999999.
	mfaCodeSpace = 1000000
)

// mfaCodeHash is the keyed hash a challenge stores in place of the code. It is domain-separated from
// sessionHash by a prefix, so a code hash and an application-session hash can never collide even on
// the same input, and it is HMAC rather than a bare digest so the state file alone does not let an
// offline guesser confirm a code without the signing key.
func (s *Server) mfaCodeHash(code string) string {
	mac := hmac.New(sha256.New, s.jwtConfig.SecretKey)
	mac.Write([]byte("mfa\x00" + code))
	return hex.EncodeToString(mac.Sum(nil))
}

// generateMFACode draws a uniform six-digit code from the cryptographic source. big.Int keeps it
// unbiased where a byte-and-modulo would skew the low digits.
func generateMFACode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(mfaCodeSpace))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// newChallengeID mints the opaque key a challenge is stored and addressed by. It is carried in the
// challenge token's claims, never guessed by the client.
func newChallengeID() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// mintChallengeToken signs the "mfa_pending" bearer the caller holds between the two login steps. It
// can do NOTHING but be verified: authMiddleware refuses it (token_type is not "session"), and only
// verifyMFAChallenge accepts it. ChallengeID rides in the claims so the store lookup needs no body
// field the client could forge.
func (s *Server) mintChallengeToken(user *core.User, challengeID string, expiresAt int64) (string, error) {
	claims := TokenClaims{
		UserID:      user.ID,
		Username:    user.Username,
		TokenType:   "mfa_pending",
		ChallengeID: challengeID,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expiresAt,
			IssuedAt:  time.Now().Unix(),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.jwtConfig.SecretKey)
}

// parseMFAChallengeToken validates a submitted challenge bearer and hands back its claims. The
// signing method is pinned to HMAC so an "alg:none" token cannot walk through, and the type and the
// challenge id are both required, so nothing but a freshly minted challenge is honoured.
func (s *Server) parseMFAChallengeToken(tokenString string) (*TokenClaims, error) {
	if tokenString == "" {
		return nil, apiErrorf(http.StatusUnauthorized, "No challenge provided")
	}
	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.jwtConfig.SecretKey, nil
	})
	if err != nil || !token.Valid {
		return nil, apiErrorf(http.StatusUnauthorized, "Invalid or expired challenge")
	}
	claims, ok := token.Claims.(*TokenClaims)
	if !ok || claims.TokenType != "mfa_pending" || claims.ChallengeID == "" {
		return nil, apiErrorf(http.StatusUnauthorized, "Invalid or expired challenge")
	}
	return claims, nil
}

// beginMFAChallenge is the send half, called from handleLogin once the password AND the ownership
// gate have passed. It generates a code, stores only its hash with an attempt count and a short
// expiry on the forest, enqueues the plaintext for external delivery, and returns the challenge
// bearer. The code is never returned from here.
func (s *Server) beginMFAChallenge(user *core.User) (string, error) {
	code, err := generateMFACode()
	if err != nil {
		return "", err
	}
	challengeID, err := newChallengeID()
	if err != nil {
		return "", err
	}
	now := time.Now().Unix()
	expiresAt := now + int64(mfaCodeTTL.Seconds())
	if err := s.changeForest(func() error {
		if _, err := s.forest.GetUserProfile(user.ID); err != nil {
			return apiErrorf(http.StatusUnauthorized, "Account unavailable")
		}
		s.sweepMFAChallenges(now, user.ID)
		if s.forest.MFAChallenges == nil {
			s.forest.MFAChallenges = map[string]core.MFAChallenge{}
		}
		s.forest.MFAChallenges[challengeID] = core.MFAChallenge{
			UserID:    user.ID,
			CodeHash:  s.mfaCodeHash(code),
			Attempts:  0,
			CreatedAt: now,
			ExpiresAt: expiresAt,
		}
		s.enqueueOutboundMFA(user, challengeID, code, now, expiresAt)
		return nil
	}); err != nil {
		return "", err
	}
	return s.mintChallengeToken(user, challengeID, expiresAt)
}

// enqueueOutboundMFA hands the plaintext code to the external outbox under the challenge id, and
// sweeps expired items in passing so a code never lingers past its window. It is called INSIDE the
// exclusive hold, so the store and its pending delivery are one durable snapshot. The engine wires
// no transport: a forward-dispatcher role, built elsewhere, drains this by Channel/Purpose.
func (s *Server) enqueueOutboundMFA(user *core.User, challengeID, code string, now, expiresAt int64) {
	state := s.correspondenceState()
	if state.Outbound == nil {
		state.Outbound = map[string]core.OutboundMessage{}
	}
	for id, item := range state.Outbound {
		if item.ExpiresAt <= now {
			delete(state.Outbound, id)
		}
	}
	state.Outbound[challengeID] = core.OutboundMessage{
		ID:          challengeID,
		Channel:     "sms",
		Purpose:     "mfa",
		To:          user.Phone,
		Payload:     code,
		ChallengeID: challengeID,
		UserID:      user.ID,
		CreatedAt:   now,
		ExpiresAt:   expiresAt,
	}
}

// sweepMFAChallenges drops every expired challenge and, if the account is at its cap, the oldest
// live one. It mirrors the application-session sweep and runs under the exclusive hold.
func (s *Server) sweepMFAChallenges(now int64, userID string) {
	if s.forest.MFAChallenges == nil {
		return
	}
	count := 0
	oldestKey := ""
	var oldest int64
	for key, item := range s.forest.MFAChallenges {
		if item.ExpiresAt <= now {
			delete(s.forest.MFAChallenges, key)
			continue
		}
		if item.UserID == userID {
			count++
			if oldestKey == "" || item.CreatedAt < oldest {
				oldestKey, oldest = key, item.CreatedAt
			}
		}
	}
	if count >= mfaChallengeCap && oldestKey != "" {
		delete(s.forest.MFAChallenges, oldestKey)
	}
}

// verifyMFAChallenge is the verify half and the ONLY path to a full session behind MFA. It compares
// in constant time, counts the attempt durably (the change commits whether the code was right or
// wrong, so a crash cannot reset a lockout), destroys the challenge on success, on lockout and on a
// structural failure, and mints the pair only when the code matched a live challenge for an account
// that still exists.
func (s *Server) verifyMFAChallenge(challengeToken, code string) (*TokenPair, error) {
	claims, err := s.parseMFAChallengeToken(challengeToken)
	if err != nil {
		return nil, err
	}
	var verified *core.User
	var outcome *apiError
	if persistErr := s.changeForest(func() error {
		outcome, verified = nil, nil
		now := time.Now().Unix()
		challenge, ok := s.forest.MFAChallenges[claims.ChallengeID]
		if !ok || challenge.ExpiresAt <= now {
			if ok {
				delete(s.forest.MFAChallenges, claims.ChallengeID)
			}
			outcome = apiErrorf(http.StatusUnauthorized, "Invalid or expired challenge")
			return nil
		}
		if challenge.Attempts >= mfaMaxAttempts {
			delete(s.forest.MFAChallenges, claims.ChallengeID)
			outcome = apiErrorf(http.StatusUnauthorized, "Too many attempts; request a new code")
			return nil
		}
		if subtle.ConstantTimeCompare([]byte(challenge.CodeHash), []byte(s.mfaCodeHash(code))) != 1 {
			challenge.Attempts++
			if challenge.Attempts >= mfaMaxAttempts {
				delete(s.forest.MFAChallenges, claims.ChallengeID)
				outcome = apiErrorf(http.StatusUnauthorized, "Too many attempts; request a new code")
			} else {
				s.forest.MFAChallenges[claims.ChallengeID] = challenge
				outcome = apiErrorf(http.StatusUnauthorized, "Invalid code; %d attempts remaining", mfaMaxAttempts-challenge.Attempts)
			}
			return nil
		}
		profile, err := s.forest.GetUserProfile(challenge.UserID)
		if err != nil {
			delete(s.forest.MFAChallenges, claims.ChallengeID)
			outcome = apiErrorf(http.StatusUnauthorized, "Account unavailable")
			return nil
		}
		verified = &core.User{ID: profile.ID, Username: profile.Username}
		delete(s.forest.MFAChallenges, claims.ChallengeID)
		return nil
	}); persistErr != nil {
		return nil, persistErr
	}
	if outcome != nil {
		return nil, outcome
	}
	return s.generateTokenPair(verified)
}

// resendMFAChallenge is the /mfa/start half: swap a fresh code into an existing live challenge and
// re-enqueue it, resetting the attempt count but NOT extending the expiry, so a resend cannot keep a
// challenge alive indefinitely. The challenge id is unchanged, so the bearer the client already
// holds stays valid.
func (s *Server) resendMFAChallenge(challengeToken string) error {
	claims, err := s.parseMFAChallengeToken(challengeToken)
	if err != nil {
		return err
	}
	code, err := generateMFACode()
	if err != nil {
		return err
	}
	var outcome *apiError
	if persistErr := s.changeForest(func() error {
		outcome = nil
		now := time.Now().Unix()
		challenge, ok := s.forest.MFAChallenges[claims.ChallengeID]
		if !ok || challenge.ExpiresAt <= now {
			if ok {
				delete(s.forest.MFAChallenges, claims.ChallengeID)
			}
			outcome = apiErrorf(http.StatusUnauthorized, "Invalid or expired challenge")
			return nil
		}
		profile, err := s.forest.GetUserProfile(challenge.UserID)
		if err != nil {
			delete(s.forest.MFAChallenges, claims.ChallengeID)
			outcome = apiErrorf(http.StatusUnauthorized, "Account unavailable")
			return nil
		}
		challenge.CodeHash = s.mfaCodeHash(code)
		challenge.Attempts = 0
		s.forest.MFAChallenges[claims.ChallengeID] = challenge
		s.enqueueOutboundMFA(&core.User{ID: profile.ID, Phone: profile.Phone}, claims.ChallengeID, code, now, challenge.ExpiresAt)
		return nil
	}); persistErr != nil {
		return persistErr
	}
	if outcome != nil {
		return outcome
	}
	return nil
}

// handleMfaVerify is POST /mfa/verify. It reads the challenge from the body, not the principal — the
// caller holds no session yet — so the Julia layer lets it through without one and Go validates the
// challenge itself. On success it answers the same token pair a password-only login does.
func (s *Server) handleMfaVerify(w http.ResponseWriter, r *http.Request) {
	s.logger.Enter("handleMfaVerify")
	defer s.logger.Exit("handleMfaVerify")

	var input struct {
		Challenge string `json:"challenge"`
		Code      string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	pair, err := s.verifyMFAChallenge(input.Challenge, input.Code)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"session_token": pair.SessionToken,
		"refresh_token": pair.RefreshToken,
	})
	s.logger.Success("MFA verification succeeded")
}

// handleMfaStart is POST /mfa/start: resend the code for a challenge already in flight. It carries
// no code out to the caller either — only the phone receives one.
func (s *Server) handleMfaStart(w http.ResponseWriter, r *http.Request) {
	s.logger.Enter("handleMfaStart")
	defer s.logger.Exit("handleMfaStart")

	var input struct {
		Challenge string `json:"challenge"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	if err := s.resendMFAChallenge(input.Challenge); err != nil {
		writeAPIError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"mfa_required":true,"resent":true}`))
	s.logger.Success("MFA code resent")
}
