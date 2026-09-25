// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/NeoTecDigital/LumberJack/internal/core"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// Only isolated fixtures and development may opt out. Production defaults to MFA.
func requireAccountMFA() bool { return os.Getenv("MOMENTUM_REQUIRE_MFA") != "false" }

func securityJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(value)
}

func securityMethods(account core.AccountSecurity, user *core.User) []string {
	methods := []string{}
	if account.TOTPSecret != "" {
		methods = append(methods, "totp")
	}
	if len(account.Passkeys) != 0 {
		methods = append(methods, "webauthn")
	}
	if user.MFAEnabled && user.Phone != "" {
		methods = append(methods, "sms")
	}
	if account.VerifiedEmail != "" {
		methods = append(methods, "email")
	}
	if len(account.RecoveryHashes) != 0 {
		methods = append(methods, "recovery")
	}
	return methods
}

// beginAccountLogin owns factor selection after password validation, for both
// browser and bearer exchanges. Enrollment challenges grant no resource access.
func (s *Server) beginAccountLogin(user *core.User, last4 string) (map[string]any, error) {
	var account core.AccountSecurity
	s.readForest(func() { account = s.forest.AccountSecurity[user.ID] })
	methods := securityMethods(account, user)
	if len(methods) == 0 && !requireAccountMFA() {
		return nil, nil
	}
	method := "totp_enroll"
	if len(methods) != 0 {
		method = methods[0]
	}
	if method == "sms" {
		if last4 == "" {
			return map[string]any{"mfa_required": true, "phone_required": true}, nil
		}
		challenge, err := s.beginMFAChallenge(user)
		return map[string]any{"mfa_required": true, "method": "sms", "challenge": challenge, "methods": methods}, err
	}
	target := ""
	if method == "email" {
		target = account.VerifiedEmail
	}
	return s.newAccountChallenge(user, method, target, "")
}

func (s *Server) newAccountChallenge(user *core.User, method, target, sessionKey string) (map[string]any, error) {
	id, err := newChallengeID()
	if err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	challenge := core.MFAChallenge{UserID: user.ID, Method: method, Target: target, SessionKey: sessionKey, CreatedAt: now, ExpiresAt: now + int64(mfaCodeTTL.Seconds())}
	answer := map[string]any{"mfa_required": true, "method": method}
	if method == "totp_enroll" {
		key, err := totp.Generate(totp.GenerateOpts{Issuer: "Momentum", AccountName: user.Username, SecretSize: 32})
		if err != nil {
			return nil, err
		}
		challenge.Secret = key.Secret()
		answer["secret"], answer["otpauth_uri"] = key.Secret(), key.URL()
		answer["qr_image"] = accountQRCode(key.URL())
	}
	if method == "webauthn" || method == "webauthn_enroll" {
		options, session, err := s.beginPasskey(user, method == "webauthn_enroll")
		if err != nil {
			return nil, err
		}
		challenge.Ceremony = session
		answer["public_key"] = options
	}
	code := ""
	if method == "email" || method == "email_enroll" || method == "sms_enroll" || method == "sms" {
		code, err = generateMFACode()
		if err != nil {
			return nil, err
		}
		challenge.CodeHash, challenge.Sends, challenge.LastSendAt = s.mfaCodeHash(code), 1, now
	}
	err = s.changeForest(func() error {
		profile, err := s.forest.GetUserProfile(user.ID)
		if err != nil || !epochIsCurrent(user.CredentialEpoch, profile.CredentialEpoch) {
			return apiErrorf(401, "Account unavailable")
		}
		if s.forest.MFAChallenges == nil {
			s.forest.MFAChallenges = map[string]core.MFAChallenge{}
		}
		s.sweepMFAChallenges(now, user.ID)
		s.forest.MFAChallenges[id] = challenge
		answer["methods"] = securityMethods(s.forest.AccountSecurity[user.ID], profile)
		if code != "" {
			channel := "sms"
			if strings.HasPrefix(method, "email") {
				channel = "email"
			}
			state := s.correspondenceState()
			if state.Outbound == nil {
				state.Outbound = map[string]core.OutboundMessage{}
			}
			state.Outbound[id] = core.OutboundMessage{ID: id, Channel: channel, Purpose: "mfa", To: target, Payload: code, ChallengeID: id, UserID: user.ID, CreatedAt: now, ExpiresAt: challenge.ExpiresAt}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	answer["challenge"], err = s.mintChallengeToken(user, id, challenge.ExpiresAt)
	return answer, err
}

// checkAccountFactor runs under the forest write lock. It records replay state
// in the same transaction that consumes the challenge. It never mints a session.
func (s *Server) checkAccountFactor(challenge core.MFAChallenge, code string, now int64) bool {
	account := s.forest.AccountSecurity[challenge.UserID]
	switch challenge.Method {
	case "totp", "totp_enroll":
		secret := account.TOTPSecret
		if challenge.Method == "totp_enroll" {
			// Competing enrollments cannot replace a factor after one was proven.
			if secret != "" {
				return false
			}
			secret = challenge.Secret
		}
		step := int64(0)
		for delta := int64(-1); delta <= 1; delta++ {
			candidate := now/30 + delta
			if candidate <= account.TOTPLastStep {
				continue
			}
			valid, _ := totp.ValidateCustom(code, secret, time.Unix(candidate*30, 0), totp.ValidateOpts{Period: 30, Skew: 0, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
			if valid {
				step = candidate
				break
			}
		}
		if step == 0 {
			return false
		}
		account.TOTPSecret, account.TOTPLastStep = secret, step
	case "recovery":
		match := -1
		for index, hash := range account.RecoveryHashes {
			if subtle.ConstantTimeCompare([]byte(hash), []byte(s.mfaCodeHash(strings.ToUpper(strings.TrimSpace(code))))) == 1 {
				match = index
			}
		}
		if match < 0 {
			return false
		}
		account.RecoveryHashes = append(account.RecoveryHashes[:match], account.RecoveryHashes[match+1:]...)
	case "email", "email_enroll", "sms_enroll", "sms", "":
		if subtle.ConstantTimeCompare([]byte(challenge.CodeHash), []byte(s.mfaCodeHash(code))) != 1 {
			return false
		}
		if challenge.Method == "email_enroll" {
			account.VerifiedEmail = challenge.Target
		}
		if challenge.Method == "sms_enroll" {
			for index := range s.forest.Users {
				if s.forest.Users[index].ID == challenge.UserID {
					s.forest.Users[index].Phone = challenge.Target
					s.forest.Users[index].MFAEnabled = true
				}
			}
		}
	default:
		return false
	}
	if s.forest.AccountSecurity == nil {
		s.forest.AccountSecurity = map[string]core.AccountSecurity{}
	}
	s.forest.AccountSecurity[challenge.UserID] = account
	return true
}

// Public factor changes require the same live, password-proven challenge.
// Enrollment-only challenges cannot be converted to login or recovery factors.
func (s *Server) selectAccountFactor(challengeToken, method, last4 string) (map[string]any, error) {
	claims, err := s.parseMFAChallengeToken(challengeToken)
	if err != nil {
		return nil, err
	}
	var user *core.User
	var target string
	var previous core.MFAChallenge
	err = s.changeForest(func() error {
		pending, ok := s.forest.MFAChallenges[claims.ChallengeID]
		if !ok || pending.ExpiresAt <= time.Now().Unix() || pending.Attempts >= mfaMaxAttempts || pending.SessionKey != "" || strings.HasSuffix(pending.Method, "_enroll") {
			return apiErrorf(401, "Invalid or expired challenge")
		}
		profile, err := s.forest.GetUserProfile(claims.UserID)
		if err != nil || !epochIsCurrent(claims.CredentialEpoch, profile.CredentialEpoch) {
			return apiErrorf(401, "Invalid or expired challenge")
		}
		account := s.forest.AccountSecurity[profile.ID]
		allowed := false
		for _, available := range securityMethods(account, profile) {
			if available == method {
				allowed = true
			}
		}
		if !allowed {
			return apiErrorf(400, "Factor is not enrolled")
		}
		if method == "email" {
			target = account.VerifiedEmail
		}
		if method == "sms" {
			if !phoneLast4Matches(profile.Phone, last4) {
				return apiErrorf(401, "Invalid credentials")
			}
			target = profile.Phone
		}
		copy := *profile
		user = &copy
		previous = pending
		delete(s.forest.MFAChallenges, claims.ChallengeID)
		return nil
	})
	if err != nil {
		return nil, err
	}
	answer, err := s.newAccountChallenge(user, method, target, "")
	if err != nil {
		return nil, err
	}
	next, err := s.parseMFAChallengeToken(answer["challenge"].(string))
	if err != nil {
		return nil, err
	}
	err = s.changeForest(func() error {
		pending := s.forest.MFAChallenges[next.ChallengeID]
		pending.Attempts = previous.Attempts
		pending.ExpiresAt = min(pending.ExpiresAt, previous.ExpiresAt)
		s.forest.MFAChallenges[next.ChallengeID] = pending
		return nil
	})
	return answer, err
}
