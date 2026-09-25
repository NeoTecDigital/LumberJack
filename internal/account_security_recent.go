// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import "time"

// Reauthentication cannot itself require a recent proof. WebAuthn shares a
// finish route with enrollment, so only a live assertion bound to this exact
// session is eligible to reach verification with an older MFA stamp.
func (s *Server) isSecurityReauthentication(path, userID, key string, input accountSecurityRequest) bool {
	if path == "/account/security" {
		return input.Operation == "reauthenticate" || input.Operation == "verify_factor"
	}
	if path != "/account/webauthn/finish" {
		return false
	}
	claims, err := s.parseMFAChallengeToken(input.Challenge)
	if err != nil || claims.UserID != userID {
		return false
	}
	valid := false
	s.readForest(func() {
		now := time.Now().Unix()
		held, live := s.registeredSessionLocked(key, now)
		pending, exists := s.forest.MFAChallenges[claims.ChallengeID]
		valid = live && held.UserID == userID && epochIsCurrent(claims.CredentialEpoch, held.CredentialEpoch) &&
			exists && pending.UserID == userID && pending.SessionKey == key && pending.Method == "webauthn" &&
			pending.ExpiresAt > now && pending.Attempts < mfaMaxAttempts
	})
	return valid
}
