// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"image/png"
	"time"

	"github.com/NeoTecDigital/LumberJack/internal/core"
	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
)

func accountQRCode(content string) string {
	code, err := qr.Encode(content, qr.M, qr.Auto)
	if err != nil {
		return ""
	}
	image, err := barcode.Scale(code, 256, 256)
	if err != nil {
		return ""
	}
	var buffer bytes.Buffer
	if png.Encode(&buffer, image) != nil {
		return ""
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(buffer.Bytes())
}

// QR approval starts with a password-proven challenge. Scanning alone grants
// nothing; another live session for the SAME account must explicitly approve.
func (s *Server) beginQRLogin(token string) (any, error) {
	claims, err := s.parseMFAChallengeToken(token)
	if err != nil {
		return nil, err
	}
	var answer map[string]any
	err = s.changeForest(func() error {
		pending, ok := s.forest.MFAChallenges[claims.ChallengeID]
		if !ok || pending.ExpiresAt <= time.Now().Unix() || pending.Attempts >= mfaMaxAttempts || pending.SessionKey != "" || pending.Method == "totp_enroll" {
			return apiErrorf(401, "Invalid or expired challenge")
		}
		profile, err := s.forest.GetUserProfile(claims.UserID)
		if err != nil || !epochIsCurrent(claims.CredentialEpoch, profile.CredentialEpoch) {
			return apiErrorf(401, "Invalid or expired challenge")
		}
		code, err := generateMFACode()
		if err != nil {
			return err
		}
		pending.Method = "qr"
		pending.Target = code
		pending.Approved = false
		s.forest.MFAChallenges[claims.ChallengeID] = pending
		answer = map[string]any{"mfa_required": true, "method": "qr", "challenge": token, "approval_code": code, "qr_image": accountQRCode("momentum:login:" + token), "expires_at": pending.ExpiresAt}
		return nil
	})
	return answer, err
}

func (s *Server) approveQRLogin(userID, token, code string) (any, error) {
	claims, err := s.parseMFAChallengeToken(token)
	if err != nil {
		return nil, err
	}
	if claims.UserID != userID {
		return nil, apiErrorf(403, "Only your own sign-in can be approved")
	}
	err = s.changeForest(func() error {
		pending, ok := s.forest.MFAChallenges[claims.ChallengeID]
		if !ok || pending.Method != "qr" || pending.UserID != userID || pending.ExpiresAt <= time.Now().Unix() {
			return apiErrorf(401, "Invalid or expired challenge")
		}
		profile, err := s.forest.GetUserProfile(userID)
		if err != nil || !epochIsCurrent(claims.CredentialEpoch, profile.CredentialEpoch) {
			return apiErrorf(401, "Invalid or expired challenge")
		}
		if subtle.ConstantTimeCompare([]byte(pending.Target), []byte(code)) != 1 {
			return apiErrorf(403, "Confirmation code does not match")
		}
		pending.Approved = true
		s.forest.MFAChallenges[claims.ChallengeID] = pending
		return nil
	})
	return map[string]any{"approved": err == nil}, err
}

func (s *Server) pollQRLogin(token string) (any, error) {
	claims, err := s.parseMFAChallengeToken(token)
	if err != nil {
		return nil, err
	}
	var user *core.User
	err = s.changeForest(func() error {
		pending, ok := s.forest.MFAChallenges[claims.ChallengeID]
		if !ok || pending.Method != "qr" || pending.ExpiresAt <= time.Now().Unix() {
			return apiErrorf(401, "Invalid or expired challenge")
		}
		profile, err := s.forest.GetUserProfile(claims.UserID)
		if err != nil || profile.LockedUntil > time.Now().Unix() || !epochIsCurrent(claims.CredentialEpoch, profile.CredentialEpoch) {
			return apiErrorf(401, "Invalid or expired challenge")
		}
		if !pending.Approved {
			return nil
		}
		user = &core.User{ID: profile.ID, Username: profile.Username, CredentialEpoch: profile.CredentialEpoch}
		delete(s.forest.MFAChallenges, claims.ChallengeID)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if user == nil {
		return map[string]any{"pending": true}, nil
	}
	return s.accountSessionAnswer(user)
}
