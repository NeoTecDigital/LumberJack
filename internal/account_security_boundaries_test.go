// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

// RED (2026-09-21): factor switching reset budget/deadline; revoked refresh
// returned 500; incorrect QR confirmation was accepted (200). All three failed
// in 0.293s before the corresponding guards and preserved deadlines were added.

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

func TestFactorSwitchPreservesChallengeBudget(t *testing.T) {
	t.Setenv("MOMENTUM_REQUIRE_MFA", "true")
	s, _ := newStockServer(t)
	u := addPasswordUser(t, s, "factor-owner", "fixture-password")
	s.forest.AccountSecurity = map[string]core.AccountSecurity{u.ID: {TOTPSecret: "JBSWY3DPEHPK3PXP", RecoveryHashes: []string{s.mfaCodeHash("AABBCCDDEEFF001122334455")}}}
	start := decodeApplication(t, applicationCall(t, s, "POST", "/session", map[string]string{"username": u.Username, "password": "fixture-password"}))
	claims, _ := s.parseMFAChallengeToken(start["challenge"].(string))
	pending := s.forest.MFAChallenges[claims.ChallengeID]
	pending.Attempts = 4
	pending.ExpiresAt = time.Now().Unix() + 40
	s.forest.MFAChallenges[claims.ChallengeID] = pending
	next, err := s.selectAccountFactor(start["challenge"].(string), "recovery", "")
	if err != nil {
		t.Fatal(err)
	}
	claims, _ = s.parseMFAChallengeToken(next["challenge"].(string))
	replacement := s.forest.MFAChallenges[claims.ChallengeID]
	if replacement.Attempts != 4 || replacement.ExpiresAt != pending.ExpiresAt {
		t.Fatal("changing factors reset the attempt budget or deadline")
	}
}

func TestRevokedJWTRefreshReturnsUnauthorized(t *testing.T) {
	s, _ := newStockServer(t)
	u := addPasswordUser(t, s, "revoke-owner", "fixture-password")
	pair, err := s.generateTokenPair(&u)
	if err != nil {
		t.Fatal(err)
	}
	key := s.sessionKeyFromBearer(pair.SessionToken)
	delete(s.forest.ApplicationSessions, key)
	answer := applicationCall(t, s, "POST", "/refresh", map[string]string{"refresh_token": pair.RefreshToken})
	if answer.Status != 401 {
		t.Fatalf("revoked refresh status=%d; expected 401", answer.Status)
	}
}

func TestQRApprovalRequiresMatchingConfirmation(t *testing.T) {
	s, _ := newStockServer(t)
	u := addMFAUser(t, s)
	challenge, err := s.beginMFAChallenge(&u)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.beginQRLogin(challenge); err != nil {
		t.Fatal(err)
	}
	token, _, _ := s.mintApplicationSession(u.ID)
	encoded, _ := json.Marshal(map[string]string{"challenge": challenge, "code": "wrong"})
	answer := s.ApplicationCall(ApplicationRequest{Method: "POST", Target: "/account/qr/approve", Headers: map[string]string{"Authorization": "Bearer " + token}, Body: encoded})
	if answer.Status != 403 {
		t.Fatalf("QR approved without matching confirmation: %d", answer.Status)
	}
}
