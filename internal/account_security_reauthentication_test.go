// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

func TestStalePasskeyReauthenticationOnlyAdmitsBoundAssertion(t *testing.T) {
	// Observed red before the route-bound guard: own assertion "status=403;
	// expected 401", forged QR operation "status=401; expected 403", and forged
	// enrollment operation "status=200; expected 403" (FAIL, 0.681s).
	t.Setenv("MOMENTUM_REQUIRE_MFA", "true")
	t.Setenv("MOMENTUM_WEBAUTHN_RP_ID", "localhost")
	t.Setenv("MOMENTUM_WEBAUTHN_ORIGINS", "http://localhost")
	for _, name := range []string{"own assertion", "other session", "public login", "enrollment", "expired", "exhausted", "arbitrary challenge", "forged QR operation", "forged enrollment operation"} {
		t.Run(name, func(t *testing.T) {
			s, _ := newStockServer(t)
			user := addPasswordUser(t, s, "stepup", "fixture-password")
			s.forest.AccountSecurity = map[string]core.AccountSecurity{user.ID: {TOTPSecret: "JBSWY3DPEHPK3PXP"}}
			token, _, err := s.mintApplicationSession(user.ID)
			if err != nil {
				t.Fatal(err)
			}
			key := s.sessionHash(token)
			held := s.forest.ApplicationSessions[key]
			held.MFAAt = time.Now().Unix() - 301
			s.forest.ApplicationSessions[key] = held
			pending := core.MFAChallenge{UserID: user.ID, Method: "webauthn", SessionKey: key, ExpiresAt: time.Now().Unix() + 120, Ceremony: []byte(`{}`)}
			switch name {
			case "other session":
				pending.SessionKey = "different-session"
			case "public login":
				pending.SessionKey = ""
			case "enrollment":
				pending.Method = "webauthn_enroll"
			case "expired":
				pending.ExpiresAt = time.Now().Unix() - 1
			case "exhausted":
				pending.Attempts = mfaMaxAttempts
			}
			s.forest.MFAChallenges = map[string]core.MFAChallenge{"stepup": pending}
			challenge, err := s.mintChallengeToken(&user, "stepup", time.Now().Unix()+120)
			if err != nil {
				t.Fatal(err)
			}
			target := "/account/webauthn/finish"
			input := map[string]any{"challenge": challenge, "credential": map[string]any{}}
			switch name {
			case "arbitrary challenge":
				input["challenge"] = "not-a-challenge"
			case "forged QR operation":
				target = "/account/qr/approve"
				input["operation"] = "reauthenticate"
			case "forged enrollment operation":
				target = "/account/webauthn/begin"
				input["operation"] = "verify_factor"
			}
			body, _ := json.Marshal(input)
			answer := s.ApplicationCall(ApplicationRequest{Method: "POST", Target: target, Headers: map[string]string{"Authorization": "Bearer " + token}, Body: body})
			want := 403
			if name == "own assertion" {
				want = 401
			} // Malformed proof reaches cryptographic verification, never authenticates.
			if answer.Status != want {
				t.Fatalf("status=%d; expected %d", answer.Status, want)
			}
			if s.forest.ApplicationSessions[key].MFAAt != held.MFAAt {
				t.Fatal("invalid assertion renewed the MFA stamp")
			}
			if name == "own assertion" && s.forest.MFAChallenges["stepup"].Attempts != 1 {
				t.Fatal("assertion never reached factor verification")
			}
		})
	}
}
