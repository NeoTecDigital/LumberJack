// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

// RED (2026-09-21): TestMandatoryMFAEnrollmentAndTOTPReplay:
// password alone bypassed mandatory MFA: <nil> (0.11s).
import (
	"github.com/pquerna/otp/totp"
	"testing"
	"time"
)

func TestMandatoryMFAEnrollmentAndTOTPReplay(t *testing.T) {
	t.Setenv("MOMENTUM_REQUIRE_MFA", "true")
	s, _ := newStockServer(t)
	u := addPasswordUser(t, s, "new-person", "test-password")
	answer := applicationCall(t, s, "POST", "/session", map[string]string{"username": u.Username, "password": "test-password"})
	if answer.Status != 200 {
		t.Fatal(string(answer.Body))
	}
	body := decodeApplication(t, answer)
	if body["mfa_required"] != true || body["method"] != "totp_enroll" {
		t.Fatalf("password alone bypassed mandatory MFA: %v", body["method"])
	}
	if len(s.forest.ApplicationSessions) != 0 {
		t.Fatal("enrollment granted workspace access")
	}
	secret := body["secret"].(string)
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	verified := applicationCall(t, s, "POST", "/session/mfa", map[string]string{"challenge": body["challenge"].(string), "code": code})
	if verified.Status != 200 {
		t.Fatal(string(verified.Body))
	}
	next := decodeApplication(t, applicationCall(t, s, "POST", "/session", map[string]string{"username": u.Username, "password": "test-password"}))
	replay := applicationCall(t, s, "POST", "/session/mfa", map[string]string{"challenge": next["challenge"].(string), "code": code})
	if replay.Status != 401 {
		t.Fatal("TOTP replay accepted across login challenges")
	}
}
