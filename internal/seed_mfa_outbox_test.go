//go:build momentum_seed

package internal

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"

	"github.com/NeoTecDigital/LumberJack/internal/core"
	"github.com/NeoTecDigital/LumberJack/types"
)

// TestSeedMFAOutboxForDrain is not a unit test: it is the seeder the Julia integrated drain
// (momentum's backend/tests/hub_outbound.jl) shells out to. No MFA-enrolment route exists on the wire
// yet, so an MFA account is planted here in-process instead. It stands the embedded engine up over
// <MOMENTUM_SEED_DIR>/momentum.dat — the exact state file the intercessor opens with name="momentum" —
// plants one MFA-enabled account, drives the engine's OWN login path so a real code lands on the
// external outbox, and leaves the persisted forest for the Julia runtime to open and drain.
//
// It lives behind the `momentum_seed` build tag, so a plain `go test ./...` never compiles it: zero
// cases, zero skips (momentum's scripts/test-all.sh fails the whole run on ANY skipped Go case). With
// the tag on, a missing MOMENTUM_SEED_DIR is a failure rather than a skip — the tag is the opt-in, and a
// seeder that quietly seeds nothing would let the Julia drain read an empty outbox as a false green.
// The Julia side invokes it as:
//
//	MOMENTUM_SEED_DIR=<dir> go test -tags momentum_seed -run TestSeedMFAOutboxForDrain -count=1 ./internal
//
// The planted identity is fictional by default — MOMENTUM_SEED_USER (default seed-user@example.com) and
// MOMENTUM_SEED_PHONE (default 2015550123, a reserved 555-01xx number) override it — and the password is
// MOMENTUM_SEED_PASSWORD or a fresh random value per run. No real identity, credential, or six-digit
// code is written into this file or printed by it.
//
// OBSERVED without the tag (`go test ./internal -run TestSeedMFAOutboxForDrain -count=1 -v`):
//
//	testing: warning: no tests to run
//	ok  	github.com/NeoTecDigital/LumberJack/internal	0.026s [no tests to run]
//
// OBSERVED RED with the tag and no MOMENTUM_SEED_DIR (`go test -tags momentum_seed ./internal -run
// TestSeedMFAOutboxForDrain -count=1`):
//
//	--- FAIL: TestSeedMFAOutboxForDrain (0.00s)
//	    seed_mfa_outbox_test.go:49: MOMENTUM_SEED_DIR unset: the momentum_seed tag opts in to seeding, so a missing target dir is a misuse, not a skip
//	FAIL
func TestSeedMFAOutboxForDrain(t *testing.T) {
	dir := os.Getenv("MOMENTUM_SEED_DIR")
	if dir == "" {
		t.Fatal("MOMENTUM_SEED_DIR unset: the momentum_seed tag opts in to seeding, so a missing target dir is a misuse, not a skip")
	}
	username := os.Getenv("MOMENTUM_SEED_USER")
	if username == "" {
		username = "seed-user@example.com"
	}
	phone := os.Getenv("MOMENTUM_SEED_PHONE")
	if phone == "" {
		phone = "2015550123"
	}
	if len(phone) < 4 {
		t.Fatalf("MOMENTUM_SEED_PHONE %q is shorter than the four digits the login path asks for", phone)
	}
	password := os.Getenv("MOMENTUM_SEED_PASSWORD")
	if password == "" {
		password = seedPassword(t)
	}

	config := types.ServerConfig{
		Organization: "momentum",
		Process: types.ProcessInfo{
			ID: "seed", Name: "momentum", ServerURL: "localhost", ServerPort: "8080",
			LogPath: dir, DatabasePath: dir,
		},
	}
	server, err := NewServer(config, core.User{Username: "admin", Password: "admin"})
	if err != nil {
		t.Fatalf("NewServer over the seed dir: %v", err)
	}

	user := core.User{
		ID: core.GenerateUserID(), Username: username,
		Phone: phone, MFAEnabled: true,
	}
	if err := user.SetPassword(password); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	if err := server.changeForest(func() error {
		return server.forest.AssignUser(user, core.ReadPermission)
	}); err != nil {
		t.Fatalf("AssignUser: %v", err)
	}

	// The engine's own login path: password + the last four of the enrolled number, which enqueues one
	// code on the external outbox and answers a challenge — never a session.
	body := login(t, server, map[string]interface{}{
		"username": username, "password": password, "phone_last4": phone[len(phone)-4:],
	})
	if body.status != 200 {
		t.Fatalf("seed MFA login answered %d, want 200", body.status)
	}
	if required, _ := body.json["mfa_required"].(bool); !required {
		t.Fatalf("seed login did not signal mfa_required: %v", body.json)
	}
	challengeID := challengeIDOf(t, server, body.json["challenge"].(string))
	out := outboundFor(t, server, challengeID)
	if out.To != phone || out.Purpose != "mfa" || out.Channel != "sms" || len(out.Payload) != 6 {
		t.Fatalf("the enqueued item is not a routable six-digit MFA code: %+v", out)
	}
	t.Logf("seeded %s/momentum.dat: one MFA outbox item (challenge=%s, to=%s, six-digit code withheld)",
		dir, challengeID, out.To)
}

// seedPassword is a throwaway credential for the planted account: 32 hex characters from crypto/rand,
// different on every run, never logged. Nothing downstream logs in with it — the Julia drain only reads
// and clears the outbox — so no caller needs to know it.
func seedPassword(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("crypto/rand for the seed password: %v", err)
	}
	return "seed-" + hex.EncodeToString(raw)
}
