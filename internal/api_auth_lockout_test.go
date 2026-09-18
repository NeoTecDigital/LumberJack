package internal

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NeoTecDigital/LumberJack/internal/core"
	"github.com/NeoTecDigital/LumberJack/types"
)

// WHAT AN UNLIMITED LOGIN IS. A six-character password against a route that answers in milliseconds
// and counts nothing is not a credential, it is a delay. The relay's per-IP bucket bounds how fast
// ONE source may ask; it cannot bound how many times ONE ACCOUNT is guessed at, because a botnet
// spends a different IP per attempt. The two limits are different mechanisms answering different
// questions, and this is the account half: consecutive misses are counted ON THE ACCOUNT, durably,
// through whichever door they arrive at.
//
// These cases name none of the new fields on purpose, so they are red for BEHAVIOUR rather than for
// a build failure — they fail against the engine as it was, which is the only red worth pasting.

// addPasswordUser plants an ordinary account with a password that works, which is what a lockout
// test needs: something to get wrong ten times and right once.
func addPasswordUser(t *testing.T, server *Server, username, password string) core.User {
	t.Helper()
	user := core.User{ID: core.GenerateUserID(), Username: username}
	if err := user.SetPassword(password); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	if err := server.changeForest(func() error {
		return server.forest.AssignUser(user, core.ReadPermission)
	}); err != nil {
		t.Fatalf("AssignUser: %v", err)
	}
	return user
}

// passwordLogin sends a password to POST /login through the router, and reports only the status —
// which on this path is the whole answer.
func passwordLogin(t *testing.T, server *Server, username, password string) int {
	t.Helper()
	return serve(t, server, jsonRequest(t, "POST", "/login", map[string]interface{}{
		"username": username, "password": password,
	})).Code
}

// openSession sends a password to the application surface's POST /session.
func openSession(t *testing.T, server *Server, username, password string) ApplicationResponse {
	t.Helper()
	return applicationCall(t, server, "POST", "/session", map[string]string{"username": username, "password": password})
}

// TestTenPasswordMissesLockTheAccount is the counter itself: ten consecutive misses and the RIGHT
// password stops working, because the account — not the request — is what is refused.
//
// OBSERVED RED (before the counter existed,
// `go test ./internal -run TestTenPasswordMissesLockTheAccount -count=1`):
//
//	--- FAIL: TestTenPasswordMissesLockTheAccount (0.48s)
//	    api_auth_lockout_test.go:76: after 10 misses the correct password answered 200; the account is not locked
func TestTenPasswordMissesLockTheAccount(t *testing.T) {
	server, _ := newStockServer(t)
	user := addPasswordUser(t, server, "lockme-account", "the-real-password")

	for attempt := 0; attempt < loginFailureLimit; attempt++ {
		if code := passwordLogin(t, server, user.Username, "not-the-password"); code != http.StatusUnauthorized {
			t.Fatalf("miss %d answered %d, want 401", attempt+1, code)
		}
	}
	if code := passwordLogin(t, server, user.Username, "the-real-password"); code != http.StatusUnauthorized {
		t.Errorf("after %d misses the correct password answered %d; the account is not locked", loginFailureLimit, code)
	}
}

// TestBothDoorsShareOneLockout. /login and /session are two entrances to one credential, so a
// counter kept by either alone is a counter an attacker steps around by using the other. Misses
// spent on the application surface lock the account against the API surface, and the refusal there
// is the SAME uniform 401 — no "locked" oracle either.
//
// OBSERVED RED (before the counter existed, same run):
//
//	--- FAIL: TestBothDoorsShareOneLockout (0.52s)
//	    api_auth_lockout_test.go:101: after 10 misses at /session, /login with the correct password answered 200
//	    api_auth_lockout_test.go:105: a locked account at /session answered 200 "{\"expires_at\":1792364850,\"id\":\"user-...\",\"token\":\"ms_508cce380282...\",\"username\":\"lockme-both\"}\n"; want the uniform 401
func TestBothDoorsShareOneLockout(t *testing.T) {
	server, _ := newStockServer(t)
	user := addPasswordUser(t, server, "lockme-both", "the-real-password")

	for attempt := 0; attempt < loginFailureLimit; attempt++ {
		if response := openSession(t, server, user.Username, "not-the-password"); response.Status != http.StatusUnauthorized {
			t.Fatalf("miss %d at /session answered %d, want 401", attempt+1, response.Status)
		}
	}
	if code := passwordLogin(t, server, user.Username, "the-real-password"); code != http.StatusUnauthorized {
		t.Errorf("after %d misses at /session, /login with the correct password answered %d", loginFailureLimit, code)
	}
	locked := openSession(t, server, user.Username, "the-real-password")
	if locked.Status != http.StatusUnauthorized || string(locked.Body) != "Invalid credentials\n" {
		t.Errorf("a locked account at /session answered %d %q; want the uniform 401", locked.Status, string(locked.Body))
	}
}

// TestASuccessfulLoginClearsTheMissCounter. The budget is CONSECUTIVE misses, not lifetime ones: a
// counter that only goes up locks out every long-lived account eventually, which is a denial of
// service the mechanism inflicts on its own users. Nine, a success, nine more, and a success still
// works.
//
// OBSERVED RED (before the counter existed, same run — the case passes vacuously with no counter at
// all, so it is paired with the two above: it is what keeps the FIX from being "never unlock").
func TestASuccessfulLoginClearsTheMissCounter(t *testing.T) {
	server, _ := newStockServer(t)
	user := addPasswordUser(t, server, "lockme-reset", "the-real-password")

	for round := 0; round < 2; round++ {
		for attempt := 0; attempt < loginFailureLimit-1; attempt++ {
			if code := passwordLogin(t, server, user.Username, "not-the-password"); code != http.StatusUnauthorized {
				t.Fatalf("round %d miss %d answered %d, want 401", round, attempt+1, code)
			}
		}
		if code := passwordLogin(t, server, user.Username, "the-real-password"); code != http.StatusOK {
			t.Fatalf("round %d: the correct password answered %d after %d misses; the budget is CONSECUTIVE", round, code, loginFailureLimit-1)
		}
	}
}

// TestALockoutSurvivesARestart. The counter lives on the account in the forest, so it is written by
// the same changeForest every other account fact is — which means a bounce of the process is not a
// way to clear it. It also proves the new fields reach the state file without naming them.
//
// OBSERVED RED (before the counter existed, same run):
//
//	--- FAIL: TestALockoutSurvivesARestart (0.48s)
//	    api_auth_lockout_test.go:159: after a reload the correct password answered 200; the lockout did not persist
func TestALockoutSurvivesARestart(t *testing.T) {
	server, dir := newStockServer(t)
	user := addPasswordUser(t, server, "lockme-restart", "the-real-password")

	for attempt := 0; attempt < loginFailureLimit; attempt++ {
		if code := passwordLogin(t, server, user.Username, "not-the-password"); code != http.StatusUnauthorized {
			t.Fatalf("miss %d answered %d, want 401", attempt+1, code)
		}
	}

	loaded, err := LoadServer(types.ServerConfig{
		Process: types.ProcessInfo{ID: "stock_process", Name: "stock", LogPath: dir, DatabasePath: dir},
	})
	if err != nil {
		t.Fatalf("LoadServer: %v", err)
	}
	loaded.jwtConfig = server.jwtConfig
	if code := passwordLogin(t, loaded, user.Username, "the-real-password"); code != http.StatusUnauthorized {
		t.Errorf("after a reload the correct password answered %d; the lockout did not persist", code)
	}
}

// TestAnUnknownUserCostsAPasswordCompare closes a USER-ENUMERATION side channel. A login for an
// account that does not exist returned before doing any work, while a login for one that does spent
// a bcrypt compare — tens of milliseconds, trivially measurable over a network — so the uniform
// "Invalid credentials" told the attacker nothing and the clock told it everything.
//
// The assertion is a RATIO with a wide margin, not a threshold: both samples are taken in the same
// run on the same machine, and the gap the defect leaves is three orders of magnitude, not three
// percent. Minimum-of-five, because the minimum is the sample least disturbed by a noisy host.
//
// OBSERVED RED (before the dummy compare existed, same run):
//
//	--- FAIL: TestAnUnknownUserCostsAPasswordCompare (0.26s)
//	    api_auth_lockout_test.go:196: an unknown user cost 212.777µs and a known one 36.788507ms: the clock says which accounts exist
func TestAnUnknownUserCostsAPasswordCompare(t *testing.T) {
	server, _ := newStockServer(t)
	user := addPasswordUser(t, server, "timing-known", "the-real-password")

	fastest := func(username string) time.Duration {
		best := time.Duration(1<<62 - 1)
		for sample := 0; sample < 5; sample++ {
			started := time.Now()
			passwordLogin(t, server, username, "not-the-password")
			if spent := time.Since(started); spent < best {
				best = spent
			}
		}
		return best
	}
	known := fastest(user.Username)
	unknown := fastest("timing-nobody-here")

	if unknown*3 < known {
		t.Errorf("an unknown user cost %v and a known one %v: the clock says which accounts exist", unknown, known)
	}
}

// TestAuthLogsNameNoUsernames. The log is the one artifact of a login that outlives the request, and
// it was writing the attempted username on every path — so a log shipped anywhere, or read by anyone
// with the file, is a list of valid accounts and of the near-misses people typed, which include each
// other's passwords often enough to matter. Nothing on the auth path names an account any more.
//
// OBSERVED RED (before the names were dropped, same run):
//
//	--- FAIL: TestAuthLogsNameNoUsernames (0.19s)
//	    api_auth_lockout_test.go:230: the log names "logged-account": ℹ Attempting login for user: logged-account
//	    api_auth_lockout_test.go:230: the log names "logged-account": ✗ Invalid password for user: logged-account
//	    api_auth_lockout_test.go:230: the log names "logged-account": ✓ Login successful for user logged-account
//	    api_auth_lockout_test.go:230: the log names "a-typo-of-a-name": ✗ User not found: a-typo-of-a-name
func TestAuthLogsNameNoUsernames(t *testing.T) {
	server, dir := newStockServer(t)
	user := addPasswordUser(t, server, "logged-account", "the-real-password")

	passwordLogin(t, server, user.Username, "not-the-password")
	passwordLogin(t, server, user.Username, "the-real-password")
	passwordLogin(t, server, "a-typo-of-a-name", "the-real-password")
	openSession(t, server, user.Username, "not-the-password")

	raw, err := os.ReadFile(filepath.Join(dir, "stock_process.log"))
	if err != nil {
		t.Fatalf("the server wrote no log to read: %v", err)
	}
	for _, name := range []string{"logged-account", "a-typo-of-a-name"} {
		if !strings.Contains(string(raw), name) {
			continue
		}
		for _, line := range strings.Split(string(raw), "\n") {
			if strings.Contains(line, name) {
				t.Errorf("the log names %q: %s", name, strings.TrimSpace(line))
			}
		}
	}
}

// TestApplicationSessionLastsADayNotAMonth. A browser session that outlives a stolen laptop by a
// month is a credential nobody remembers issuing. Thirty days was inherited, not chosen.
//
// OBSERVED RED (before the TTL changed, same run):
//
//	--- FAIL: TestApplicationSessionLastsADayNotAMonth (0.11s)
//	    api_auth_lockout_test.go:260: the session runs for 720h0m0s, want 24h0m0s
func TestApplicationSessionLastsADayNotAMonth(t *testing.T) {
	server, _ := newStockServer(t)
	user := addPasswordUser(t, server, "day-long", "the-real-password")

	response := openSession(t, server, user.Username, "the-real-password")
	if response.Status != http.StatusOK {
		t.Fatalf("/session answered %d: %q", response.Status, string(response.Body))
	}
	var body struct {
		ExpiresAt int64 `json:"expires_at"`
	}
	if err := json.Unmarshal(response.Body, &body); err != nil {
		t.Fatalf("the answer was not JSON: %q", string(response.Body))
	}
	lifetime := time.Duration(body.ExpiresAt-time.Now().Unix()) * time.Second
	if lifetime > 24*time.Hour || lifetime < 23*time.Hour+59*time.Minute {
		t.Errorf("the session runs for %v, want %v", lifetime, 24*time.Hour)
	}
}

// TestRefreshRefusesAPrincipalThatIsGoneOrLocked. A refresh token lives a week and was honoured on
// its SIGNATURE alone — the handler read the claims and minted a fresh session without ever asking
// whether the account still existed. So deleting an account did not end its sessions, and locking
// one did not stop it: the holder refreshed straight past both for seven days.
//
// OBSERVED RED (before the re-validation existed, same run):
//
//	--- FAIL: TestRefreshRefusesAPrincipalThatIsGoneOrLocked (0.45s)
//	    api_auth_lockout_test.go:290: refresh for an account nobody holds answered 200
//	    api_auth_lockout_test.go:296: refresh for a locked account answered 200
func TestRefreshRefusesAPrincipalThatIsGoneOrLocked(t *testing.T) {
	server, _ := newStockServer(t)
	user := addPasswordUser(t, server, "refresher", "the-real-password")

	refreshFor := func(id, username string) int {
		pair, err := server.generateTokenPair(&core.User{ID: id, Username: username})
		if err != nil {
			t.Fatalf("generateTokenPair: %v", err)
		}
		return serve(t, server, jsonRequest(t, "POST", "/refresh", map[string]interface{}{
			"refresh_token": pair.RefreshToken,
		})).Code
	}

	if code := refreshFor("user-nobody-holds", "ghost"); code != http.StatusUnauthorized {
		t.Errorf("refresh for an account nobody holds answered %d", code)
	}
	for attempt := 0; attempt < loginFailureLimit; attempt++ {
		passwordLogin(t, server, user.Username, "not-the-password")
	}
	if code := refreshFor(user.ID, user.Username); code != http.StatusUnauthorized {
		t.Errorf("refresh for a locked account answered %d", code)
	}
}
