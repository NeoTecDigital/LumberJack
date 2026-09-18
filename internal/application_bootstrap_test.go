package internal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

// THE SILENT DIVERGENCE THIS ENDS. ConfigureApplication reads an admin username and password out of
// the environment and creates that account — unless the datastore already holds users, in which case
// it returned successfully having done NOTHING. That is the right default: a bootstrap that reset the
// administrator's password on every start would hand the environment file a permanent key to the
// installation. But it said nothing, so an environment whose password no longer matched the stored
// hash looked exactly like one that did, and the only symptom was a login that would not work. It was
// measured here: the local datastore's admin stopped matching backend/.env after a reset, and nothing
// in any log said so.
//
// So: a populated store now says loudly that it left the account alone, and there is ONE explicit,
// opt-in way to repair the mismatch — CORRESPONDER_ADMIN_RECONCILE=1, which resets that one account's
// password from the environment and nothing else. Off by default, because the default must never be
// "the environment file overwrites the database".

// bootstrapKey is a throwaway signing key of the length ConfigureApplication demands. It signs
// nothing that outlives the test.
const bootstrapKey = "bootstrap-test-key-0123456789abcdef"

// readServerLog reads the durable log a stock server writes, which is where a bootstrap line has to
// land to be of any use to whoever is reading it at three in the morning.
func readServerLog(t *testing.T, dir string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "stock_process.log"))
	if err != nil {
		t.Fatalf("the server wrote no log to read: %v", err)
	}
	return string(raw)
}

// adminHash reads the stored credential of the named account, which is the thing these cases are
// about leaving alone or replacing.
func adminHash(t *testing.T, server *Server, username string) string {
	t.Helper()
	hash := ""
	found := false
	server.readForest(func() {
		for i := range server.forest.Users {
			if server.forest.Users[i].Username == username {
				hash, found = server.forest.Users[i].Password, true
				return
			}
		}
	})
	if !found {
		t.Fatalf("the forest holds no account named %q", username)
	}
	return hash
}

// TestBootstrapSaysLoudlyThatItLeftTheAdminAlone is the default path: a populated store keeps its
// accounts, and now SAYS SO, naming the variable that would change it.
//
// OBSERVED RED (before the line existed,
// `go test ./internal -run TestBootstrap -count=1`):
//
//	--- FAIL: TestBootstrapSaysLoudlyThatItLeftTheAdminAlone (0.04s)
//	    application_bootstrap_test.go:81: the bootstrap said nothing about leaving the admin alone
//	    application_bootstrap_test.go:84: the bootstrap did not name CORRESPONDER_ADMIN_RECONCILE
func TestBootstrapSaysLoudlyThatItLeftTheAdminAlone(t *testing.T) {
	server, dir := newStockServer(t)
	before := adminHash(t, server, "admin")

	if err := server.ConfigureApplication("admin", "a-different-password", bootstrapKey); err != nil {
		t.Fatalf("ConfigureApplication: %v", err)
	}

	log := readServerLog(t, dir)
	if !strings.Contains(log, "was NOT created or updated") {
		t.Errorf("the bootstrap said nothing about leaving the admin alone")
	}
	if !strings.Contains(log, "CORRESPONDER_ADMIN_RECONCILE") {
		t.Errorf("the bootstrap did not name CORRESPONDER_ADMIN_RECONCILE")
	}
	if after := adminHash(t, server, "admin"); after != before {
		t.Errorf("the default bootstrap rewrote the stored credential")
	}
	if strings.Contains(log, "a-different-password") {
		t.Errorf("the bootstrap wrote the configured password into the log")
	}
}

// TestBootstrapReconcilesOnlyWhenAskedAndOnlyTheAdmin is the repair: with the flag set, the
// configured admin's password becomes the environment's, every other account is untouched, and the
// line says what happened without saying what the password is.
//
// OBSERVED RED (before the repair existed, same run):
//
//	--- FAIL: TestBootstrapReconcilesOnlyWhenAskedAndOnlyTheAdmin (0.11s)
//	    application_bootstrap_test.go:116: the reconciled admin does not verify the configured password
//	    application_bootstrap_test.go:127: the bootstrap did not report the repair
func TestBootstrapReconcilesOnlyWhenAskedAndOnlyTheAdmin(t *testing.T) {
	t.Setenv("CORRESPONDER_ADMIN_RECONCILE", "1")
	server, dir := newStockServer(t)
	bystander := addPasswordUser(t, server, "bystander", "the-bystanders-password")
	bystanderBefore := adminHash(t, server, bystander.Username)

	if err := server.ConfigureApplication("admin", "the-reconciled-password", bootstrapKey); err != nil {
		t.Fatalf("ConfigureApplication: %v", err)
	}

	reconciled := core.User{Password: adminHash(t, server, "admin")}
	if !reconciled.VerifyPassword("the-reconciled-password") {
		t.Errorf("the reconciled admin does not verify the configured password")
	}
	if !strings.HasPrefix(reconciled.Password, "$2") {
		t.Errorf("the reconciled credential is not a bcrypt hash: %q", reconciled.Password)
	}
	if after := adminHash(t, server, bystander.Username); after != bystanderBefore {
		t.Errorf("the repair rewrote an account it was not asked about")
	}

	log := readServerLog(t, dir)
	if !strings.Contains(log, "CORRESPONDER_ADMIN_RECONCILE=1") || !strings.Contains(log, "reset the password") {
		t.Errorf("the bootstrap did not report the repair")
	}
	if strings.Contains(log, "the-reconciled-password") {
		t.Errorf("the repair wrote the configured password into the log")
	}
}

// TestBootstrapReconcileSaysSoWhenTheAccountIsNotThere. The repair updates ONE named account; it does
// not create one, because a populated forest keeping its identities is the rule the repair is an
// exception to, not a rule it overturns. A name nobody holds is a misconfiguration, and silence about
// it is exactly the failure this whole slice exists to end.
//
// OBSERVED RED (before the repair existed, same run):
//
//	--- FAIL: TestBootstrapReconcileSaysSoWhenTheAccountIsNotThere (0.04s)
//	    application_bootstrap_test.go:154: the bootstrap said nothing about the missing account
func TestBootstrapReconcileSaysSoWhenTheAccountIsNotThere(t *testing.T) {
	t.Setenv("CORRESPONDER_ADMIN_RECONCILE", "1")
	server, dir := newStockServer(t)
	usersBefore := len(server.forest.Users)

	if err := server.ConfigureApplication("no-such-operator", "the-reconciled-password", bootstrapKey); err != nil {
		t.Fatalf("ConfigureApplication: %v", err)
	}

	if !strings.Contains(readServerLog(t, dir), "no account named") {
		t.Errorf("the bootstrap said nothing about the missing account")
	}
	if after := len(server.forest.Users); after != usersBefore {
		t.Errorf("the repair created %d account(s); it updates one, it does not create one", after-usersBefore)
	}
}

// TestBootstrapStillCreatesTheAdminOnAnEmptyStore. The whole point of the default path is that a
// FRESH install is still bootstrapped — the loud line and the flag are about a populated one, and
// neither may get in the way of the first start.
//
// OBSERVED RED (before the change, this passed — it is the regression guard for the two cases above,
// which is the only honest thing to say about it).
func TestBootstrapStillCreatesTheAdminOnAnEmptyStore(t *testing.T) {
	server, _ := newStockServer(t)
	// A store holding only the system user is the "empty" this branch means.
	if err := server.changeForest(func() error {
		server.forest.Users = []core.User{{ID: SystemUserID, Username: "system"}}
		return nil
	}); err != nil {
		t.Fatalf("empty the forest: %v", err)
	}

	if err := server.ConfigureApplication("first-operator", "the-first-password", bootstrapKey); err != nil {
		t.Fatalf("ConfigureApplication: %v", err)
	}
	created := core.User{Password: adminHash(t, server, "first-operator")}
	if !created.VerifyPassword("the-first-password") {
		t.Errorf("a fresh store did not get its configured administrator")
	}
}
