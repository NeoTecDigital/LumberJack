// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package embedded

import (
	engine "github.com/NeoTecDigital/LumberJack/internal"
	"github.com/NeoTecDigital/LumberJack/products/pngstore"
	"strings"
	"testing"
)

type pngWorkloadSetup struct {
	*pngWorkloadRun
	job, associate, thread pngstore.Record
}

func pngWorkloadProvisioned(t *testing.T) *pngWorkloadSetup {
	t.Helper()
	run := pngWorkloadStart(t, t.TempDir())
	run.scope = engine.DomainScope{AccountID: "labelled-account", Product: "manifest"}
	run.provision()
	run.authority.targetRevision = pngWorkloadRevision
	job := run.asAdministrator(run.newRow("business:job", nil))[0]
	associate := run.asAdministrator(run.newRow("business:associate", map[string]interface{}{"full_name": "LABELLED person"}))[0]
	thread := run.asAdministrator(run.newRow(pngWorkloadThreads, map[string]interface{}{"title": "LABELLED thread"}))[0]
	return &pngWorkloadSetup{pngWorkloadRun: run, job: job, associate: associate, thread: thread}
}

func (run *pngWorkloadSetup) grant() {
	run.t.Helper()
	if err := run.readGrantChange(pngWorkloadGrantOperation, pngWorkloadPrincipal, pngWorkloadRevision); err != nil {
		run.t.Fatal("workload grant refused", err)
	}
}

const pngWorkloadGrantOperation = engine.EnrollmentWorkloadGrant

func (run *pngWorkloadSetup) refused(label string, proof pngWorkloadProof, request pngstore.Request, mode string) {
	run.t.Helper()
	before := run.revision
	if _, err := run.as(proof, request, mode); err == nil {
		run.t.Fatalf("%s was allowed", label)
	}
	run.refreshRevision()
	if run.revision != before {
		run.t.Fatalf("%s was refused but changed the forest", label)
	}
}

func TestPNGWorkloadWritesWithNoOneSignedIn(t *testing.T) {
	run := pngWorkloadProvisioned(t)
	proof := pngWorkloadValidProof()
	run.grant()
	run.refreshRevision()
	message := run.newRow("resource:png.messages", map[string]interface{}{"text": "LABELLED message", "direction": "inbound"})
	contact := run.newRow(pngWorkloadContacts, map[string]interface{}{"phone_number": "LABELLED phone"})
	body, err := run.as(proof, run.command(message, contact), "command")
	if err != nil {
		t.Fatal("the workload's own list was refused", err)
	}
	created := pngWorkloadRecords(t, body)
	if len(created) != 2 {
		t.Fatalf("created %d rows", len(created))
	}
	for family, fields := range map[string][]string{"resource:png.messages": {"id", "account_id", "text"}, pngWorkloadThreads: {"id", "title"}, pngWorkloadContacts: {"id", "phone_number"}} {
		read, err := run.as(proof, run.query(family, fields...), "read")
		if err != nil || len(read["records"].([]interface{})) == 0 {
			t.Fatalf("workload read of %s: %v", family, err)
		}
	}
	patched, err := run.as(proof, run.command(pngWorkloadPatch(run.thread, map[string]interface{}{"id": run.thread.Key, "account_id": run.scope.AccountID, "title": "LABELLED newer"})), "command")
	if err != nil || len(pngWorkloadRecords(t, patched)) != 1 {
		t.Fatal("workload patch of a person's row in its family refused", err)
	}
	run.assertAttribution(body)
}

// The receipt on disk names the workload, in the place it names a person for a person's write.
func (run *pngWorkloadSetup) assertAttribution(body map[string]interface{}) {
	run.t.Helper()
	nodes := pngACLStateNodes(run.t, run.directory)
	workload, person := 0, 0
	for _, node := range nodes {
		if node["kind"] != "activity.manifest.root" {
			continue
		}
		receipts, _ := node["command_receipts"].(map[string]interface{})
		for _, raw := range receipts {
			receipt, _ := raw.(map[string]interface{})
			command, _ := receipt["command"].(map[string]interface{})
			switch command["principalId"] {
			case pngWorkloadPrincipal:
				workload++
			case pngACLAdministrator:
				person++
			}
		}
	}
	if workload != 2 || person != 4 {
		run.t.Fatalf("receipts name the workload %d times and the administrator %d", workload, person)
	}
}

func TestPNGWorkloadCannotDoAnythingElse(t *testing.T) {
	run := pngWorkloadProvisioned(t)
	proof := pngWorkloadValidProof()
	run.grant()
	run.refreshRevision()
	command := func(mutations ...pngstore.Mutation) pngstore.Request { return run.command(mutations...) }
	own := func(fields map[string]interface{}) pngstore.Mutation {
		return run.newRow("resource:png.messages", fields)
	}
	cases := []struct {
		label   string
		request pngstore.Request
		mode    string
	}{
		{"a row in another family", command(run.newRow("business:job", nil)), "command"},
		{"a row in a resource family outside the list", command(run.newRow("resource:png.jobs", nil)), "command"},
		{"a read of another family", run.query("business:job", "id"), "read"},
		{"a read of its command history", run.query("native.command_receipt", "id"), "read"},
		{"a change to a person's row in another family", command(pngWorkloadPatch(run.job, map[string]interface{}{"id": run.job.Key, "account_id": run.scope.AccountID})), "command"},
		{"a child of another kind", command(run.newRow("business:associate", map[string]interface{}{"full_name": "LABELLED"})), "command"},
		{"a change to a record of another kind", command(pngWorkloadPatch(run.associate, map[string]interface{}{"id": run.associate.Key, "account_id": run.scope.AccountID, "full_name": "LABELLED"})), "command"},
		{"a field the owner holds and it does not", command(own(map[string]interface{}{"accepted_at": "LABELLED"})), "command"},
		{"another family's column", command(own(map[string]interface{}{"phone_number": "LABELLED"})), "command"},
		{"a field no profile has", command(own(map[string]interface{}{"not_in_any_profile": "LABELLED"})), "command"},
		{"an access-list key as data", command(own(map[string]interface{}{"fixture.acl": "LABELLED"})), "command"},
		{"a reference", func() pngstore.Request {
			request := command(own(nil))
			request.References = []pngstore.Reference{{Family: run.thread.Family, Key: run.thread.Key, NativeID: run.thread.NativeID, Version: run.thread.Version}}
			return request
		}(), "command"},
		{"a uniqueness check over another family", func() pngstore.Request {
			request := command(own(nil))
			request.Unique = []pngstore.Unique{{Family: "business:job", Fields: map[string]interface{}{"id": "labelled"}}}
			return request
		}(), "command"},
		{"derived carrier events", func() pngstore.Request {
			request := command(run.newRow("business:presence_event", map[string]interface{}{"event_type": "arrived"}))
			request.Result = []byte(`{"derive_carrier_events":true}`)
			return request
		}(), "command"},
	}
	for _, item := range cases {
		run.refused(item.label, proof, item.request, item.mode)
	}
	if _, err := run.as(proof, run.command(own(nil)), "command"); err != nil {
		t.Fatal("every refusal above must be about what it asked, and this asks for nothing outside the list", err)
	}
}

func TestPNGWorkloadProofFormsFailClosed(t *testing.T) {
	run := pngWorkloadProvisioned(t)
	run.grant()
	run.refreshRevision()
	change := func(mutate func(*pngWorkloadProof)) pngWorkloadProof {
		proof := pngWorkloadValidProof()
		mutate(&proof)
		return proof
	}
	cases := map[string]pngWorkloadProof{
		"a stale grant revision":      change(func(p *pngWorkloadProof) { p.revision = "labelled-stale" }),
		"the person's issuer":         change(func(p *pngWorkloadProof) { p.issuer = run.config.Trust.Issuer }),
		"another workload issuer":     change(func(p *pngWorkloadProof) { p.issuer = "workload-authority:other" }),
		"a workload never granted":    change(func(p *pngWorkloadProof) { p.principal, p.session = "workload:other", "workload-session:other:r" }),
		"a message session":           change(func(p *pngWorkloadProof) { p.session = "channel-message:1" }),
		"a person's session":          change(func(p *pngWorkloadProof) { p.session = "fixture-session" }),
		"another workload's session":  change(func(p *pngWorkloadProof) { p.session = "workload-session:other:r" }),
		"a malformed principal":       change(func(p *pngWorkloadProof) { p.principal = "workload:ALIVE5" }),
		"an unknown kind":             change(func(p *pngWorkloadProof) { p.kind = "service" }),
		"a human claim of a workload": change(func(p *pngWorkloadProof) { p.kind, p.issuer = "human", run.config.Trust.Issuer }),
		"an integration claim":        change(func(p *pngWorkloadProof) { p.kind = "integration_actor" }),
		"a person under its session":  {"human", pngACLAdministrator, pngWorkloadSession, run.config.Trust.Issuer, "fixture-grant"},
		"a workload under a person":   {"workload", pngACLAdministrator, pngWorkloadSession, pngWorkloadIssuer, pngWorkloadRevision},
	}
	for label, proof := range cases {
		run.refused(label, proof, run.command(run.newRow("resource:png.messages", nil)), "command")
	}
	if _, err := run.as(pngWorkloadValidProof(), run.command(run.newRow("resource:png.messages", nil)), "command"); err != nil {
		t.Fatal("every refusal above must be about its proof, and this proof is the valid one", err)
	}
}

func TestPNGWorkloadCannotReachTheGraphOrAnotherAccount(t *testing.T) {
	run := pngWorkloadProvisioned(t)
	proof := pngWorkloadValidProof()
	run.grant()
	input := DomainInput{Mode: "read", Method: "POST", Target: "/manifest/read", Body: domainFixtureJSON(t, map[string]interface{}{"contractRevision": "manifest-associates/0.1", "scope": run.scope})}
	intent := pngFixtureResolve(t, run.handle, input)
	if _, err := run.handle.DomainCall(domainFixtureJSON(t, DomainRequest{DomainInput: input, RequestID: "labelled-graph", Proof: run.issue(proof, intent, "admission", nil)})); err == nil {
		t.Fatal("a workload read the graph")
	}
	home, revision := run.scope, run.revision
	run.scope = engine.DomainScope{AccountID: "labelled-other-account", Product: "manifest"}
	run.provision()
	run.refused("another account's root", proof, run.command(run.newRow("resource:png.messages", nil)), "command")
	run.refused("a read in another account", proof, run.query("resource:png.messages", "id"), "read")
	run.scope, run.revision = home, revision
}

func TestPNGWorkloadStopsAtRevokeAndSurvivesARestart(t *testing.T) {
	directory := t.TempDir()
	run := pngWorkloadProvisionedIn(t, directory)
	proof := pngWorkloadValidProof()
	run.refused("a write before any grant", proof, run.command(run.newRow("resource:png.messages", nil)), "command")
	run.grant()
	run.refreshRevision()
	if _, err := run.as(proof, run.command(run.newRow("resource:png.messages", nil)), "command"); err != nil {
		t.Fatal("granted write refused", err)
	}
	closePNGFixture(t, run.handle)
	run.handle = openPNGFixture(t, directory, run.config)
	run.refreshRevision()
	if _, err := run.as(proof, run.command(run.newRow("resource:png.messages", nil)), "command"); err != nil {
		t.Fatal("granted write refused after a reopen", err)
	}
	if err := run.readGrantChange(engine.EnrollmentWorkloadRevoke, pngWorkloadPrincipal, pngWorkloadRevision); err != nil {
		t.Fatal("revoke refused", err)
	}
	run.refreshRevision()
	run.refused("a write after a revoke", proof, run.command(run.newRow("resource:png.messages", nil)), "command")
	run.refused("a read after a revoke", proof, run.query("resource:png.messages", "id"), "read")
	closePNGFixture(t, run.handle)
	run.handle = openPNGFixture(t, directory, run.config)
	t.Cleanup(func() { closePNGFixture(t, run.handle) })
	run.refreshRevision()
	run.refused("a write after a revoke and a reopen", proof, run.command(run.newRow("resource:png.messages", nil)), "command")
}

func pngWorkloadProvisionedIn(t *testing.T, directory string) *pngWorkloadSetup {
	t.Helper()
	run := pngWorkloadStart(t, directory)
	run.provision()
	run.authority.targetRevision = pngWorkloadRevision
	return &pngWorkloadSetup{pngWorkloadRun: run}
}

func TestPNGWorkloadCommandReplaysAsItself(t *testing.T) {
	run := pngWorkloadProvisioned(t)
	proof := pngWorkloadValidProof()
	run.grant()
	run.refreshRevision()
	request := run.command(run.newRow("resource:png.messages", map[string]interface{}{"text": "LABELLED"}))
	first, err := run.as(proof, request, "command")
	if err != nil {
		t.Fatal(err)
	}
	second, err := run.as(proof, request, "command")
	if err != nil {
		t.Fatal(err)
	}
	if first["receipt"].(map[string]interface{})["status"] != "applied" || second["receipt"].(map[string]interface{})["status"] != "replayed" {
		t.Fatalf("statuses %v then %v", first["receipt"], second["receipt"])
	}
	other := proof
	other.principal, other.session = pngACLAdministrator, "fixture-session"
	other.kind, other.issuer, other.revision = "human", run.config.Trust.Issuer, "fixture-grant"
	body, err := run.as(other, request, "command")
	if err == nil && strings.Contains(domainFixtureStatus(body), "replayed") {
		t.Fatal("a person replayed a workload's command as their own")
	}
}

func domainFixtureStatus(body map[string]interface{}) string {
	receipt, _ := body["receipt"].(map[string]interface{})
	status, _ := receipt["status"].(string)
	return status
}

// A policy narrowed after a grant holds through the whole exchange, with no regrant.
func TestPNGWorkloadNarrowedPolicyHolds(t *testing.T) {
	directory := t.TempDir()
	run := pngWorkloadProvisionedIn(t, directory)
	proof := pngWorkloadValidProof()
	run.grant()
	run.refreshRevision()
	if _, err := run.as(proof, run.command(run.newRow(pngWorkloadContacts, nil)), "command"); err != nil {
		t.Fatal(err)
	}
	closePNGFixture(t, run.handle)
	run.config.WorkloadPolicy = &engine.DomainWorkloadPolicy{Issuer: pngWorkloadIssuer, Families: map[string][]string{"resource:png.messages": run.families["resource:png.messages"]}}
	run.handle = openPNGFixture(t, directory, run.config)
	t.Cleanup(func() { closePNGFixture(t, run.handle) })
	run.refreshRevision()
	run.refused("a write to a family the policy dropped", proof, run.command(run.newRow(pngWorkloadContacts, nil)), "command")
	run.refused("a read of a family the policy dropped", proof, run.query(pngWorkloadContacts, "id"), "read")
	if _, err := run.as(proof, run.command(run.newRow("resource:png.messages", nil)), "command"); err != nil {
		t.Fatal("the family the policy kept was refused", err)
	}
}
