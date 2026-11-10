// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package embedded

import (
	engine "github.com/NeoTecDigital/LumberJack/internal"
	"github.com/NeoTecDigital/LumberJack/products/pngstore"
	"strings"
	"testing"
)

func pngBoundObservation(run *pngBoundRun) map[string]interface{} {
	return map[string]interface{}{"contractRevision": "quickbooks-observation/1", "provider": "quickbooks", "connectionId": "LABELLED-connection", "entity": "Account", "externalId": "LABELLED-external", "environment": "sandbox", "realmId": "LABELLED-realm", "sourceRevision": strings.Repeat("a", 64), "source": map[string]interface{}{"Id": "LABELLED-external", "Name": "LABELLED source"}, "projectedFamily": nil, "projected": map[string]interface{}{}}
}

func TestPNGBoundWorkloadActualSixFamiliesPairReadbackAndReopen(t *testing.T) {
	run := pngBoundStart(t)
	messaging := run.grant("messaging.sync")
	accounting := run.grant("accounting.sync")
	rows := []pngstore.Mutation{
		run.newRow("resource:png.messages", map[string]interface{}{"text": "LABELLED message", "direction": "inbound"}),
		run.newRow(pngWorkloadThreads, map[string]interface{}{"title": "LABELLED thread", "is_archived": false}),
		run.newRow(pngWorkloadContacts, map[string]interface{}{"phone": "LABELLED phone"}),
		run.newRow("resource:png_import", map[string]interface{}{"attributes": pngBoundObservation(run)}),
		run.newRow("business:associate", map[string]interface{}{"type": "client", "full_name": "LABELLED client", "quickbooks_id": "LABELLED-client"}),
		run.newRow("business:job", map[string]interface{}{"title": "LABELLED project", "quickbooks_id": "LABELLED-project"}),
	}
	for i, row := range rows {
		w := messaging
		if i >= 3 {
			w = accounting
		}
		body, err := run.asBound(w, run.command(row), "command")
		if err != nil || len(pngWorkloadRecords(t, body)) != 1 {
			t.Fatal("actual family create", row.Family, err)
		}
	}
	pngBoundReadAll(t, run, messaging, accounting)
	closePNGFixture(t, run.handle)
	run.handle = openPNGFixture(t, run.directory, run.config)
	pngBoundReadAll(t, run, messaging, accounting)
	pngBoundUpdateAll(t, run, messaging, accounting)
}

func pngBoundReadAll(t *testing.T, run *pngBoundRun, messaging, accounting engine.DomainWorkloadRun) {
	t.Helper()
	for _, w := range []engine.DomainWorkloadRun{messaging, accounting} {
		pngBoundReadPurpose(t, run, w)
	}
}

func pngBoundReadPurpose(t *testing.T, run *pngBoundRun, w engine.DomainWorkloadRun) {
	t.Helper()
	for family, rule := range run.config.WorkloadPolicy.Purposes[w.Grant.Purpose].Families {
		body, err := run.asBound(w, run.query(family, rule.ReadFields...), "read")
		if err != nil {
			t.Fatal("actual family read", family, err)
		}
		records, ok := body["records"].([]interface{})
		if !ok || len(records) != 1 {
			t.Fatal("actual retained record missing", family)
		}
	}
}

func pngBoundRow(t *testing.T, run *pngBoundRun, w engine.DomainWorkloadRun, family string) pngstore.Record {
	t.Helper()
	rule := run.config.WorkloadPolicy.Purposes[w.Grant.Purpose].Families[family]
	body, err := run.asBound(w, run.query(family, rule.ReadFields...), "read")
	if err != nil {
		t.Fatal(err)
	}
	var rows []pngstore.Record
	if engine.DecodeDomainJSON(domainFixtureJSON(t, body["records"]), &rows) != nil || len(rows) != 1 {
		t.Fatal("expected one actual row")
	}
	return rows[0]
}

func pngBoundUpdateAll(t *testing.T, run *pngBoundRun, messaging, accounting engine.DomainWorkloadRun) {
	t.Helper()
	changes := []struct {
		family, field string
		value         interface{}
		w             engine.DomainWorkloadRun
	}{
		{pngWorkloadThreads, "last_message", "LABELLED update", messaging},
		{pngWorkloadContacts, "email", "LABELLED@example.invalid", messaging},
		{"resource:png_import", "attributes", pngBoundObservation(run), accounting},
		{"business:associate", "full_name", "LABELLED renamed client", accounting},
		{"business:job", "title", "LABELLED renamed project", accounting},
	}
	for _, change := range changes {
		row := pngBoundRow(t, run, change.w, change.family)
		body, err := run.asBound(change.w, run.command(pngWorkloadPatch(row, map[string]interface{}{change.field: change.value})), "command")
		if err != nil || len(pngWorkloadRecords(t, body)) != 1 {
			t.Fatal("actual source-owned update", change.family, err)
		}
	}
}

func TestPNGBoundWorkloadActualReplayCannotChangeRunFenceOrPurpose(t *testing.T) {
	run := pngBoundStart(t)
	w := run.grant("messaging.sync")
	request := run.command(run.newRow("resource:png.messages", map[string]interface{}{"text": "LABELLED"}))
	first, err := run.asBound(w, request, "command")
	if err != nil {
		t.Fatal(err)
	}
	replay, err := run.asBound(w, request, "command")
	if err != nil || domainFixtureStatus(first) != "applied" || domainFixtureStatus(replay) != "replayed" {
		t.Fatal("exact W replay failed", err)
	}
	before := run.revision
	changed := w
	changed.RunID = "LABELLED-other-run"
	changed.FenceGeneration = "2"
	run.activate(changed)
	if _, err = run.asBound(changed, request, "command"); err == nil {
		t.Fatal("new run adopted old receipt")
	}
	if run.revision != before {
		t.Fatal("denied replay changed current state")
	}
	run.activate(w)
	closePNGFixture(t, run.handle)
	run.handle = openPNGFixture(t, run.directory, run.config)
	replay, err = run.asBound(w, request, "command")
	if err != nil || domainFixtureStatus(replay) != "replayed" {
		t.Fatal("exact retained W lost after reopen", err)
	}
	pngBoundAssertRetained(t, run, w, request.CommandID)
}

func pngBoundAssertRetained(t *testing.T, run *pngBoundRun, w engine.DomainWorkloadRun, commandID string) {
	t.Helper()
	found := 0
	for _, node := range pngACLStateNodes(t, run.directory) {
		found += pngBoundNodeReceipt(t, node, w, commandID)
	}
	if found != 1 {
		t.Fatalf("expected one actual retained workload record, got %d", found)
	}
}

func pngBoundNodeReceipt(t *testing.T, node map[string]interface{}, w engine.DomainWorkloadRun, commandID string) int {
	t.Helper()
	receipts, _ := node["command_receipts"].(map[string]interface{})
	found := 0
	for _, raw := range receipts {
		receipt, _ := raw.(map[string]interface{})
		command, _ := receipt["command"].(map[string]interface{})
		if command["commandId"] != commandID {
			continue
		}
		record, _ := receipt["workloadRecord"].(map[string]interface{})
		if record["contractRevision"] != "manifest-native-workload-record/0.1" || !pngFixtureEqual(record["workload"], w) || record["principalId"] != pngBoundPrincipal(w.Grant) || record["requestFingerprint"] != command["bodySha256"] {
			t.Fatal("typed native W provenance absent/mismatch")
		}
		found++
	}
	return found
}

func TestPNGBoundWorkloadActualRevokeBlocksAdmissionAndRetainedReplay(t *testing.T) {
	run := pngBoundStart(t)
	w := run.grant("accounting.sync")
	request := run.command(run.newRow("business:job", map[string]interface{}{"title": "LABELLED"}))
	if _, err := run.asBound(w, request, "command"); err != nil {
		t.Fatal(err)
	}
	if err := run.changeGrant(w.Grant, engine.EnrollmentWorkloadRevoke); err != nil {
		t.Fatal(err)
	}
	// Even a deliberately stale synthetic callback cannot override native installed G.
	run.activate(w)
	if _, err := run.asBound(w, request, "command"); err == nil {
		t.Fatal("revoked G replayed retained command")
	}
	if _, err := run.asBound(w, run.query("business:job", "id"), "read"); err == nil {
		t.Fatal("revoked G read current records")
	}
	closePNGFixture(t, run.handle)
	run.handle = openPNGFixture(t, run.directory, run.config)
	if _, err := run.asBound(w, request, "command"); err == nil {
		t.Fatal("revoked G revived after reopen")
	}
}

func TestPNGBoundWorkloadActualHandoffRequiresFreshCurrentRun(t *testing.T) {
	run := pngBoundStart(t)
	w := run.grant("messaging.sync")
	exchange, err := run.beginBound(w, run.query("resource:png.messages", "id"), "read")
	if err != nil {
		t.Fatal(err)
	}
	newer := w
	newer.FenceGeneration = "2"
	newer.RunID = "LABELLED-new-run"
	run.activate(newer)
	if run.finishBound(exchange) == nil {
		t.Fatal("fresh handoff accepted superseded run")
	}
}

func TestPNGBoundWorkloadActualSourceAndFamilyDenialsHavePositiveCanary(t *testing.T) {
	run := pngBoundStart(t)
	w := run.grant("messaging.sync")
	body, err := run.asBound(w, run.command(run.newRow("resource:png.messages", map[string]interface{}{"text": "LABELLED"})), "command")
	if err != nil {
		t.Fatal(err)
	}
	message := pngWorkloadRecords(t, body)[0]
	cases := []pngstore.Request{
		run.command(pngWorkloadPatch(message, map[string]interface{}{"text": "no existing message edits"})),
		run.command(run.newRow("resource:png.messages", map[string]interface{}{"phone": "another family field"})),
		run.command(run.newRow(pngWorkloadThreads, map[string]interface{}{"title": "LABELLED", "is_archived": true})),
		run.command(run.newRow("business:job", map[string]interface{}{"title": "wrong purpose"})),
	}
	for _, request := range cases {
		if _, err := run.asBound(w, request, "command"); err == nil {
			t.Fatal("source/family ceiling broadened")
		}
	}
	if _, err := run.asBound(w, run.command(run.newRow(pngWorkloadThreads, map[string]interface{}{"title": "LABELLED", "is_archived": false})), "command"); err != nil {
		t.Fatal("positive canary", err)
	}
}

func TestPNGBoundWorkloadActualCrossConnectionCommandCollisionAndMaxFence(t *testing.T) {
	run := pngBoundStart(t)
	first := run.grant("accounting.sync")
	request := run.command(run.newRow("business:job", map[string]interface{}{"title": "LABELLED first"}))
	if _, err := run.asBound(first, request, "command"); err != nil {
		t.Fatal(err)
	}
	other := first
	other.Grant.ConnectionID = "LABELLED-other-connection"
	other.FenceGeneration = "18446744073709551615"
	if err := run.changeGrant(other.Grant, engine.EnrollmentWorkloadGrant); err != nil {
		t.Fatal(err)
	}
	run.activate(other)
	reused := run.command(run.newRow("business:job", map[string]interface{}{"title": "LABELLED second"}))
	freshID := reused.CommandID
	reused.CommandID = request.CommandID
	before := run.revision
	exchange, err := run.beginBound(other, reused, "command")
	if err != nil {
		t.Fatal("expected exact native conflict response", err)
	}
	if domainFixtureStatus(exchange.body) != "conflict" || exchange.received.Pair != nil {
		t.Fatal("cross-connection command ID was not a no-effect conflict")
	}
	run.discardBound(exchange)
	run.refreshRevision()
	if run.revision != before {
		t.Fatal("cross-connection conflict changed state")
	}
	reused.CommandID = freshID
	if _, err = run.asBound(other, reused, "command"); err != nil {
		t.Fatal("legitimate already-issued MAX fence could not finish", err)
	}
}
