// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package embedded

import (
	"encoding/json"
	"flag"
	"fmt"
	engine "github.com/NeoTecDigital/LumberJack/internal"
	"github.com/NeoTecDigital/LumberJack/products/pngstore"
	"os"
	"sort"
	"strings"
	"testing"
)

// One scripted run through the real handle, written as decisions and disclosed rows with random
// native ids removed. Running it on two engines and comparing the two files is the differential:
// the same script must get the same answer from the engine that stores copies and the one that
// stores references, and from a forest written by the first and reopened by the second.
var pngACLTranscript = flag.String("png-acl-transcript", "", "Write the labelled decision transcript to this file")
var pngACLTranscriptDir = flag.String("png-acl-transcript-dir", "", "Forest directory shared between phases")
var pngACLTranscriptPhase = flag.String("png-acl-transcript-phase", "all", "first, second or all")

const pngACLStranger = "labelled-stranger"
const pngACLSecondPhaseSequence = 500000

type pngACLTranscriptRun struct {
	*pngACLRun
	lines []string
}

func TestPNGSharedACLDecisionTranscript(t *testing.T) {
	if *pngACLTranscript == "" {
		t.Skip("explicit diagnostic requested only")
	}
	directory := *pngACLTranscriptDir
	if directory == "" {
		directory = t.TempDir()
	}
	run := &pngACLTranscriptRun{pngACLRun: pngACLStart(t, *pngProfileArtifact, directory)}
	if *pngACLTranscriptPhase != "second" {
		run.firstPhase()
	}
	if *pngACLTranscriptPhase != "first" {
		run.reopen()
		run.secondPhase()
	}
	closePNGFixture(t, run.handle)
	if err := os.WriteFile(*pngACLTranscript, []byte(strings.Join(run.lines, "\n")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
}

func (run *pngACLTranscriptRun) reopen() {
	closePNGFixture(run.t, run.handle)
	run.handle = openPNGFixture(run.t, run.directory, run.config)
	run.sequence = pngACLSecondPhaseSequence
	run.refreshRevision()
}

func (run *pngACLTranscriptRun) firstPhase() {
	run.provision()
	run.decide("seed", func() (string, error) { return "", run.writeRows(40) })
	run.matrix("fresh")
	run.change("grant-member", engine.EnrollmentReadGrant, pngACLMember, "fixture-grant")
	run.matrix("member-granted")
	run.decide("seed-after-grant", func() (string, error) { return "", run.writeRows(5) })
	run.matrix("member-granted-new-rows")
	run.change("regrant-member-other-revision", engine.EnrollmentReadGrant, pngACLMember, "labelled-other-revision")
	run.matrix("member-stale-revision")
	run.change("revoke-member", engine.EnrollmentReadRevoke, pngACLMember, "labelled-other-revision")
	run.matrix("member-revoked")
	run.change("grant-owner-refused", engine.EnrollmentReadGrant, pngACLOwner, "fixture-grant")
	run.crossAccount()
}

func (run *pngACLTranscriptRun) secondPhase() {
	run.matrix("reopened")
	run.change("grant-member-after-reopen", engine.EnrollmentReadGrant, pngACLMember, "fixture-grant")
	run.matrix("reopened-member-granted")
	run.decide("seed-after-reopen", func() (string, error) { return "", run.writeRows(5) })
	run.reopen()
	run.sequence = pngACLSecondPhaseSequence + 100000
	run.matrix("reopened-twice")
	run.change("revoke-member-after-reopen", engine.EnrollmentReadRevoke, pngACLMember, "fixture-grant")
	run.matrix("reopened-member-revoked")
}

func (run *pngACLTranscriptRun) change(label, operation, target, revision string) {
	run.decide(label, func() (string, error) { return "", run.readGrantChange(operation, target, revision) })
	run.refreshRevision()
}

func (run *pngACLTranscriptRun) decide(label string, action func() (string, error)) {
	run.t.Helper()
	detail, err := action()
	line := label + ": allow " + detail
	if err != nil {
		line = label + ": deny " + err.Error()
	}
	run.lines = append(run.lines, strings.TrimSpace(line))
}

func (run *pngACLTranscriptRun) matrix(label string) {
	for _, principal := range []string{pngACLAdministrator, pngACLOwner, pngACLMember, pngACLStranger} {
		prefix := label + "/" + principal
		run.decide(prefix+"/read-page", func() (string, error) {
			return run.disclosed(pngstore.Query{Limit: 7, Fields: []string{"id", "account_id", run.artifact.Fields[0]}}, principal)
		})
		run.decide(prefix+"/read-all-granted-fields", func() (string, error) {
			return run.disclosed(pngstore.Query{Limit: 3, Fields: []string{"id", "account_id", run.artifact.Fields[0], run.artifact.Fields[19]}}, principal)
		})
		run.decide(prefix+"/read-field-outside-profile", func() (string, error) {
			return run.disclosed(pngstore.Query{Limit: 3, Fields: []string{"id", "not_in_any_profile"}}, principal)
		})
		run.decide(prefix+"/write-new", func() (string, error) { return "", run.writeRowsAs(1, principal) })
		run.decide(prefix+"/patch-existing", func() (string, error) { return "", run.patchFirst(principal) })
	}
}

func (run *pngACLTranscriptRun) disclosed(query pngstore.Query, principal string) (string, error) {
	body, err := run.call(run.readRequest(query), "read", principal)
	if err != nil {
		return "", err
	}
	raw, _ := body["records"].([]interface{})
	rows := make([]string, 0, len(raw))
	for _, value := range raw {
		row, _ := value.(map[string]interface{})
		delete(row, "native_id")
		encoded, err := json.Marshal(row)
		if err != nil {
			return "", err
		}
		rows = append(rows, string(encoded))
	}
	sort.Strings(rows)
	return fmt.Sprintf("rows=%d sha=%s", len(rows), domainFixtureSHA(strings.Join(rows, "\n"))), nil
}

func (run *pngACLTranscriptRun) currentFirst() (pngstore.Record, error) {
	body, err := run.call(run.readRequest(pngstore.Query{Key: "labelled-0000001", Limit: 1, Fields: []string{"id", "account_id", run.artifact.Fields[1]}}), "read", pngACLAdministrator)
	if err != nil {
		return pngstore.Record{}, err
	}
	var rows []pngstore.Record
	if err = engine.DecodeDomainJSON(domainFixtureJSON(run.t, body["records"]), &rows); err != nil || len(rows) != 1 {
		return pngstore.Record{}, fmt.Errorf("labelled first row absent: %v", err)
	}
	return rows[0], nil
}

func (run *pngACLTranscriptRun) patchFirst(principal string) error {
	current, err := run.currentFirst()
	if err != nil {
		return err
	}
	data := map[string]interface{}{"id": current.Key, "account_id": run.scope.AccountID, run.artifact.Fields[1]: "LABELLED patched by " + principal}
	mutation := pngstore.Mutation{Family: current.Family, Key: current.Key, NativeID: current.NativeID, ExpectedVersion: current.Version, Data: data, Patch: true}
	_, err = run.call(run.writeRequest([]pngstore.Mutation{mutation}), "command", principal)
	return err
}

// A second account on the same forest: its rows never appear through the first account's scope,
// and the first account's row identity is refused through the second's.
func (run *pngACLTranscriptRun) crossAccount() {
	first, err := run.currentFirst()
	if err != nil {
		run.t.Fatal(err)
	}
	home, homeRevision := run.scope, run.revision
	run.scope = engine.DomainScope{AccountID: "labelled-other-account", Product: "manifest"}
	run.provision()
	run.decide("other-account/seed", func() (string, error) { return "", run.writeRows(3) })
	run.decide("other-account/read-page", func() (string, error) {
		return run.disclosed(pngstore.Query{Limit: 50, Fields: []string{"id", "account_id"}}, pngACLAdministrator)
	})
	run.decide("other-account/read-home-key", func() (string, error) {
		return run.disclosed(pngstore.Query{Key: first.Key, Limit: 1, Fields: []string{"id"}}, pngACLAdministrator)
	})
	foreign := pngstore.Mutation{Family: first.Family, Key: first.Key, NativeID: first.NativeID, ExpectedVersion: first.Version, Data: map[string]interface{}{"id": first.Key, "account_id": run.scope.AccountID}, Patch: true}
	run.decide("other-account/patch-home-record", func() (string, error) {
		_, err := run.call(run.writeRequest([]pngstore.Mutation{foreign}), "command", pngACLAdministrator)
		return "", err
	})
	run.scope, run.revision = home, homeRevision
	run.decide("home/read-page-after-other-account", func() (string, error) {
		return run.disclosed(pngstore.Query{Limit: 500, Fields: []string{"id"}}, pngACLAdministrator)
	})
}
