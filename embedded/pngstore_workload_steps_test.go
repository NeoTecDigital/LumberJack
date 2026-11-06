// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package embedded

import (
	"flag"
	"fmt"
	engine "github.com/NeoTecDigital/LumberJack/internal"
	"github.com/NeoTecDigital/LumberJack/products/pngstore"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Steps of a cross-engine proof over one forest: an older engine writes it, this one grants and
// uses a workload. The older engine's steps are in pngstore_acl_rollback_test.go, which it carries.
var pngWorkloadStep = flag.String("png-workload-step", "", "grant or use; diagnostic only")
var pngACLWorkloadPolicy = flag.String("png-acl-workload-policy", "", "Configure this workload policy on the transcript and measure runs")

func init() {
	pngACLConfigure = func(config *DomainConfig) {
		if *pngACLWorkloadPolicy == "" {
			return
		}
		raw, err := os.ReadFile(*pngACLWorkloadPolicy)
		if err != nil {
			panic(err)
		}
		var policy engine.DomainWorkloadPolicy
		if err = engine.DecodeDomainJSON(raw, &policy); err != nil {
			panic(err)
		}
		config.WorkloadPolicy = &policy
	}
}

func TestPNGWorkloadCrossEngineStep(t *testing.T) {
	if *pngWorkloadStep == "" {
		t.Skip("explicit diagnostic requested only")
	}
	artifact, err := filepath.Abs(pngWorkloadArtifact)
	if err != nil {
		t.Fatal(err)
	}
	*pngProfileArtifact = artifact
	run := &pngWorkloadSetup{pngWorkloadRun: pngWorkloadStart(t, *pngACLTranscriptDir)}
	run.sequence = int(time.Now().UnixMilli() % 1000000000)
	run.refreshRevision()
	switch *pngWorkloadStep {
	case "grant":
		pngACLStep(t, "workload grant", run.readGrantChange(engine.EnrollmentWorkloadGrant, pngWorkloadPrincipal, pngWorkloadRevision))
	case "use":
		run.useAcrossEngines()
	default:
		t.Fatalf("unknown step %q", *pngWorkloadStep)
	}
	closePNGFixture(t, run.handle)
	pngACLPrintHeader(t, *pngACLTranscriptDir)
}

func (run *pngWorkloadSetup) useAcrossEngines() {
	proof := pngWorkloadValidProof()
	run.refreshRevision()
	body, err := run.as(proof, run.query("resource:png.messages", "id", "account_id", run.artifact.Fields[0]), "read")
	pngACLStep(run.t, fmt.Sprintf("workload reads %d rows", pngWorkloadRowCount(body)), err)
	var rows []pngstore.Record
	if err = engine.DecodeDomainJSON(domainFixtureJSON(run.t, body["records"]), &rows); err != nil || len(rows) == 0 {
		run.t.Fatal("no row to patch", err)
	}
	patch := map[string]interface{}{"id": rows[0].Key, "account_id": run.scope.AccountID, run.artifact.Fields[0]: "LABELLED patched by the workload"}
	_, err = run.as(proof, run.command(pngWorkloadPatch(rows[0], patch)), "command")
	pngACLStep(run.t, "workload patches a row an older engine wrote", err)
	_, err = run.as(proof, run.command(run.newRow("resource:png.messages", nil)), "command")
	pngACLStep(run.t, "workload creates a row", err)
	pngACLStep(run.t, "revoke workload", run.readGrantChange(engine.EnrollmentWorkloadRevoke, pngWorkloadPrincipal, pngWorkloadRevision))
	run.refreshRevision()
	if _, err = run.as(proof, run.command(run.newRow("resource:png.messages", nil)), "command"); err == nil {
		run.t.Fatal("a revoked workload wrote")
	}
	if _, err = run.as(proof, run.query("resource:png.messages", "id"), "read"); err == nil {
		run.t.Fatal("a revoked workload read")
	}
	run.t.Log("LABELLED rollback revoked workload is denied")
}

func pngWorkloadRowCount(body map[string]interface{}) int {
	rows, _ := body["records"].([]interface{})
	return len(rows)
}
