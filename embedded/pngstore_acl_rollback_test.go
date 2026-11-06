// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package embedded

import (
	"bytes"
	"flag"
	"fmt"
	engine "github.com/NeoTecDigital/LumberJack/internal"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// One step of a rollback proof, run in turn by different engines over one forest directory. The
// baseline tree carries this same file, so the old engine really is the one being asked.
var pngACLRollbackStep = flag.String("png-acl-rollback-step", "", "copies, empty, reference, access, use or refused; diagnostic only")

func TestPNGSharedACLRollbackStep(t *testing.T) {
	if *pngACLRollbackStep == "" {
		t.Skip("explicit diagnostic requested only")
	}
	directory := *pngACLTranscriptDir
	if directory == "" {
		t.Fatal("-png-acl-transcript-dir names the shared forest")
	}
	if *pngACLRollbackStep == "refused" {
		pngACLAssertRefused(t, directory)
		return
	}
	run := pngACLStart(t, *pngProfileArtifact, directory)
	run.sequence = int(time.Now().UnixMilli() % 1000000000)
	pngACLRollbackRun(t, run, *pngACLRollbackStep)
	closePNGFixture(t, run.handle)
	pngACLPrintHeader(t, directory)
}

func pngACLRollbackRun(t *testing.T, run *pngACLRun, step string) {
	switch step {
	case "copies":
		run.provision()
		pngACLStep(t, "write 3", run.writeRows(3))
		pngACLStep(t, "grant member", run.readGrantChange(engine.EnrollmentReadGrant, pngACLMember, "fixture-grant"))
	case "empty":
		run.provision()
		pngACLStep(t, "grant member", run.readGrantChange(engine.EnrollmentReadGrant, pngACLMember, "fixture-grant"))
	case "reference":
		run.refreshRevision()
		pngACLStep(t, "write 1", run.writeRows(1))
	case "access":
		pngACLRollbackAccess(t, run)
	case "use":
		pngACLRollbackUse(t, run)
	default:
		t.Fatalf("unknown step %q", step)
	}
}

// Reads and access changes that create no record, so this engine leaves no reference behind.
func pngACLRollbackAccess(t *testing.T, run *pngACLRun) {
	run.refreshRevision()
	pngACLStep(t, "administrator reads", run.readPage(5, pngACLAdministrator))
	pngACLStep(t, "member reads", run.readPage(5, pngACLMember))
	pngACLStep(t, "revoke member", run.readGrantChange(engine.EnrollmentReadRevoke, pngACLMember, "fixture-grant"))
	pngACLStep(t, "grant member", run.readGrantChange(engine.EnrollmentReadGrant, pngACLMember, "fixture-grant"))
}

// Everything an operator needs from a forest after a rollback: read, revoke, write, grant again.
func pngACLRollbackUse(t *testing.T, run *pngACLRun) {
	run.refreshRevision()
	pngACLStep(t, "administrator reads", run.readPage(5, pngACLAdministrator))
	pngACLStep(t, "member reads", run.readPage(5, pngACLMember))
	pngACLStep(t, "revoke member", run.readGrantChange(engine.EnrollmentReadRevoke, pngACLMember, "fixture-grant"))
	if err := run.readPage(5, pngACLMember); err == nil {
		t.Fatal("revoked member still reads")
	}
	t.Log("LABELLED rollback revoked member is denied")
	pngACLStep(t, "write 1", run.writeRows(1))
	pngACLStep(t, "grant member", run.readGrantChange(engine.EnrollmentReadGrant, pngACLMember, "fixture-grant"))
	pngACLStep(t, "member reads", run.readPage(5, pngACLMember))
}

func pngACLStep(t *testing.T, label string, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	t.Logf("LABELLED rollback %s: allow", label)
}

func pngACLAssertRefused(t *testing.T, directory string) {
	path := filepath.Join(directory, "fixture.dat")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := OpenPath("fixture", directory, "fixture", "fixture-private-owner")
	if err == nil {
		_ = handle.Close()
		t.Fatal("this engine opened a forest it cannot change access in")
	}
	after, readErr := os.ReadFile(path)
	if readErr != nil || !bytes.Equal(before, after) {
		t.Fatal("the refused open changed the state file", readErr)
	}
	t.Logf("LABELLED rollback refused, state file unchanged: %v", err)
}

func pngACLPrintHeader(t *testing.T, directory string) {
	raw, err := os.ReadFile(filepath.Join(directory, "fixture.dat"))
	if err != nil {
		t.Fatal(err)
	}
	t.Log("LABELLED rollback header " + fmt.Sprintf("%q", raw[:min(len(raw), 44)]))
}
