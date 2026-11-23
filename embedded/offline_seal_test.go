// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package embedded

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"github.com/NeoTecDigital/LumberJack/internal"
	"github.com/NeoTecDigital/LumberJack/types"
)

var fixtureCommand = []byte(`{"command_id":"fixture","edits":[{"op":"create","kind":"fixture-secret-row"}]}`)

func sealFixture(t *testing.T) (SealRequest, []byte) {
	t.Helper()
	base := t.TempDir()
	dir := filepath.Join(base, "account")
	cfg := embeddedConfig(t)
	cfg.Process.DatabasePath = filepath.Join(dir, "hub")
	cfg.Process.Name = "catalog"
	h, e := Open(cfg, "owner")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = h.CreateNode(CreateNodeRequest{Path: "work/fixture", Type: "leaf"}); e != nil {
		t.Fatal(e)
	}
	if e = h.Close(); e != nil {
		t.Fatal(e)
	}
	k := make([]byte, 32)
	rand.Read(k)
	key := filepath.Join(base, "fixture-wrap")
	if e = os.WriteFile(key, k, 0600); e != nil {
		t.Fatal(e)
	}
	r := SealRequest{dir, "hub", "catalog", "owner", &types.StorageConfig{Mode: "local-test", LocalKeyFile: key}}
	records, e := OpenRecords(dir, r.Name, r.Principal)
	if e != nil {
		t.Fatal(e)
	}
	receipt, e := records.Apply(fixtureCommand)
	if e != nil {
		t.Fatal(e)
	}
	if e = records.Close(); e != nil {
		t.Fatal(e)
	}
	return r, receipt
}
func fileDigests(t *testing.T, dir string) map[string][32]byte {
	t.Helper()
	m := map[string][32]byte{}
	e := filepath.WalkDir(dir, func(p string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			return nil
		}
		b, e := os.ReadFile(p)
		if e == nil {
			m[p] = sha256.Sum256(b)
		}
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	return m
}
func assertConverted(t *testing.T, r SealRequest, receipt []byte) {
	t.Helper()
	before := fileDigests(t, r.Directory)
	already, e := SealAccount(r)
	if e != nil || !already {
		t.Fatalf("second seal: %v %v", already, e)
	}
	if !reflect.DeepEqual(before, fileDigests(t, r.Directory)) {
		t.Fatal("second seal changed live bytes")
	}
	hub, e := Open(types.ServerConfig{Process: types.ProcessInfo{DatabasePath: filepath.Join(r.Directory, r.Hub), Name: r.Name}, Storage: r.Storage}, internal.SystemUserID)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = hub.StatusOf("work/fixture"); e != nil {
		t.Fatal(e)
	}
	if e = hub.Close(); e != nil {
		t.Fatal(e)
	}
	before = fileDigests(t, r.Directory) // An ordinary writable hub reopen may refresh its ciphertext.
	h, e := OpenIndexedRecordsWithStorage(r.Directory, r.Name, r.Principal, nil, false, r.Storage)
	if e != nil {
		t.Fatal(e)
	}
	defer h.Close()
	got, e := h.Apply(fixtureCommand)
	if e != nil || !bytes.Equal(receipt, got) {
		t.Fatal("receipt changed", e)
	}
	for _, policy := range []*types.StorageConfig{nil, {Mode: "local-test", LocalKeyFile: filepath.Join(t.TempDir(), "absent")}} {
		if _, e = OpenIndexedRecordsWithStorage(r.Directory, r.Name, r.Principal, nil, true, policy); !errors.Is(e, types.ErrSealingLabel) {
			t.Fatal("policy refusal:", e)
		}
	}
	if !reflect.DeepEqual(before, fileDigests(t, r.Directory)) {
		t.Fatal("refusal or retry wrote to disk")
	}
}
func TestSealAccount(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("atomic exchange unavailable")
	}
	r, receipt := sealFixture(t)
	before := fileDigests(t, r.Directory)
	if _, e := OpenIndexedRecordsWithStorage(r.Directory, r.Name, r.Principal, nil, true, r.Storage); !errors.Is(e, types.ErrSealingLabel) {
		t.Fatal(e)
	}
	live, e := OpenRecords(r.Directory, r.Name, r.Principal)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = SealAccount(r); !errors.Is(e, ErrLocked) {
		t.Fatal("open writer", e)
	}
	live.Close()
	denied := r
	denied.Principal = "other"
	if _, e = SealAccount(denied); !errors.Is(e, ErrRecordDenied) {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(before, fileDigests(t, r.Directory)) {
		t.Fatal("refusal touched store")
	}
	if already, e := SealAccount(r); e != nil || already {
		t.Fatal(already, e)
	}
	assertConverted(t, r, receipt)
}
func TestSealCrash(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("atomic exchange unavailable")
	}
	if phase := os.Getenv("LJ_FIXTURE_CRASH_PHASE"); phase != "" {
		var r SealRequest
		if e := json.Unmarshal([]byte(os.Getenv("LJ_FIXTURE_SEAL_REQUEST")), &r); e != nil {
			t.Fatal(e)
		}
		_, e := sealAccount(r, func(seen string) error {
			if seen == phase {
				os.Exit(77)
			}
			return nil
		})
		t.Fatal("missed crash point", e)
	}
	for _, phase := range []string{"copied", "records", "verified", "synced", "exchanged", "published"} {
		t.Run(phase, func(t *testing.T) {
			r, receipt := sealFixture(t)
			before := fileDigests(t, r.Directory)
			wire, _ := json.Marshal(r)
			cmd := exec.Command(os.Args[0], "-test.run=^TestSealCrash$")
			cmd.Env = append(os.Environ(), "LJ_FIXTURE_CRASH_PHASE="+phase, "LJ_FIXTURE_SEAL_REQUEST="+string(wire))
			b, e := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(e, &exit) || exit.ExitCode() != 77 {
				t.Fatalf("crash: %v %s", e, b)
			}
			published := phase == "exchanged" || phase == "published"
			if !published && !reflect.DeepEqual(before, fileDigests(t, r.Directory)) {
				t.Fatal("mixed or changed original")
			}
			if already, e := SealAccount(r); e != nil || already != published {
				t.Fatal(already, e)
			}
			assertConverted(t, r, receipt)
		})
	}
}

func TestWritePriorRecordFixture(t *testing.T) {
	dir := os.Getenv("LJ_FIXTURE_OLD_READER")
	if dir == "" {
		t.Skip("cross-version gate")
	}
	r, _ := sealFixture(t)
	for name, cfg := range map[string]*types.StorageConfig{"plain": nil, "sealed": r.Storage} {
		h, e := OpenIndexedRecordsWithStorage(dir, name, "owner", nil, false, cfg)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = h.Apply(fixtureCommand); e != nil {
			t.Fatal(e)
		}
		if e = h.Close(); e != nil {
			t.Fatal(e)
		}
	}
}
