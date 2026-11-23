// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package abi

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"github.com/NeoTecDigital/LumberJack/embedded"
	"github.com/NeoTecDigital/LumberJack/extension"
)

func TestMalformedRecordPrincipalLeavesNoFiles(t *testing.T) {
	for _, open := range []func(unsafe.Pointer, int64, unsafe.Pointer) int32{RecordOpen, RecordOpenV2} {
		for _, principal := range []string{"", " owner", "owner ", "bad\x00key", strings.Repeat("x", 257)} {
			dir := filepath.Join(t.TempDir(), "absent")
			raw, err := json.Marshal(map[string]string{"directory": dir, "name": "data", "principal": principal, "durability": "local-sync"})
			if err != nil {
				t.Fatal(err)
			}
			var h uint64 = 42
			status := open(unsafe.Pointer(&raw[0]), int64(len(raw)), unsafe.Pointer(&h))
			if status != int32(statusInvalid) || h != 0 {
				t.Fatalf("open returned status=%d handle=%d", status, h)
			}
			if _, err = os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("open touched directory: %v", err)
			}
		}
	}
}

func TestLiveProfileConflictBothDirections(t *testing.T) {
	for _, first := range []string{"pointer", "record"} {
		t.Run(first, func(t *testing.T) {
			dir := t.TempDir()
			alias := filepath.Join(t.TempDir(), "alias")
			if err := os.Symlink(dir, alias); err != nil {
				t.Fatal(err)
			}
			var err error
			if first == "pointer" {
				h, e := embedded.OpenPath("", dir, "data", "system")
				if e != nil {
					t.Fatal(e)
				}
				defer h.Close()
				_, err = embedded.OpenRecords(alias, "data", "owner")
				if recordStatus(err) != statusConflict {
					t.Fatalf("record status: %v", err)
				}
			} else {
				h, e := embedded.OpenRecords(dir, "data", "owner")
				if e != nil {
					t.Fatal(e)
				}
				defer h.Close()
				_, err = embedded.OpenPath("", alias, "data", "system")
				if openStatus(err) != statusConflict {
					t.Fatalf("pointer status: %v", err)
				}
			}
			if !errors.Is(err, embedded.ErrProfileConflict) || !errors.Is(err, embedded.ErrRecordConflict) || errors.Is(err, embedded.ErrLocked) {
				t.Fatalf("incorrect classification: %v", err)
			}
		})
	}
}

type scopeProbe struct{ scope extension.StoreScope }

func (e scopeProbe) Spec() extension.Spec { return extension.Spec{Name: "scope-probe", Scope: e.scope} }
func (e scopeProbe) Attach(extension.Host) (extension.Instance, error) {
	panic("record open attached extension")
}

func TestRegisteredScopeOnRecordOpen(t *testing.T) {
	previous := registered()
	defer func() { registeredMu.Lock(); registeredExtensions = previous; registeredMu.Unlock() }()
	for _, version := range []struct {
		n    uint32
		open func(unsafe.Pointer, int64, unsafe.Pointer) int32
	}{
		{1, RecordOpen}, {2, RecordOpenV2},
	} {
		for _, tc := range []struct {
			name string
			set  []extension.Extension
			want int32
		}{
			{"hub", []extension.Extension{scopeProbe{extension.HubStore}}, int32(statusOK)},
			{"undeclared", []extension.Extension{scopeProbe{}}, int32(statusConflict)},
			{"record", []extension.Extension{scopeProbe{extension.RecordStore}}, int32(statusConflict)},
			{"mixed", []extension.Extension{scopeProbe{extension.HubStore}, scopeProbe{}}, int32(statusConflict)},
			{"unknown", []extension.Extension{scopeProbe{255}}, int32(statusConflict)},
		} {
			t.Run(fmt.Sprintf("v%d/%s", version.n, tc.name), func(t *testing.T) {
				registeredMu.Lock()
				registeredExtensions = nil
				registeredMu.Unlock()
				Register(tc.set...)
				dir := filepath.Join(t.TempDir(), "store")
				raw, _ := json.Marshal(map[string]string{"directory": dir, "name": "journal", "principal": "owner", "durability": "local-sync"})
				var h uint64
				got := version.open(unsafe.Pointer(&raw[0]), int64(len(raw)), unsafe.Pointer(&h))
				if got != tc.want || (h != 0) != (got == 0) {
					t.Fatalf("status %d, handle %d", got, h)
				}
				if h != 0 {
					RecordClose(h)
					return
				}
				if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("refusal touched directory")
				}
			})
		}
	}
}
