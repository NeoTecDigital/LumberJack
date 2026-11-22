// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package abi

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"github.com/NeoTecDigital/LumberJack/embedded"
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
