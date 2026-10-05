// Written by Richard Christopher, Copyright 2026 Richard Christopher

package types

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultsAreTodaysBehaviour(t *testing.T) {
	persistence, sync := PersistenceConfig{}.WithDefaults(), SyncConfig{}.WithDefaults()
	if persistence.Mode != PersistenceSnapshot || persistence.HotSync != HotSyncCommit || sync.Role != SyncRoleSingle || sync.Ack != SyncAckLocal {
		t.Fatalf("defaults: %+v %+v", persistence, sync)
	}
	if err := persistence.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := sync.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestPersistenceValidationRefusesWhatItDoesNotDo(t *testing.T) {
	cases := map[string]PersistenceConfig{
		"persistence.mode":                 {Mode: "journal"},
		"persistence.hot_sync":             {HotSync: "sometimes"},
		"persistence.hot_sync_interval_ms": {HotSyncIntervalMS: -5},
		"persistence.cold_every_commits":   {ColdEveryCommits: -1},
		"persistence.cold_every_seconds":   {ColdEverySeconds: -1},
	}
	for want, config := range cases {
		err := config.WithDefaults().Validate()
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: %v", want, err)
		}
	}
}

func TestSyncValidationAcceptsRolesThisBuildRefusesLater(t *testing.T) {
	if err := (SyncConfig{Role: SyncRolePrimary, Listen: ":9000"}).WithDefaults().Validate(); err != nil {
		t.Fatalf("primary with listen: %v", err)
	}
	if err := (SyncConfig{Role: SyncRoleReplica, Primary: "host:9000"}).WithDefaults().Validate(); err != nil {
		t.Fatalf("replica with primary: %v", err)
	}
	for want, config := range map[string]SyncConfig{
		"sync.role":            {Role: "observer"},
		"sync.ack":             {Ack: "all"},
		"needs sync.listen":    {Role: SyncRolePrimary},
		"needs sync.primary":   {Role: SyncRoleReplica},
		"acknowledges locally": {Role: SyncRoleSingle, Ack: SyncAckQuorum},
	} {
		err := config.WithDefaults().Validate()
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: %v", want, err)
		}
	}
}

func TestLoadStoreConfigReadsTheBlocksBesideTheStateFile(t *testing.T) {
	dir := t.TempDir()
	persistence, sync, err := LoadStoreConfig(dir)
	if err != nil || persistence.Mode != PersistenceSnapshot || sync.Role != SyncRoleSingle {
		t.Fatalf("absent file: %+v %+v %v", persistence, sync, err)
	}
	body := "version: x\npersistence:\n  mode: tiered\n  hot_sync: interval\n  hot_sync_interval_ms: 5\nsync:\n  role: single\n"
	if err := os.WriteFile(filepath.Join(dir, StoreConfigFile), []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	persistence, sync, err = LoadStoreConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if persistence.Mode != PersistenceTiered || persistence.HotSync != HotSyncInterval || persistence.HotSyncIntervalMS != 5 || persistence.ColdEveryCommits != 2000 {
		t.Fatalf("loaded %+v", persistence)
	}
	if err := os.WriteFile(filepath.Join(dir, StoreConfigFile), []byte("persistence:\n  mode: tierd\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadStoreConfig(dir); err == nil || !strings.Contains(err.Error(), `persistence.mode "tierd"`) {
		t.Fatalf("misspelt mode: %v", err)
	}
}
