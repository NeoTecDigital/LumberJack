// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package types

import (
	"reflect"
	"testing"
)

// The storage environment (owner decision Q10(a)): LUMBERJACK_STORAGE_* is read; the older
// CORRESPONDER_STORAGE_* names are read for one release, only where the new name is not set, and
// said to be deprecated.

// clearStorageEnvironment unsets every storage variable for the test, so only what it sets is read.
func clearStorageEnvironment(t *testing.T) {
	t.Helper()
	for _, variable := range storageEnvironment {
		unsetForTest(t, variable.name)
		if variable.deprecated != "" {
			unsetForTest(t, variable.deprecated)
		}
	}
}

func TestStorageEnvironmentPrefersNewNamesAndAcceptsOldOnes(t *testing.T) {
	clearStorageEnvironment(t)
	t.Setenv("CORRESPONDER_STORAGE_MODE", "local-test")
	t.Setenv("CORRESPONDER_STORAGE_LOCAL_KEY_FILE", "/old/key")
	t.Setenv("CORRESPONDER_STORAGE_MIGRATE_LEGACY", "1")
	t.Setenv("LUMBERJACK_STORAGE_LOCAL_KEY_FILE", "/new/key")
	t.Setenv("LUMBERJACK_STORAGE_WRITE_LABEL", StorageLabelNeutral)
	config, deprecated := StorageFromEnvironment()
	want := StorageConfig{Mode: "local-test", LocalKeyFile: "/new/key", MigrateLegacy: true, WriteLabel: StorageLabelNeutral}
	if config != want {
		t.Fatalf("read %+v, want %+v", config, want)
	}
	if !reflect.DeepEqual(deprecated, []string{"CORRESPONDER_STORAGE_MODE", "CORRESPONDER_STORAGE_MIGRATE_LEGACY"}) {
		t.Fatalf("deprecated names reported: %v", deprecated)
	}
}

func TestStorageSwitchesAreAnExactOne(t *testing.T) {
	clearStorageEnvironment(t)
	t.Setenv("LUMBERJACK_STORAGE_REWRAP_KEYS", "true")
	t.Setenv("LUMBERJACK_STORAGE_MIGRATE_LEGACY", "1")
	config, deprecated := StorageFromEnvironment()
	if config.RewrapKeys || !config.MigrateLegacy || len(deprecated) != 0 {
		t.Fatalf("read %+v (%v)", config, deprecated)
	}
}

func TestAdminReconcileAlias(t *testing.T) {
	unsetForTest(t, "LUMBERJACK_ADMIN_RECONCILE")
	t.Setenv("CORRESPONDER_ADMIN_RECONCILE", "1")
	if reconcile, deprecated := AdminReconcileFromEnvironment(); !reconcile || !deprecated {
		t.Fatalf("the deprecated name read as %v (deprecated %v)", reconcile, deprecated)
	}
	t.Setenv("LUMBERJACK_ADMIN_RECONCILE", "0")
	if reconcile, deprecated := AdminReconcileFromEnvironment(); reconcile || deprecated {
		t.Fatalf("the new name did not win: %v (deprecated %v)", reconcile, deprecated)
	}
}

func TestStorageWriteLabelIsOneOfTwo(t *testing.T) {
	for label, valid := range map[string]bool{"": true, StorageLabelLegacy: true, StorageLabelNeutral: true, "momentum": false} {
		if err := (StorageConfig{WriteLabel: label}).Validate(); (err == nil) != valid {
			t.Errorf("label %q: %v", label, err)
		}
	}
}
