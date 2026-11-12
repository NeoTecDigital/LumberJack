// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package types

import (
	"fmt"
	"os"
)

// StorageConfig is how a store seals its state file and its objects. A ServerConfig that carries
// one is explicit and the environment is not read; one that does not reads the environment
// (StorageFromEnvironment), which is how the CLI and the C ABI configure it.
type StorageConfig struct {
	// Mode is "" (plaintext), "kms" or "local-test".
	Mode string `json:"mode,omitempty" yaml:"mode" mapstructure:"mode"`
	// KMSKey is the Cloud KMS CryptoKey resource name, for "kms".
	KMSKey string `json:"kms_key,omitempty" yaml:"kms_key" mapstructure:"kms_key"`
	// LocalKeyFile is a private 32-byte key file, for "local-test".
	LocalKeyFile string `json:"local_key_file,omitempty" yaml:"local_key_file" mapstructure:"local_key_file"`
	// MigrateLegacy lets a plaintext state file be sealed on open: the reviewed offline cutover.
	MigrateLegacy bool `json:"migrate_legacy,omitempty" yaml:"migrate_legacy" mapstructure:"migrate_legacy"`
	// RewrapKeys wraps every account key again on open.
	RewrapKeys bool `json:"rewrap_keys,omitempty" yaml:"rewrap_keys" mapstructure:"rewrap_keys"`
	// WriteLabel is the sealing label written: StorageLabelLegacy (the default for this release)
	// or StorageLabelNeutral. A store read under the neutral label stays neutral.
	WriteLabel string `json:"write_label,omitempty" yaml:"write_label" mapstructure:"write_label"`
}

// The sealing labels a store may be written under (docs/extension-api.md §7.5).
const (
	StorageLabelLegacy  = "legacy"
	StorageLabelNeutral = "neutral"
)

// Validate refuses a label no build writes.
func (c StorageConfig) Validate() error {
	switch c.WriteLabel {
	case "", StorageLabelLegacy, StorageLabelNeutral:
		return nil
	}
	return fmt.Errorf("storage write_label %q: use %q or %q", c.WriteLabel, StorageLabelLegacy, StorageLabelNeutral)
}

// storageEnvironment is each StorageConfig field's variable, and the deprecated name it replaces.
var storageEnvironment = []struct {
	name, deprecated string
	set              func(*StorageConfig, string)
}{
	{"LUMBERJACK_STORAGE_MODE", "CORRESPONDER_STORAGE_MODE", func(c *StorageConfig, v string) { c.Mode = v }},
	{"LUMBERJACK_STORAGE_KMS_KEY", "CORRESPONDER_STORAGE_KMS_KEY", func(c *StorageConfig, v string) { c.KMSKey = v }},
	{"LUMBERJACK_STORAGE_LOCAL_KEY_FILE", "CORRESPONDER_STORAGE_LOCAL_KEY_FILE", func(c *StorageConfig, v string) { c.LocalKeyFile = v }},
	{"LUMBERJACK_STORAGE_MIGRATE_LEGACY", "CORRESPONDER_STORAGE_MIGRATE_LEGACY", func(c *StorageConfig, v string) { c.MigrateLegacy = v == "1" }},
	{"LUMBERJACK_STORAGE_REWRAP_KEYS", "CORRESPONDER_STORAGE_REWRAP_KEYS", func(c *StorageConfig, v string) { c.RewrapKeys = v == "1" }},
	{"LUMBERJACK_STORAGE_WRITE_LABEL", "", func(c *StorageConfig, v string) { c.WriteLabel = v }},
}

// StorageFromEnvironment reads the storage configuration from LUMBERJACK_STORAGE_*. For one release
// each older CORRESPONDER_STORAGE_* name is still read when its new name is not set at all; the
// names it fell back to are answered, so the caller can say they are deprecated. The switches are
// read as an exact "1", as they always were.
func StorageFromEnvironment() (StorageConfig, []string) {
	var config StorageConfig
	var deprecated []string
	for _, variable := range storageEnvironment {
		if value, set := os.LookupEnv(variable.name); set {
			variable.set(&config, value)
			continue
		}
		if variable.deprecated == "" {
			continue
		}
		if value, set := os.LookupEnv(variable.deprecated); set {
			variable.set(&config, value)
			deprecated = append(deprecated, variable.deprecated)
		}
	}
	return config, deprecated
}

// AdminReconcileFromEnvironment reads LUMBERJACK_ADMIN_RECONCILE, or for one release the deprecated
// CORRESPONDER_ADMIN_RECONCILE when the new name is not set; it answers whether it fell back.
func AdminReconcileFromEnvironment() (reconcile bool, deprecated bool) {
	if value, set := os.LookupEnv("LUMBERJACK_ADMIN_RECONCILE"); set {
		return value == "1", false
	}
	value, set := os.LookupEnv("CORRESPONDER_ADMIN_RECONCILE")
	return set && value == "1", set
}
