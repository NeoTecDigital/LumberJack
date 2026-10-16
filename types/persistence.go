// Written by Richard Christopher, Copyright 2026 Richard Christopher

package types

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// The persistence and sync blocks of config.yaml.
//
// `persistence` says how a write reaches the disk. `snapshot` is what every build before this one
// did: the whole forest is rewritten per write, so a write costs the size of the store. `tiered`
// appends the changed nodes to a log beside the state file and rewrites the state file in the
// background, so a write costs the size of the change.
//
// `sync` names this instance's role among several. Only `single` runs in this build; `primary`
// and `replica` are accepted by the validator so a config written for a later build still parses,
// and refused at open so no one believes they are replicating when they are not.
const (
	PersistenceSnapshot = "snapshot"
	PersistenceTiered   = "tiered"

	HotSyncCommit   = "commit"
	HotSyncInterval = "interval"
	HotSyncNone     = "none"

	SyncRoleSingle  = "single"
	SyncRolePrimary = "primary"
	SyncRoleReplica = "replica"

	SyncAckLocal  = "local"
	SyncAckOne    = "one"
	SyncAckQuorum = "quorum"

	// StoreConfigFile is the file an embedded runtime reads its blocks from, in the database
	// directory beside the state file. The CLI reads the same blocks from its own config.yaml.
	StoreConfigFile = "config.yaml"
)

// PersistenceConfig is the `persistence` block.
type PersistenceConfig struct {
	Mode              string `yaml:"mode" json:"mode" mapstructure:"mode"`
	HotSync           string `yaml:"hot_sync" json:"hot_sync" mapstructure:"hot_sync"`
	HotSyncIntervalMS int    `yaml:"hot_sync_interval_ms" json:"hot_sync_interval_ms" mapstructure:"hot_sync_interval_ms"`
	ColdEveryCommits  int    `yaml:"cold_every_commits" json:"cold_every_commits" mapstructure:"cold_every_commits"`
	ColdEverySeconds  int    `yaml:"cold_every_seconds" json:"cold_every_seconds" mapstructure:"cold_every_seconds"`
}

// SyncConfig is the `sync` block.
type SyncConfig struct {
	Role    string `yaml:"role" json:"role" mapstructure:"role"`
	Listen  string `yaml:"listen" json:"listen" mapstructure:"listen"`
	Primary string `yaml:"primary" json:"primary" mapstructure:"primary"`
	Ack     string `yaml:"ack" json:"ack" mapstructure:"ack"`
}

// DefaultPersistence is today's behaviour: a whole state file per write.
func DefaultPersistence() PersistenceConfig {
	return PersistenceConfig{Mode: PersistenceSnapshot, HotSync: HotSyncCommit, HotSyncIntervalMS: 20,
		ColdEveryCommits: 2000, ColdEverySeconds: 60}
}

// DefaultSync is one instance on its own.
func DefaultSync() SyncConfig {
	return SyncConfig{Role: SyncRoleSingle, Ack: SyncAckLocal}
}

// WithDefaults fills every field the config left empty.
func (c PersistenceConfig) WithDefaults() PersistenceConfig {
	defaults := DefaultPersistence()
	if c.Mode == "" {
		c.Mode = defaults.Mode
	}
	if c.HotSync == "" {
		c.HotSync = defaults.HotSync
	}
	if c.HotSyncIntervalMS == 0 {
		c.HotSyncIntervalMS = defaults.HotSyncIntervalMS
	}
	if c.ColdEveryCommits == 0 {
		c.ColdEveryCommits = defaults.ColdEveryCommits
	}
	if c.ColdEverySeconds == 0 {
		c.ColdEverySeconds = defaults.ColdEverySeconds
	}
	return c
}

// Validate refuses a block that names something this program does not do.
func (c PersistenceConfig) Validate() error {
	switch c.Mode {
	case PersistenceSnapshot, PersistenceTiered:
	default:
		return fmt.Errorf("persistence.mode %q: use %q or %q", c.Mode, PersistenceSnapshot, PersistenceTiered)
	}
	switch c.HotSync {
	case HotSyncCommit, HotSyncInterval, HotSyncNone:
	default:
		return fmt.Errorf("persistence.hot_sync %q: use %q, %q or %q", c.HotSync, HotSyncCommit, HotSyncInterval, HotSyncNone)
	}
	if c.HotSyncIntervalMS < 1 {
		return fmt.Errorf("persistence.hot_sync_interval_ms %d: must be at least 1", c.HotSyncIntervalMS)
	}
	if c.ColdEveryCommits < 1 {
		return fmt.Errorf("persistence.cold_every_commits %d: must be at least 1", c.ColdEveryCommits)
	}
	if c.ColdEverySeconds < 1 {
		return fmt.Errorf("persistence.cold_every_seconds %d: must be at least 1", c.ColdEverySeconds)
	}
	return nil
}

// WithDefaults fills every field the config left empty.
func (c SyncConfig) WithDefaults() SyncConfig {
	defaults := DefaultSync()
	if c.Role == "" {
		c.Role = defaults.Role
	}
	if c.Ack == "" {
		c.Ack = defaults.Ack
	}
	return c
}

// Validate refuses a block that is inconsistent. A role this build does not run is ACCEPTED here
// and refused at open, with an error that says so.
func (c SyncConfig) Validate() error {
	switch c.Role {
	case SyncRoleSingle, SyncRolePrimary, SyncRoleReplica:
	default:
		return fmt.Errorf("sync.role %q: use %q, %q or %q", c.Role, SyncRoleSingle, SyncRolePrimary, SyncRoleReplica)
	}
	switch c.Ack {
	case SyncAckLocal, SyncAckOne, SyncAckQuorum:
	default:
		return fmt.Errorf("sync.ack %q: use %q, %q or %q", c.Ack, SyncAckLocal, SyncAckOne, SyncAckQuorum)
	}
	if c.Role == SyncRolePrimary && c.Listen == "" {
		return errors.New("sync.role primary needs sync.listen")
	}
	if c.Role == SyncRoleReplica && c.Primary == "" {
		return errors.New("sync.role replica needs sync.primary")
	}
	if c.Role == SyncRoleSingle && c.Ack != SyncAckLocal {
		return fmt.Errorf("sync.ack %q needs a primary; a single instance acknowledges locally", c.Ack)
	}
	return nil
}

// storeConfigFile is what LoadStoreConfig reads: the two blocks, and nothing else of config.yaml.
type storeConfigFile struct {
	Persistence PersistenceConfig `yaml:"persistence"`
	Sync        SyncConfig        `yaml:"sync"`
}

// LoadStoreConfig reads the persistence and sync blocks from `<dir>/config.yaml`.
//
// An ABSENT file is the defaults, so a database directory that has never been configured opens
// exactly as it always did. A file that is there and cannot be read or parsed is an error: a host
// that wrote `mode: tiered` and mistyped it must not silently run in snapshot mode.
func LoadStoreConfig(dir string) (PersistenceConfig, SyncConfig, error) {
	path := filepath.Join(dir, StoreConfigFile)
	body, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return DefaultPersistence(), DefaultSync(), nil
	}
	if err != nil {
		return PersistenceConfig{}, SyncConfig{}, fmt.Errorf("%s: %w", path, err)
	}
	var file storeConfigFile
	if err := yaml.Unmarshal(body, &file); err != nil {
		return PersistenceConfig{}, SyncConfig{}, fmt.Errorf("%s: %w", path, err)
	}
	persistence, sync := file.Persistence.WithDefaults(), file.Sync.WithDefaults()
	if err := persistence.Validate(); err != nil {
		return PersistenceConfig{}, SyncConfig{}, fmt.Errorf("%s: %w", path, err)
	}
	if err := sync.Validate(); err != nil {
		return PersistenceConfig{}, SyncConfig{}, fmt.Errorf("%s: %w", path, err)
	}
	return persistence, sync, nil
}
