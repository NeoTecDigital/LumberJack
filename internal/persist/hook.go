// Written by Richard Christopher, Copyright 2026 Richard Christopher

package persist

import (
	"fmt"

	"github.com/NeoTecDigital/LumberJack/types"
)

// Hook is the sync layer's seam: it receives every record after the local append has succeeded,
// in sequence order, before the commit that staged it is acknowledged. A primary ships the record
// to its replicas from here; a replica applies what the primary ships through the same shape.
//
// This build has one implementation, the no-op below. The two roles that need another are
// accepted by the config validator and refused by OpenHook, so a config written for the build
// that implements them parses today and says plainly what it cannot do.
type Hook interface {
	// Appended is called once per record, after the record is durable to the configured
	// hot_sync. An error is reported to the committer; the local append is not undone.
	Appended(record Record) error
	// Close releases whatever the hook holds. It is called once, at log close.
	Close() error
}

// NoHook is the single-instance hook: nothing leaves the process.
type NoHook struct{}

func (NoHook) Appended(Record) error { return nil }
func (NoHook) Close() error          { return nil }

// OpenHook answers the hook a sync config asks for, or refuses with an error naming the role.
func OpenHook(config types.SyncConfig) (Hook, error) {
	switch config.Role {
	case types.SyncRoleSingle:
		return NoHook{}, nil
	case types.SyncRolePrimary, types.SyncRoleReplica:
		return nil, fmt.Errorf("sync.role %q is not available in this build: only %q runs; the role is "+
			"accepted by the config so it can be set ahead of the build that implements it", config.Role, types.SyncRoleSingle)
	default:
		return nil, fmt.Errorf("sync.role %q is not one this program knows", config.Role)
	}
}
