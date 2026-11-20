// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package embedded

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"syscall"
)

// ErrProfileConflict means the other store profile owns this sidecar in this process.
// It is a configuration conflict (not retryable lock contention).
var ErrProfileConflict = fmt.Errorf("incompatible open store profile: %w", ErrRecordConflict)

type storeProfile uint8

const (
	unclassifiedProfile storeProfile = iota
	pointerProfile
	recordProfile
)

type profileHolder struct {
	info    os.FileInfo
	profile storeProfile
}

var (
	profileMu      sync.Mutex
	profileHolders = make(map[*os.File]profileHolder)
)

// Classify only an actual flock collision. Match file identity rather than path text so
// aliases cannot turn a local configuration conflict into a retryable error. The mutex
// covers the nonblocking lock and its registration (and the reverse order on release).
func lockProfile(file *os.File, profile storeProfile) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	profileMu.Lock()
	defer profileMu.Unlock()
	err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err == nil {
		if profile != unclassifiedProfile {
			profileHolders[file] = profileHolder{info, profile}
		}
		return nil
	}
	if !errors.Is(err, syscall.EWOULDBLOCK) {
		return err
	}
	if profile != unclassifiedProfile {
		for _, holder := range profileHolders {
			if holder.profile != profile && os.SameFile(holder.info, info) {
				return ErrProfileConflict
			}
		}
	}
	return ErrLocked
}
