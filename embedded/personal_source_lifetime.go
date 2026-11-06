// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package embedded

import (
	"context"
	"fmt"
	"sync"
)

type personalSourceRuntimeLifetime struct {
	epoch   string
	closing chan struct{}
}
type personalSourceRuntimeOwner struct {
	runtime *Runtime
	epoch   string
	limit   int
	pins    map[string]bool
}

var personalSourceOwners = struct {
	sync.Mutex
	byEpoch      map[string]*personalSourceRuntimeOwner
	reservations int
}{byEpoch: map[string]*personalSourceRuntimeOwner{}}

func reservePersonalSourceEpoch(limit int) error {
	personalSourceOwners.Lock()
	defer personalSourceOwners.Unlock()
	if limit <= 0 || len(personalSourceOwners.byEpoch)+personalSourceOwners.reservations >= limit {
		return fmt.Errorf("private source epoch capacity unavailable")
	}
	personalSourceOwners.reservations++
	return nil
}
func releasePersonalSourceReservation() {
	personalSourceOwners.Lock()
	personalSourceOwners.reservations--
	personalSourceOwners.Unlock()
}
func registerPersonalSourceOwner(rt *Runtime, epoch string, config PersonalSourceConfig) *personalSourceRuntimeOwner {
	registryMu.Lock()
	rt.sourceLifetime = &personalSourceRuntimeLifetime{epoch: epoch}
	registryMu.Unlock()
	owner := &personalSourceRuntimeOwner{rt, epoch, config.Bounds.MaxLeases, map[string]bool{}}
	personalSourceOwners.Lock()
	personalSourceOwners.byEpoch[epoch] = owner
	personalSourceOwners.Unlock()
	return owner
}
func lookupPersonalSourceOwner(epoch string) (*personalSourceRuntimeOwner, error) {
	personalSourceOwners.Lock()
	defer personalSourceOwners.Unlock()
	owner := personalSourceOwners.byEpoch[epoch]
	if owner == nil {
		return nil, ErrClosed
	}
	return owner, nil
}
func (owner *personalSourceRuntimeOwner) pin() (*Runtime, error) {
	registryMu.Lock()
	defer registryMu.Unlock()
	personalSourceOwners.Lock()
	rt := owner.runtime
	personalSourceOwners.Unlock()
	if rt == nil || rt.refs <= 0 || configuredOpenWait(rt) != nil {
		return nil, ErrClosed
	}
	rt.refs++
	return rt, nil
}
func (owner *personalSourceRuntimeOwner) retainCurrent() error {
	registryMu.Lock()
	defer registryMu.Unlock()
	personalSourceOwners.Lock()
	defer personalSourceOwners.Unlock()
	rt := owner.runtime
	if rt == nil || rt.refs <= 0 || configuredOpenWait(rt) != nil {
		return ErrClosed
	}
	ids := rt.server.PersonalSourceRetained()
	if len(ids) > owner.limit {
		return fmt.Errorf("actual source entries exceed protected capacity")
	}
	for _, id := range ids {
		if !owner.pins[id] {
			owner.pins[id] = true
			rt.refs++
		}
	}
	return nil
}
func (owner *personalSourceRuntimeOwner) complete(id string) {
	personalSourceOwners.Lock()
	rt := owner.runtime
	held := rt != nil && owner.pins[id]
	if held {
		delete(owner.pins, id)
	}
	personalSourceOwners.Unlock()
	if held {
		_ = rt.close()
	}
}
func configuredOpenWait(rt *Runtime) chan struct{} {
	if wait := domainOpenWait(rt); wait != nil {
		return wait
	}
	if rt != nil && rt.sourceLifetime != nil {
		return rt.sourceLifetime.closing
	}
	return nil
}

// Called with no registry/source/forest lock. Both configured surfaces share
// actual refs, file/flock, Server and teardown; retained unknown pins prevent it.
func (rt *Runtime) closeConfiguredRuntime(wait chan struct{}) error {
	if rt.domainLifetime != nil {
		err := rt.closeDomainRuntime(wait)
		rt.detachPersonalSourceOwner()
		return err
	}
	err := rt.server.Shutdown(context.Background())
	if lockErr := releaseLock(rt.lock); err == nil {
		err = lockErr
	}
	registryMu.Lock()
	rt.detachPersonalSourceOwner()
	delete(registry, rt.path)
	close(rt.closed)
	close(wait)
	registryMu.Unlock()
	return err
}
func (rt *Runtime) detachPersonalSourceOwner() {
	personalSourceOwners.Lock()
	defer personalSourceOwners.Unlock()
	if rt.sourceLifetime == nil {
		return
	}
	owner := personalSourceOwners.byEpoch[rt.sourceLifetime.epoch]
	if owner != nil && owner.runtime == rt {
		owner.runtime = nil
	}
}
