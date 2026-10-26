// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package embedded

import (
	"context"
	"crypto/subtle"
	"fmt"
	engine "github.com/NeoTecDigital/LumberJack/internal"
	"sync"
)

type domainRuntimeLifetime struct {
	epoch   string
	closing chan struct{}
}
type domainRuntimeOwner struct {
	runtime  *Runtime
	hostID   string
	token    string
	limit    int
	pins     map[string]*Runtime
	finished map[string]engine.DomainCompletion
}

var domainOwners = struct {
	sync.Mutex
	byEpoch      map[string]*domainRuntimeOwner
	reservations int
}{byEpoch: map[string]*domainRuntimeOwner{}}

func reserveDomainEpoch(limit int) error {
	domainOwners.Lock()
	defer domainOwners.Unlock()
	if limit <= 0 || len(domainOwners.byEpoch)+domainOwners.reservations >= limit {
		return fmt.Errorf("explicit retained epoch capacity exhausted/unconfigured")
	}
	domainOwners.reservations++
	return nil
}
func releaseDomainEpochReservation() {
	domainOwners.Lock()
	domainOwners.reservations--
	domainOwners.Unlock()
}

func registerDomainOwner(rt *Runtime, epoch string, config DomainConfig) {
	domainOwners.Lock()
	defer domainOwners.Unlock()
	domainOwners.byEpoch[epoch] = &domainRuntimeOwner{runtime: rt, hostID: config.HostID, token: config.ControlToken, limit: config.MaxLeases, pins: map[string]*Runtime{}, finished: map[string]engine.DomainCompletion{}}
}
func lookupDomainOwner(epoch string) (*domainRuntimeOwner, error) {
	domainOwners.Lock()
	defer domainOwners.Unlock()
	owner := domainOwners.byEpoch[epoch]
	if owner == nil {
		return nil, fmt.Errorf("native epoch unknown")
	}
	return owner, nil
}
func retainDomainLease(rt *Runtime, begin engine.DomainBegin) error {
	domainOwners.Lock()
	defer domainOwners.Unlock()
	owner := domainOwners.byEpoch[begin.Lease.Epoch]
	if owner == nil || owner.runtime != rt || len(owner.pins)+len(owner.finished) >= owner.limit {
		return fmt.Errorf("bounded native lease registry unavailable/full")
	}
	owner.pins[begin.Lease.LeaseID] = rt
	return nil
}
func (owner *domainRuntimeOwner) completed(input DomainControl) ([]byte, bool, error) {
	domainOwners.Lock()
	defer domainOwners.Unlock()
	done, present := owner.finished[input.LeaseID]
	if !present || input.Action != "finish" {
		return nil, false, nil
	}
	if input.HostID != owner.hostID || subtle.ConstantTimeCompare([]byte(input.ChannelToken), []byte(owner.token)) != 1 || input.ResponseHash != done.ResponseHash || input.Disposition != done.Disposition {
		return nil, true, fmt.Errorf("native completion tombstone mismatch")
	}
	if input.Disposition == "handed-off" && input.PermitID != done.PermitID {
		return nil, true, fmt.Errorf("native completion permit mismatch")
	}
	body, err := engine.CanonicalDomainJSON(map[string]bool{"completed": true})
	return body, true, err
}
func releaseDomainLease(owner *domainRuntimeOwner, input DomainControl) {
	completion := engine.DomainCompletion{LeaseID: input.LeaseID, ResponseHash: input.ResponseHash, Disposition: input.Disposition, PermitID: input.PermitID}
	sweepDomainCompletions(owner, []engine.DomainCompletion{completion})
}
func sweepDomainCompletions(owner *domainRuntimeOwner, completed []engine.DomainCompletion) {
	for _, done := range completed {
		releaseDomainCompletion(owner, done)
	}
}
func releaseDomainCompletion(owner *domainRuntimeOwner, done engine.DomainCompletion) {
	domainOwners.Lock()
	rt := owner.pins[done.LeaseID]
	if rt != nil {
		delete(owner.pins, done.LeaseID)
		owner.finished[done.LeaseID] = done
	}
	domainOwners.Unlock()
	if rt != nil {
		_ = rt.close()
	}
}
func domainRuntimeClosing(rt *Runtime) bool {
	return rt != nil && rt.domainLifetime != nil && rt.domainLifetime.closing != nil
}
func (rt *Runtime) closeDomainRuntime(wait chan struct{}) error {
	err := rt.server.Shutdown(context.Background())
	if lockErr := releaseLock(rt.lock); err == nil {
		err = lockErr
	}
	registryMu.Lock()
	domainOwners.Lock()
	owner := domainOwners.byEpoch[rt.domainLifetime.epoch]
	if owner != nil && owner.runtime == rt {
		owner.runtime = nil
	}
	domainOwners.Unlock()
	delete(registry, rt.path)
	close(rt.closed)
	close(wait)
	registryMu.Unlock()
	// Lifetime pointer is immutable; its refs are read under registryMu, not this registry.
	return err
}
func domainOpenWait(rt *Runtime) chan struct{} {
	if domainRuntimeClosing(rt) {
		return rt.domainLifetime.closing
	}
	return nil
}
