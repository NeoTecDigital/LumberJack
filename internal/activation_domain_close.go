// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"crypto/subtle"
	"fmt"
)

// Closed tuples and retained lease/completion entries each use the explicit MaxLeases
// capacity. They are separate capped sets, without eviction, expiry or fake draining.
func validateDomainCloseKeysLocked(d *domainEngine, keys []DomainGateKey) error {
	if len(keys) == 0 || len(keys) > d.config.MaxResources {
		return fmt.Errorf("explicit bounded gate closure required")
	}
	newKeys := map[DomainGateKey]bool{}
	for _, key := range keys {
		owned, present := d.scopes[key.Scope]
		if !present || owned.Binding.RootID == "" {
			return fmt.Errorf("gate closure binding invalid")
		}
		if err := validateStagedIdentifiers(owned.Bounds, key.PrincipalID, key.SessionID); err != nil {
			return err
		}
		if !d.closed[key] {
			newKeys[key] = true
		}
	}
	if len(newKeys) > 0 && len(newKeys) > d.config.MaxLeases-len(d.closed) {
		return fmt.Errorf("explicit retained closed-key capacity exhausted")
	}
	return nil
}

func (s *Server) closeDomainKeys(d *domainEngine, input DomainControl) (DomainControlResult, error) {
	if input.Epoch != d.epoch || input.HostID != d.config.HostID || d.config.OwnerControlToken == "" || subtle.ConstantTimeCompare([]byte(input.ChannelToken), []byte(d.config.OwnerControlToken)) != 1 {
		return DomainControlResult{}, fmt.Errorf("authority-owner close channel denied")
	}
	d.mu.Lock()
	if err := validateDomainCloseKeysLocked(d, input.Keys); err != nil {
		d.mu.Unlock()
		return DomainControlResult{}, err
	}
	for _, key := range input.Keys {
		d.closed[key] = true
	}
	unadopted := domainUnadoptedClosedLocked(d)
	d.mu.Unlock()
	for _, entry := range unadopted {
		_, _ = s.finishDomain(d, entry, DomainControl{ResponseHash: entry.responseHash, Disposition: "irrevocably-discarded"})
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	drained := true
	for _, entry := range d.entries {
		key := DomainGateKey{entry.lease.PrincipalID, entry.lease.SessionID, entry.lease.Scope}
		if d.closed[key] && !entry.finished {
			drained = false
		}
	}
	return DomainControlResult{Value: map[string]bool{"closed": true, "drained": drained}}, nil
}

func domainUnadoptedClosedLocked(d *domainEngine) []*domainEntry {
	result := []*domainEntry{}
	for _, entry := range d.entries {
		key := DomainGateKey{entry.lease.PrincipalID, entry.lease.SessionID, entry.lease.Scope}
		if d.closed[key] && !entry.adopted && !entry.executing && !entry.finished {
			result = append(result, entry)
		}
	}
	return result
}
