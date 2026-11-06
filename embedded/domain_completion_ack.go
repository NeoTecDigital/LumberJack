// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package embedded

import (
	"crypto/subtle"
	"fmt"

	engine "github.com/NeoTecDigital/LumberJack/internal"
)

// DomainAcknowledgeCompletionCall frees only an authenticated, finished lease.
func DomainAcknowledgeCompletionCall(body []byte) ([]byte, error) {
	input, err := engine.DecodeDomainCompletionAck(body)
	if err != nil {
		return nil, err
	}
	owner, err := lookupDomainOwner(input.Epoch)
	if err != nil {
		return nil, err
	}
	rt, err := owner.pinCompletionAck(input)
	if err != nil {
		return nil, err
	}
	if rt != nil {
		defer rt.close()
		domainOwners.Lock()
		err = rt.server.AcknowledgeDomainCompletion(input)
		if err == nil {
			delete(owner.finished, input.LeaseID)
		}
		domainOwners.Unlock()
		if err != nil {
			return nil, err
		}
	}
	return engine.CanonicalDomainJSON(map[string]bool{"acknowledged": true})
}

func (owner *domainRuntimeOwner) pinCompletionAck(input DomainControl) (*Runtime, error) {
	registryMu.Lock()
	defer registryMu.Unlock()
	domainOwners.Lock()
	defer domainOwners.Unlock()
	done, present := owner.finished[input.LeaseID]
	if !present || input.HostID != owner.hostID || subtle.ConstantTimeCompare([]byte(input.ChannelToken), []byte(owner.token)) != 1 {
		return nil, fmt.Errorf("native completion acknowledgement denied")
	}
	if input.ResponseHash != done.ResponseHash || input.Disposition != done.Disposition {
		return nil, fmt.Errorf("native completion acknowledgement mismatch")
	}
	if input.Disposition == "handed-off" && input.PermitID != done.PermitID {
		return nil, fmt.Errorf("native completion acknowledgement permit mismatch")
	}
	rt := owner.runtime
	if rt == nil {
		delete(owner.finished, input.LeaseID)
		return nil, nil
	}
	if rt.refs <= 0 || domainRuntimeClosing(rt) {
		return nil, fmt.Errorf("native completion acknowledgement closing")
	}
	rt.refs++
	return rt, nil
}
