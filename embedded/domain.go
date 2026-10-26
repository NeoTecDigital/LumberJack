// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package embedded

import (
	"context"
	"fmt"

	engine "github.com/NeoTecDigital/LumberJack/internal"
)

type DomainConfig = engine.DomainConfig
type DomainInput = engine.DomainInput
type DomainRequest = engine.DomainRequest
type DomainControl = engine.DomainControl

func (h *Handle) ConfigureDomain(body []byte) ([]byte, error) {
	var config DomainConfig
	if err := engine.DecodeDomainJSON(body, &config); err != nil {
		return nil, err
	}
	products, policy, err := manifestDomainRegistration(config)
	if err != nil {
		return nil, err
	}
	rt, err := h.domainPin()
	if err != nil {
		return nil, err
	}
	defer rt.close()
	if err = reserveDomainEpoch(config.MaxRetainedEpochs); err != nil {
		return nil, err
	}
	defer releaseDomainEpochReservation()
	if err = rt.server.ConfigureDomain(config, products, policy); err != nil {
		return nil, err
	}
	epoch, err := rt.server.DomainEpoch()
	if err != nil {
		return nil, err
	}
	registryMu.Lock()
	rt.domainLifetime = &domainRuntimeLifetime{epoch: epoch}
	registryMu.Unlock()
	registerDomainOwner(rt, epoch, config)
	return engine.CanonicalDomainJSON(map[string]interface{}{"configured": true, "epoch": epoch, "maxLeases": config.MaxLeases})
}
func (h *Handle) DomainResolve(body []byte) ([]byte, error) {
	var input DomainInput
	if err := engine.DecodeDomainJSON(body, &input); err != nil {
		return nil, err
	}
	rt, err := h.domainPin()
	if err != nil {
		return nil, err
	}
	defer rt.close()
	intent, err := rt.server.DomainResolve(context.Background(), input)
	if err != nil {
		return nil, err
	}
	return engine.CanonicalDomainJSON(intent)
}
func (h *Handle) DomainCall(body []byte) ([]byte, error) {
	var input DomainRequest
	if err := engine.DecodeDomainJSON(body, &input); err != nil {
		return nil, err
	}
	rt, err := h.domainPin()
	if err != nil {
		return nil, err
	}
	begin, err := rt.server.DomainCall(context.Background(), input)
	if err != nil {
		_ = rt.close()
		return nil, err
	}
	if err = retainDomainLease(rt, begin); err != nil {
		_ = rt.close()
		return nil, err
	}
	return engine.CanonicalDomainJSON(begin)
}
func DomainControlCall(body []byte) ([]byte, error) {
	var input DomainControl
	if err := engine.DecodeDomainControlJSON(body, &input); err != nil {
		return nil, err
	}
	owner, err := lookupDomainOwner(input.Epoch)
	if err != nil {
		return nil, err
	}
	if answer, found, err := owner.completed(input); found || err != nil {
		return answer, err
	}
	rt, err := owner.pin()
	if err != nil {
		return nil, err
	}
	defer rt.close()
	result, err := rt.server.DomainControl(context.Background(), input)
	if err != nil {
		return nil, err
	}
	if result.Completed {
		releaseDomainLease(owner, input)
	}
	if input.Action == "close" {
		sweepDomainCompletions(owner, rt.server.DomainCompletedLeases())
	}
	return engine.CanonicalDomainJSON(result.Value)
}
func DomainFailure(code string) []byte {
	if code != "domain_invalid" && code != "domain_unavailable" {
		code = "domain_denied"
	}
	body, _ := engine.CanonicalDomainJSON(map[string]interface{}{"error": map[string]string{"code": code, "outcome": "unknown"}})
	return body
}
func (h *Handle) domainPin() (*Runtime, error) {
	registryMu.Lock()
	defer registryMu.Unlock()
	if h.done.Load() || h.runtime.refs <= 0 || domainRuntimeClosing(h.runtime) {
		return nil, ErrClosed
	}
	h.runtime.refs++
	return h.runtime, nil
}
func (o *domainRuntimeOwner) pin() (*Runtime, error) {
	registryMu.Lock()
	defer registryMu.Unlock()
	rt := o.runtime
	if rt == nil || rt.refs <= 0 || domainRuntimeClosing(rt) {
		return nil, fmt.Errorf("native epoch unavailable")
	}
	rt.refs++
	return rt, nil
}
