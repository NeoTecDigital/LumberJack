// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package embedded

import (
	"context"
	engine "github.com/NeoTecDigital/LumberJack/internal"
)

type PersonalSourceConfig = engine.PersonalSourceConfig
type PersonalSourceEnvelope = engine.SourceEnvelope

func (h *Handle) ConfigurePersonalSource(raw []byte) ([]byte, error) {
	var config PersonalSourceConfig
	if engine.DecodeDomainJSON(raw, &config) != nil {
		return nil, ErrClosed
	}
	rt, err := h.domainPin()
	if err != nil {
		return nil, err
	}
	defer rt.close()
	if err = reservePersonalSourceEpoch(config.Bounds.MaxRetainedEpochs); err != nil {
		return nil, err
	}
	defer releasePersonalSourceReservation()
	result, err := rt.server.ConfigurePersonalSource(config)
	if err != nil {
		return nil, err
	}
	epoch, err := rt.server.PersonalSourceEpoch()
	if err != nil {
		return nil, err
	}
	owner := registerPersonalSourceOwner(rt, epoch, config)
	if err = rt.server.SetPersonalSourceCompletion(epoch, owner.complete); err != nil {
		return nil, err
	}
	return engine.CanonicalDomainJSON(result)
}

// Execute once, sync ACTUAL retained entries even on an unknown/error envelope.
// No public response sizing reruns or Handle/systemDefault authority are used.
func (h *Handle) PersonalSourceCall(raw []byte) ([]byte, error) {
	rt, err := h.domainPin()
	if err != nil {
		return nil, err
	}
	defer rt.close()
	epoch, err := rt.server.PersonalSourceEpoch()
	if err != nil {
		return nil, err
	}
	owner, err := lookupPersonalSourceOwner(epoch)
	if err != nil {
		return nil, err
	}
	result, cause := rt.server.PersonalSourceCall(context.Background(), raw)
	if err = owner.retainCurrent(); err != nil {
		return nil, err
	}
	return result, cause
}
func PersonalSourceControlCall(raw []byte) ([]byte, error) {
	var request PersonalSourceEnvelope
	if engine.DecodeDomainJSON(raw, &request) != nil {
		return nil, ErrClosed
	}
	owner, err := lookupPersonalSourceOwner(request.Epoch)
	if err != nil {
		return nil, err
	}
	rt, err := owner.pin()
	if err != nil {
		return nil, err
	}
	defer rt.close()
	result, cause := rt.server.PersonalSourceCall(context.Background(), raw)
	if err = owner.retainCurrent(); err != nil {
		return nil, err
	}
	return result, cause
}
func PersonalSourceFailure(err error) []byte { return engine.PersonalSourceFailure(err) }

// Protected setup only; SAME handle/server/storage and existing source epoch.
func (h *Handle) ConfigureNativeControl(raw []byte) ([]byte, error) {
	rt, err := h.domainPin()
	if err != nil {
		return nil, err
	}
	defer rt.close()
	result, err := rt.server.ConfigureNativeControl(raw)
	if err != nil {
		return nil, err
	}
	return engine.CanonicalDomainJSON(result)
}
func VerifyNativeSourceSeal(raw []byte) ([]byte, error) { return engine.VerifyNativeSourceSeal(raw) }
