// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package embedded

import (
	"fmt"
	"github.com/NeoTecDigital/LumberJack/internal"
)

type ActivationConfig = internal.ActivationConfig

func DecodeActivationConfig(body []byte) (ActivationConfig, error) {
	return internal.DecodeActivationConfig(body)
}

func ValidateActivationConfig(config ActivationConfig) error {
	return internal.ValidateActivationConfig(config)
}

// ConfigureActivation is explicit, one-shot and independent of native user identities.
func (h *Handle) ConfigureActivation(config ActivationConfig) error {
	registryMu.Lock()
	defer registryMu.Unlock()
	if err := h.ensureOpen(); err != nil {
		return err
	}
	if !h.runtime.application.Load() {
		return fmt.Errorf("application is not configured")
	}
	return h.runtime.server.ConfigureActivation(config)
}
