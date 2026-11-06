// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package embedded

import (
	"fmt"

	"github.com/NeoTecDigital/LumberJack/internal"
)

type SessionAdmissionConfig = internal.SessionAdmissionConfig

func DecodeSessionAdmissionConfig(body []byte) (SessionAdmissionConfig, error) {
	return internal.DecodeSessionAdmissionConfig(body)
}

// ConfigureSessionAdmission is explicit and one-shot, after the application is configured. Without
// it POST /session/admit refuses every admission.
func (h *Handle) ConfigureSessionAdmission(config SessionAdmissionConfig) error {
	registryMu.Lock()
	defer registryMu.Unlock()
	if err := h.ensureOpen(); err != nil {
		return err
	}
	if !h.runtime.application.Load() {
		return fmt.Errorf("application is not configured")
	}
	return h.runtime.server.ConfigureSessionAdmission(config)
}
