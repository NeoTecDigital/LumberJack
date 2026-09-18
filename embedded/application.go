package embedded

import (
	"fmt"
	"github.com/NeoTecDigital/LumberJack/internal"
)

type ApplicationRequest = internal.ApplicationRequest
type ApplicationResponse = internal.ApplicationResponse

// ConfigureApplication switches this runtime from trusted-library bootstrap to
// authenticated application use. All old handles also lose implicit system access.
func (h *Handle) ConfigureApplication(username, password, secret string) error {
	registryMu.Lock()
	defer registryMu.Unlock()
	if err := h.ensureOpen(); err != nil {
		return err
	}
	if h.runtime.application.Load() {
		return fmt.Errorf("application already configured")
	}
	if err := h.runtime.server.ConfigureApplication(username, password, secret); err != nil {
		return err
	}
	h.runtime.application.Store(true)
	return nil
}

func (h *Handle) ApplicationCall(request ApplicationRequest) (ApplicationResponse, error) {
	if err := h.ensureOpen(); err != nil {
		return ApplicationResponse{}, err
	}
	if !h.runtime.application.Load() {
		return ApplicationResponse{}, fmt.Errorf("application is not configured")
	}
	return h.runtime.server.ApplicationCall(request), nil
}

func (h *Handle) actor() string {
	if h.runtime.application.Load() {
		return h.requestedPrincipal
	}
	return h.principal
}

// ApplicationHub is reserved for the trusted embedder, separate from requests
// authenticated through ApplicationCall.
func (h *Handle) ApplicationHub(request []byte) ([]byte, error) {
	if err := h.ensureOpen(); err != nil {
		return nil, err
	}
	if !h.runtime.application.Load() {
		return nil, fmt.Errorf("application is not configured")
	}
	return h.runtime.server.ApplicationHub(request)
}
