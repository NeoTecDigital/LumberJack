// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package embedded

import engine "github.com/NeoTecDigital/LumberJack/internal"

// ProvisionOwnedRoot is protected host setup on an open, not yet domain-configured handle.
func (handle *Handle) ProvisionOwnedRoot(body []byte) ([]byte, error) {
	var spec engine.DomainOwnedRootSpec
	if err := engine.DecodeDomainJSON(body, &spec); err != nil {
		return nil, err
	}
	runtime, err := handle.domainPin()
	if err != nil {
		return nil, err
	}
	defer runtime.close()
	result, err := runtime.server.ProvisionOwnedRoot(spec)
	if err != nil {
		return nil, err
	}
	return engine.CanonicalDomainJSON(result)
}
