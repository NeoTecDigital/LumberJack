// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package embedded

import (
	"context"
	engine "github.com/NeoTecDigital/LumberJack/internal"
)

// DomainEnrollJSON retains exactly the same Runtime until actual control completion.
func (handle *Handle) DomainEnrollJSON(body []byte) ([]byte, error) {
	runtime, err := handle.domainPin()
	if err != nil {
		return nil, err
	}
	begin, err := runtime.server.DomainEnrollJSON(context.Background(), body)
	if err != nil {
		_ = runtime.close()
		return nil, err
	}
	if err = retainDomainLease(runtime, begin); err != nil {
		_ = runtime.close()
		return nil, err
	}
	return engine.CanonicalDomainJSON(begin)
}
