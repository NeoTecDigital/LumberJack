// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import "fmt"

// EmptyHost is explicit installation state, never a synthetic account or grant.
// Enrollment and all scoped operations still require actual protected bindings.
func validateDomainRootMode(config DomainConfig) error {
	if config.EmptyHost {
		if len(config.Scopes) != 0 || config.ProvisioningProfile != nil || len(config.RoleCatalog) != 0 {
			return fmt.Errorf("empty native host cannot carry accounts, provisioning or role grants")
		}
		return nil
	}
	if (len(config.Scopes) == 0 && config.ProvisioningProfile == nil) || len(config.Scopes) > config.MaxResources {
		return fmt.Errorf("explicit bounded native root bindings required")
	}
	return nil
}
