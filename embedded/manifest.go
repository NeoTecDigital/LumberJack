// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package embedded

import (
	"fmt"
	engine "github.com/NeoTecDigital/LumberJack/internal"
	"github.com/NeoTecDigital/LumberJack/products/manifest"
)

func manifestDomainRegistration(config DomainConfig) (map[string]engine.DomainProduct, engine.DomainPolicy, error) {
	for _, owned := range config.Scopes {
		if owned.Binding.ProductID != "manifest" {
			return nil, nil, fmt.Errorf("compiled product adapter absent")
		}
		if err := manifest.ValidateLayout(owned, config.ACLMetadataKey); err != nil {
			return nil, nil, err
		}
	}
	policy, err := engine.NewDomainOwnerPolicy(config.ACLMetadataKey)
	return map[string]engine.DomainProduct{"manifest": manifest.New()}, policy, err
}
