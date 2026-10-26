// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package embedded

import (
	"fmt"
	engine "github.com/NeoTecDigital/LumberJack/internal"
	"github.com/NeoTecDigital/LumberJack/products/manifest"
	"github.com/NeoTecDigital/LumberJack/products/pngstore"
)

func manifestDomainRegistration(config DomainConfig) (map[string]engine.DomainProduct, engine.DomainPolicy, error) {
	scopes := append([]engine.DomainOwnedScope(nil), config.Scopes...)
	if profile := config.ProvisioningProfile; profile != nil {
		scopes = append(scopes, engine.DomainOwnedScope{Binding: engine.DomainNativeBinding{ProductID: "manifest"}, Bounds: profile.Bounds, Layout: profile.Layout})
	}
	for _, owned := range scopes {
		if owned.Binding.ProductID != "manifest" {
			return nil, nil, fmt.Errorf("compiled product adapter absent")
		}
		if err := manifest.ValidateLayout(owned, config.ACLMetadataKey); err != nil {
			return nil, nil, err
		}
		if err := validateOptionalStore(owned, config.ACLMetadataKey); err != nil {
			return nil, nil, err
		}
	}
	policy, err := engine.NewDomainOwnerPolicy(config.ACLMetadataKey)
	return map[string]engine.DomainProduct{"manifest": manifest.New()}, policy, err
}
func validateOptionalStore(owned engine.DomainOwnedScope, key string) error {
	if owned.Layout.Kinds["png_record"] == "" {
		return nil
	}
	return pngstore.ValidateLayout(owned, key)
}
