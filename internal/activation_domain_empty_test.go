// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import "testing"

func TestExplicitEmptyHostHasNoImplicitProvisioning(t *testing.T) {
	config := DomainConfig{EmptyHost: true, MaxResources: 8}
	if err := validateDomainRootMode(config); err != nil {
		t.Fatal(err)
	}
	config.EmptyHost = false
	if err := validateDomainRootMode(config); err == nil {
		t.Fatal("legacy missing root configuration must still fail")
	}
}

func TestExplicitEmptyHostRejectsAuthorityContent(t *testing.T) {
	cases := []DomainConfig{
		{EmptyHost: true, Scopes: []DomainOwnedScope{{}}},
		{EmptyHost: true, ProvisioningProfile: &DomainProvisioningProfile{}},
		{EmptyHost: true, RoleCatalog: []byte("{}")},
	}
	for _, config := range cases {
		if err := validateDomainRootMode(config); err == nil {
			t.Fatal("empty host accepted authority content")
		}
	}
}
