// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package embedded

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	engine "github.com/NeoTecDigital/LumberJack/internal"
	"os"
	"testing"
)

var pngProfileArtifact = flag.String("png-profile-artifact", "", "Explicit protected synthetic profile/catalog; no authority inferred")

func TestPNGProtectedExportConfiguresActualEmptyRuntime(t *testing.T) {
	if *pngProfileArtifact == "" {
		t.Skip("explicit protected artifact not supplied")
	}
	config := pngProtectedConfig(t, *pngProfileArtifact)
	handle, err := OpenPath("fixture", t.TempDir(), "fixture", "fixture-private-owner")
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	if _, err = handle.ConfigureDomain(domainFixtureJSON(t, config)); err != nil {
		t.Fatal("actual protected empty-runtime configuration denied", err)
	}
	t.Log("actual empty runtime accepts complete protected profile/catalog/digest; NO enrollment/proof acceptance claimed by configure")
}

func pngProtectedConfig(t *testing.T, path string) DomainConfig {
	t.Helper()
	raw, err := os.ReadFile(path)
	var artifact map[string]json.RawMessage
	if err != nil || engine.DecodeDomainJSON(raw, &artifact) != nil {
		t.Fatal("protected artifact invalid", err)
	}
	var profile engine.DomainProvisioningProfile
	if err = engine.DecodeDomainJSON(artifact["provisioningProfile"], &profile); err != nil {
		t.Fatal(err)
	}
	var encoded string
	if err = engine.DecodeDomainJSON(artifact["roleCatalog"], &encoded); err != nil {
		t.Fatal(err)
	}
	catalog, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	config := domainFixtureConfig()
	config.Scopes, config.ProvisioningProfile, config.RoleCatalog = nil, &profile, catalog
	config.MaxFields, config.MaxRequestBytes, config.MaxResponseBytes = 512, 1000000, 1000000
	config.Trust.MaxBodyBytes, config.Trust.MaxResponseBytes = 1000000, 1000000
	config.Trust.VerifierEndpoint = "http://127.0.0.1:1/internal/explicit-unavailable-fixture"
	return config
}
