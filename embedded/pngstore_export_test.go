// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package embedded

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var pngExportPath = flag.String("png-fixture-export", "", "Explicit NEW synthetic /tmp owner spec for actual FFI tests only")
var pngVerifierURL = flag.String("png-fixture-verifier", "", "Explicit synthetic loopback verifier URL, never a production profile")

func TestPNGExportExplicitFFIOwnerSpec(t *testing.T) {
	if *pngExportPath == "" {
		t.Skip("explicit synthetic FFI export not requested")
	}
	absolute, err := filepath.Abs(*pngExportPath)
	if err != nil || absolute != *pngExportPath || !strings.HasPrefix(absolute, "/tmp/") {
		t.Fatal("explicit real /tmp owner export required")
	}
	if _, err = os.Lstat(absolute); !os.IsNotExist(err) {
		t.Fatal("refusing existing owner spec")
	}
	config := pngFixtureConfig()
	config.Trust.VerifierEndpoint = *pngVerifierURL
	spec := pngFixtureOwnerSpec(config, filepath.Join(filepath.Dir(absolute), "native"))
	if err = os.WriteFile(absolute, domainFixtureJSON(t, spec), 0600); err != nil {
		t.Fatal(err)
	}
}
