// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package main

import (
	"testing"

	"github.com/NeoTecDigital/LumberJack/embedded"
	"github.com/NeoTecDigital/LumberJack/types"
)

// The `auth` JSON reaches the engine through decodeApplicationConfiguration: the engine reads its
// three parts, and every other part goes to the extension that declared it. The generic archive
// declares none, so an `activation` or `admission` part fails the configure (LJ_INVALID) rather
// than being ignored.
func TestApplicationConfigurationRefusesPartsNoExtensionDeclared(t *testing.T) {
	base := `"username":"operator","password":"a-long-enough-password","secret":"a-long-enough-signing-key-0123456789"`
	for name, body := range map[string]struct {
		json  string
		fails bool
	}{
		"engine parts only": {`{` + base + `}`, false},
		"admission":         {`{` + base + `,"admission":{"keyId":"k"}}`, true},
		"activation null":   {`{` + base + `,"activation":null}`, true},
	} {
		config, err := decodeApplicationConfiguration([]byte(body.json))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		handle, err := embedded.Open(embedded.Config{Process: types.ProcessInfo{Name: "ffi_configure", DatabasePath: t.TempDir()}}, "system")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := configureApplication(handle, config); (err != nil) != body.fails {
			t.Errorf("%s: configure answered %v", name, err)
		}
		if err := handle.Close(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if _, err := decodeApplicationConfiguration([]byte(`{"username":7}`)); err == nil {
		t.Fatal("a mistyped engine part was accepted")
	}
}
