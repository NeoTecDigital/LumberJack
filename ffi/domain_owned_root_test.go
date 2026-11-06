// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package main

import (
	"os"
	"strings"
	"testing"
)

func TestOwnedRootFFIClosedInvalidInputsAndDeclaredExport(t *testing.T) {
	if ic_lj_domain_provision_root(0, nil, 0, nil, nil) != statusInvalid {
		t.Fatal("invalid owned-root ABI call accepted")
	}
	header, err := os.ReadFile("lumberjack.h")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(header), "ic_lj_domain_provision_root(") {
		t.Fatal("matching declared export missing")
	}
}
