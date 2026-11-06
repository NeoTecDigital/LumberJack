// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package main

import (
	"os"
	"strings"
	"testing"
)

func TestPersonalSourceFFIClosedInvalidInputsAndMatchingFree(t *testing.T) {
	if ic_lj_personal_source_control(nil, 0, nil, nil) != statusInvalid {
		t.Fatal("invalid source ABI accepted")
	}
	ic_lj_personal_source_free(nil)
	header, err := os.ReadFile("lumberjack.h")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"configure", "call", "control", "free"} {
		if !strings.Contains(string(header), "ic_lj_personal_source_"+name+"(") {
			t.Fatal("matching declared export missing", name)
		}
	}
}
