// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package main

import (
	"bytes"
	"os"
	"testing"
)

// The checked-in wrappers are what the generator writes now: the generic archive's, and the example
// product archive's.
func TestGeneratedWrappersAreCurrent(t *testing.T) {
	for file, include := range map[string]string{"../base_exports.go": "", "../testdata/example/base_exports.go": "/../.."} {
		var want bytes.Buffer
		if err := Write(&want, "main", include); err != nil {
			t.Fatal(err)
		}
		held, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(held, want.Bytes()) {
			t.Errorf("%s is stale: run go run ./ffi/gen -include %q > %s", file, include, file)
		}
	}
}

// The generator writes the nineteen base exports and nothing else.
func TestGeneratorWritesTheNineteenBaseExports(t *testing.T) {
	var out bytes.Buffer
	if err := Write(&out, "main", ""); err != nil {
		t.Fatal(err)
	}
	if count := bytes.Count(out.Bytes(), []byte("//export ic_lj_")); count != 19 || len(baseExports) != 19 {
		t.Fatalf("%d exports generated, %d declared", count, len(baseExports))
	}
}
