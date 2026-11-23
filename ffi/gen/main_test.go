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
	for _, item := range []struct {
		file, include string
		records       bool
	}{
		{"../base_exports.go", "", false}, {"../testdata/example/base_exports.go", "/../..", false},
		{"../records.go", "", true}, {"../testdata/example/record_exports.go", "/../..", true},
	} {
		file, include := item.file, item.include
		var want bytes.Buffer
		if err := writeFamily(&want, "main", include, item.records); err != nil {
			t.Fatal(err)
		}
		held, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(held, want.Bytes()) {
			t.Errorf("%s is stale (records=%v, include=%q)", file, item.records, include)
		}
	}
}

// The generator writes the twenty base exports and nothing else.
func TestGeneratorWritesTheTwentyBaseExports(t *testing.T) {
	var out bytes.Buffer
	if err := Write(&out, "main", ""); err != nil {
		t.Fatal(err)
	}
	if count := bytes.Count(out.Bytes(), []byte("//export ic_lj_")); count != 20 || len(baseExports) != 20 {
		t.Fatalf("%d exports generated, %d declared", count, len(baseExports))
	}
}
