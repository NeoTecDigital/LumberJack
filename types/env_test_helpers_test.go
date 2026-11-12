// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package types

import (
	"os"
	"testing"
)

// unsetForTest removes a variable for the test and puts back what it was after it.
func unsetForTest(t *testing.T, name string) {
	t.Helper()
	previous, was := os.LookupEnv(name)
	if err := os.Unsetenv(name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if was {
			_ = os.Setenv(name, previous)
		} else {
			_ = os.Unsetenv(name)
		}
	})
}
