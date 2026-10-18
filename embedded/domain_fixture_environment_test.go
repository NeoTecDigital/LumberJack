// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package embedded

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDomainFixtureModuleCacheUsesExplicitConfiguration(t *testing.T) {
	want := filepath.Join(t.TempDir(), "configured-cache")
	t.Setenv("GOMODCACHE", want)
	t.Setenv("GOPATH", filepath.Join(t.TempDir(), "ignored-gopath"))
	if actual := domainFixtureModuleCache(t); actual != want {
		t.Fatalf("module cache = %q, want explicit configuration", actual)
	}
}

func TestDomainFixtureModuleCacheUsesFirstGoPath(t *testing.T) {
	first, second := t.TempDir(), t.TempDir()
	t.Setenv("GOMODCACHE", "")
	t.Setenv("GOPATH", first+string(os.PathListSeparator)+second)
	if actual := domainFixtureModuleCache(t); actual != filepath.Join(first, "pkg", "mod") {
		t.Fatalf("module cache = %q, want first GOPATH entry", actual)
	}
}

func TestDomainFixtureModuleCacheDerivesDefaultFromHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("GOMODCACHE", "")
	t.Setenv("GOPATH", "")
	t.Setenv("HOME", home)
	if actual := domainFixtureModuleCache(t); actual != filepath.Join(home, "go", "pkg", "mod") {
		t.Fatalf("module cache = %q, want portable home-derived default", actual)
	}
}
