// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package embedded

import (
	"flag"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	engine "github.com/NeoTecDigital/LumberJack/internal"
)

const coownerFFIAccount = "00000000-0000-0000-0000-00000000c004"

var coownerFFIExport = flag.String("coowner-fixture-export", "", "NEW private /tmp/Mindfull owner.json for synthetic paired co-owner FFI tests only")
var coownerFFIVerifier = flag.String("coowner-fixture-verifier", "", "Exact synthetic loopback Activity native verifier URL")
var coownerFFIAccountFlag = flag.String("coowner-fixture-account", "", "Only the explicitly approved synthetic co-owner account UUID")

// Only the legacy bootstrap is seeded. Python must use the real EnrollmentBroker
// to provision the UUID account and obtain its actual founder/root/receipt.
func TestCoownerExportExplicitFFIOwnerSpec(t *testing.T) {
	if *coownerFFIExport == "" {
		t.Skip("explicit synthetic co-owner FFI export not requested")
	}
	if *coownerFFIAccountFlag != coownerFFIAccount {
		t.Fatal("only the fixed synthetic co-owner UUID is permitted")
	}
	directory, err := coownerFFIPaths(*coownerFFIExport, *pngProfileArtifact)
	if err != nil {
		t.Fatal(err)
	}
	if err = coownerFFICallback(*coownerFFIVerifier); err != nil {
		t.Fatal(err)
	}
	config := coownerFFIConfig(t)
	spec := pngFixtureOwnerSpec(config, directory)
	if err = coownerFFIWrite(*coownerFFIExport, domainFixtureJSON(t, spec)); err != nil {
		t.Fatal(err)
	}
	t.Log("synthetic bootstrap/config exported; UUID account requires actual Python enrollment; no receipt or lease generated")
}

func coownerFFIPaths(output, artifact string) (string, error) {
	parent := filepath.Dir(output)
	if filepath.Clean(output) != output || !filepath.IsAbs(output) || filepath.Base(output) != "owner.json" || !strings.HasPrefix(parent, "/tmp/Mindfull/") {
		return "", fmt.Errorf("explicit private /tmp/Mindfull operation owner.json required")
	}
	real, err := filepath.EvalSymlinks(parent)
	if err != nil || real != parent {
		return "", fmt.Errorf("fixture operation directory cannot contain symlinks")
	}
	if err = coownerFFIPrivate(parent, true); err != nil {
		return "", err
	}
	if !filepath.IsAbs(artifact) || filepath.Clean(artifact) != artifact || filepath.Dir(artifact) != parent || artifact == output {
		return "", fmt.Errorf("explicit protected synthetic artifact must share the private operation directory")
	}
	if err = coownerFFIPrivate(artifact, false); err != nil {
		return "", err
	}
	directory := filepath.Join(parent, "native")
	for _, path := range []string{output, directory} {
		if _, err = os.Lstat(path); !os.IsNotExist(err) {
			return "", fmt.Errorf("fixture output/native target must be NEW")
		}
	}
	return directory, nil
}

func coownerFFIPrivate(path string, directory bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("fixture path must be owned by this process user, without symlinks")
	}
	if directory && (!info.IsDir() || info.Mode().Perm() != 0700) {
		return fmt.Errorf("private 0700 fixture operation directory required")
	}
	if !directory && (!info.Mode().IsRegular() || info.Mode().Perm() != 0600 || stat.Nlink != 1 || info.Size() <= 0 || info.Size() > 1000000) {
		return fmt.Errorf("bounded private single-link 0600 synthetic profile artifact required")
	}
	return nil
}

func coownerFFICallback(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.Path != "/internal/activity-native/check" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.Opaque != "" {
		return fmt.Errorf("exact synthetic Activity callback URL required")
	}
	address, err := netip.ParseAddr(parsed.Hostname())
	port, portErr := strconv.Atoi(parsed.Port())
	if err != nil || address.String() != "127.0.0.1" || !address.IsLoopback() || portErr != nil || port < 1 || port > 65535 || parsed.Host != "127.0.0.1:"+strconv.Itoa(port) {
		return fmt.Errorf("literal IPv4 loopback and explicit canonical port required")
	}
	return nil
}

func coownerFFIConfig(t *testing.T) DomainConfig {
	t.Helper()
	config := pngProtectedConfig(t, *pngProfileArtifact)
	profile := config.ProvisioningProfile
	if profile == nil || profile.ProfileRef.ProfileID != "activity-manifest-png" || profile.ProfileRef.ProfileRevision != "0.3" || !config.Trust.SyntheticLoopbackOnly || config.Trust.LocalHumanPreview {
		t.Fatal("exact synthetic protected profile and loopback-only trust required")
	}
	digest, err := engine.DomainProvisioningProfileDigest(*profile)
	if err != nil || digest != profile.ProfileRef.ProfileDigest {
		t.Fatal("protected profile digest mismatch", err)
	}
	coownerFFICatalog(t, config.RoleCatalog)
	bootstrap := pngFixtureConfig()
	config.Scopes, config.IntegrationIssuer = bootstrap.Scopes, bootstrap.IntegrationIssuer
	if len(config.Scopes) != 1 || config.Scopes[0].Binding.AccountID != "fixture-account" {
		t.Fatal("exact legacy bootstrap scope required; UUID root must not be seeded")
	}
	config.Trust.VerifierEndpoint = *coownerFFIVerifier
	config.MaxResources, config.MaxLeases = 200, 200
	return config
}

func coownerFFICatalog(t *testing.T, raw []byte) {
	t.Helper()
	var catalog struct {
		ID      string        `json:"catalogId"`
		Version string        `json:"catalogVersion"`
		Roles   []interface{} `json:"roles"`
	}
	if engine.DecodeDomainJSON(raw, &catalog) != nil || catalog.ID != "activity-manifest-png-roles" || catalog.Version != "0.1" || catalog.Roles == nil || len(catalog.Roles) != 0 {
		t.Fatal("exact empty synthetic role catalog required")
	}
}

func coownerFFIWrite(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err = file.Write(data); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	return file.Close()
}
