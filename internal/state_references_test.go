// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/NeoTecDigital/LumberJack/internal/compat"
)

const bannerBeforeReferences = "LUMBERJACK-STATE-2\nthis file is a flat node table\n"

// What the build before references does with a state file, spelled out because that binary is not
// importable. It knows one banner, and anything else it reads as the older nested shape.
func readBeforeReferences(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !bytes.HasPrefix(raw, []byte(bannerBeforeReferences)) {
		return readTheOldWay(path)
	}
	raw = raw[len(bannerBeforeReferences):]
	compressed, err := gzip.NewReader(bytes.NewReader(raw[sha256.Size:]))
	if err != nil {
		return err
	}
	data, err := io.ReadAll(compressed)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	if !compareHashes(raw[:sha256.Size], sum[:]) {
		return fmt.Errorf("data hash mismatch, file may be corrupted")
	}
	_, err = decodeState(data)
	return err
}

// aclReference is a stored ACL reference as the domain wrote one: its contract revision sorts first.
func aclReference(rootID, kind string) map[string]interface{} {
	return map[string]interface{}{"contractRevision": compat.ACLReferenceRevision, "rootId": rootID, "kind": kind}
}

func stateBannerOf(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < len(stateMagic) {
		t.Fatal("state file shorter than its banner")
	}
	return string(raw[:len(stateMagic)])
}

// referencesFixture is a stock server whose forest holds a record, and a way to put a reference on
// it.
func referencesFixture(t *testing.T) (*Server, func()) {
	t.Helper()
	server, _ := newStockServer(t)
	if err := server.changeForest(addRootChild(server, "copy")); err != nil {
		t.Fatal(err)
	}
	return server, func() {
		if err := server.changeForest(func() error {
			for _, child := range server.forest.Children {
				child.Metadata = map[string]interface{}{"acl": aclReference(child.ID, "copy")}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}

// The build before references opens a forest with none, and refuses one holding a reference at the
// reader, before any data is read; this build reads both.
func TestStateFileRefusesTheOlderBuildOnlyOnceAReferenceExists(t *testing.T) {
	server, addReference := referencesFixture(t)
	if banner := stateBannerOf(t, server.statePath()); banner != stateMagic {
		t.Fatalf("a forest with no reference has banner %q", banner)
	}
	if err := readBeforeReferences(server.statePath()); err != nil {
		t.Fatalf("the older build must still open this forest: %v", err)
	}
	addReference()
	if banner := stateBannerOf(t, server.statePath()); banner != stateMagicReferences {
		t.Fatalf("a forest holding a reference has banner %q", banner)
	}
	if err := readBeforeReferences(server.statePath()); err == nil || !strings.Contains(err.Error(), "gzip: invalid header") {
		t.Fatalf("the older build must refuse this forest at the reader: %v", err)
	}
	reloaded := reloadServer(t, server.config.Process.DatabasePath)
	if banner := stateBannerOf(t, reloaded.statePath()); banner != stateMagicReferences {
		t.Fatalf("reopened by this build, the banner is %q", banner)
	}
}

func TestStateBannersKeepTheRefusalTheyRelyOn(t *testing.T) {
	if stateMagic != bannerBeforeReferences {
		t.Fatal("the banner an older build accepts must not change")
	}
	if stateMagicReferences == stateMagic || len(stateMagicReferences) != len(stateMagic) {
		t.Fatal("the two banners must differ and read the same number of bytes")
	}
	if len(stateMagicReferences) <= sha256.Size || stateMagicReferences[sha256.Size] == 0x1f {
		t.Fatal("an older build must reach a non-gzip byte inside this banner")
	}
}

func TestStateReferenceMarkMatchesAReferenceAndNotItsText(t *testing.T) {
	reference, err := json.Marshal(map[string]interface{}{"metadata": map[string]interface{}{"acl": aclReference("root", "kind")}})
	if err != nil {
		t.Fatal(err)
	}
	if !stateHoldsACLReferences(reference) {
		t.Fatalf("a stored reference went unnoticed: %s", reference)
	}
	text, err := json.Marshal(map[string]interface{}{"note": string(stateACLReferenceMark), "acl": map[string]interface{}{"contractRevision": "lj.domain.acl/1"}})
	if err != nil {
		t.Fatal(err)
	}
	if stateHoldsACLReferences(text) {
		t.Fatalf("row text and a full list must not select the new banner: %s", text)
	}
}

func encryptedEnvelopeVersion(t *testing.T, path string) int {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(raw, []byte(encryptedStateMagic)) {
		t.Fatal("expected an encrypted state file")
	}
	var envelope encryptedStateEnvelope
	if err = json.Unmarshal(raw[len(encryptedStateMagic):], &envelope); err != nil {
		t.Fatal(err)
	}
	return envelope.Version
}

// The build before references accepts envelope version 3 and refuses every other.
func TestEncryptedStateRefusesTheOlderBuildOnlyOnceAReferenceExists(t *testing.T) {
	t.Setenv("CORRESPONDER_STORAGE_MODE", "local-test")
	t.Setenv("CORRESPONDER_STORAGE_LOCAL_KEY_FILE", storageTestKey(t))
	server, addReference := referencesFixture(t)
	if version := encryptedEnvelopeVersion(t, server.statePath()); version != 3 {
		t.Fatalf("a forest with no reference has envelope version %d", version)
	}
	addReference()
	if version := encryptedEnvelopeVersion(t, server.statePath()); version != 4 {
		t.Fatalf("a forest holding a reference has envelope version %d", version)
	}
	if _, err := reloadServer(t, server.config.Process.DatabasePath).getNodeFromPath("copy"); err != nil {
		t.Fatalf("this build must read its own envelope: %v", err)
	}
}
