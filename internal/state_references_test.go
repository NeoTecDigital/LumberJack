// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
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

func aclStateBanner(t *testing.T, f *enrollmentFixture) string {
	t.Helper()
	raw, err := os.ReadFile(f.server.statePath())
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < len(stateMagic) {
		t.Fatal("state file shorter than its banner")
	}
	return string(raw[:len(stateMagic)])
}

func aclAssertOpenable(t *testing.T, f *enrollmentFixture, step string) {
	t.Helper()
	if banner := aclStateBanner(t, f); banner != stateMagic {
		t.Fatalf("%s: a forest with no reference has banner %q", step, banner)
	}
	if err := readBeforeReferences(f.server.statePath()); err != nil {
		t.Fatalf("%s: the older build must still open this forest: %v", step, err)
	}
}

func aclAssertRefused(t *testing.T, f *enrollmentFixture, step string) {
	t.Helper()
	if banner := aclStateBanner(t, f); banner != stateMagicReferences {
		t.Fatalf("%s: a forest holding a reference has banner %q", step, banner)
	}
	if err := readBeforeReferences(f.server.statePath()); err == nil || !strings.Contains(err.Error(), "gzip: invalid header") {
		t.Fatalf("%s: the older build must refuse this forest at the reader: %v", step, err)
	}
}

func TestStateFileRefusesTheOlderBuildOnlyOnceAReferenceExists(t *testing.T) {
	f := newEnrollmentFixture(t)
	rootID := aclFixtureProvision(t, f, "unit-banner")
	aclAssertOpenable(t, f, "provisioned")
	aclSeedRecords(t, f, rootID, "copy", 2, aclFixtureCopy(t, f, rootID))
	aclFixtureRestart(t, f)
	aclAssertOpenable(t, f, "copies, reopened")
	target := "unit-banner-member"
	aclFixtureGrant(t, f, EnrollmentReadGrant, "unit-banner", rootID, target, "grant")
	aclAssertOpenable(t, f, "copies, after a paired grant")
	aclSeedRecords(t, f, rootID, "follower", 1, aclFixtureFollower(rootID))
	if err := f.server.persistState(f.server.statePath()); err != nil {
		t.Fatal(err)
	}
	aclAssertRefused(t, f, "first reference")
	aclFixtureRestart(t, f)
	aclAssertRefused(t, f, "reopened by this build")
	aclFixtureGrant(t, f, EnrollmentReadRevoke, "unit-banner", rootID, target, "revoke")
	aclAssertRefused(t, f, "after a paired revoke")
	if err := aclFixtureDecision(t, f, "unit-banner", target, "copy-000"); err == nil {
		t.Fatal("revoke through the new banner left the member on a stored copy")
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
	reference, err := json.Marshal(map[string]interface{}{"metadata": map[string]interface{}{"acl": domainACLReferenceValue("root", "kind")}})
	if err != nil {
		t.Fatal(err)
	}
	if !stateHoldsACLReferences(reference) {
		t.Fatalf("a stored reference went unnoticed: %s", reference)
	}
	text, err := json.Marshal(map[string]interface{}{"note": string(stateACLReferenceMark), "acl": map[string]interface{}{"contractRevision": domainACLRevision}})
	if err != nil {
		t.Fatal(err)
	}
	if stateHoldsACLReferences(text) {
		t.Fatalf("row text and a full list must not select the new banner: %s", text)
	}
}

func aclEnvelopeVersion(t *testing.T, f *enrollmentFixture) int {
	t.Helper()
	raw, err := os.ReadFile(f.server.statePath())
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
	f := newEnrollmentFixture(t)
	rootID := aclFixtureProvision(t, f, "unit-envelope")
	aclSeedRecords(t, f, rootID, "copy", 2, aclFixtureCopy(t, f, rootID))
	aclFixtureRestart(t, f)
	if version := aclEnvelopeVersion(t, f); version != 3 {
		t.Fatalf("a forest with no reference has envelope version %d", version)
	}
	aclSeedRecords(t, f, rootID, "follower", 1, aclFixtureFollower(rootID))
	aclFixtureRestart(t, f)
	if version := aclEnvelopeVersion(t, f); version != 4 {
		t.Fatalf("a forest holding a reference has envelope version %d", version)
	}
	if err := aclFixtureDecision(t, f, "unit-envelope", aclFixtureOwner, "follower-000"); err != nil {
		t.Fatal("this build must read its own envelope", err)
	}
}

// Recovery reads the file back to witness a lost acknowledgement, so it must accept both banners.
func TestEnrollmentWitnessAcceptsTheReferencesBanner(t *testing.T) {
	f := newEnrollmentFixture(t)
	rootID := aclFixtureProvision(t, f, "unit-witness")
	aclSeedRecords(t, f, rootID, "follower", 2, aclFixtureFollower(rootID))
	target := "unit-witness-member"
	input := f.input(EnrollmentReadGrant, "unit-witness", "unit-grant", "unit-proof-grant", enrollmentCurrentRevision(t, f, rootID), &target)
	actual := f.server.stateWriter.write
	f.server.stateWriter.write = func(snapshot stateSnapshot) error {
		if err := actual(snapshot); err != nil {
			return err
		}
		return errors.New("unit lost ACK after actual publication")
	}
	begin := f.enroll(t, input)
	if received := f.received(t, begin); received.Pair != nil {
		t.Fatal("a lost acknowledgement became a successful disclosure")
	}
	aclAssertRefused(t, f, "published before the lost acknowledgement")
	f.server.stateWriter.write = actual
	if result := enrollmentDiscard(t, f, begin); !result.Completed || f.server.sourceFence().unknown {
		t.Fatal("the witness did not accept the durable pair under the new banner")
	}
}
