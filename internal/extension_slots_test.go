// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NeoTecDigital/LumberJack/core"
	"github.com/NeoTecDigital/LumberJack/extension"
	"github.com/NeoTecDigital/LumberJack/internal/slots"
)

// Slots (docs/extension-api.md §4.5, §7.8.1–4): keys nobody claims round-trip as their bytes, a
// claimed key decodes once and encodes only when set, keys are disjoint at Open, and the outbox
// carries its own.

func TestUnclaimedKeyRoundTripsVerbatim(t *testing.T) {
	raw := []byte(`{"from_a_product":{"z":1.50,"a":[3,2,{"k":12345678901234567890}]},"id":"n","type":0,"name":"n","parents":null,"events":null,"planned_events":null,"users":null,"entries":null,"zz_later":"kept","children":["c"]}`)
	node, children, err := core.DecodeRecord(raw)
	if err != nil {
		t.Fatal(err)
	}
	held, _ := node.Slots(slots.Token{}).Get("from_a_product")
	if held == nil || string(held.Raw) != `{"z":1.50,"a":[3,2,{"k":12345678901234567890}]}` {
		t.Fatalf("the unclaimed key was not kept as its bytes: %v", held)
	}
	node.Name = "renamed"
	again, err := core.EncodeRecord(node, children)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"id":"n","type":0,"name":"renamed","parents":null,"events":null,"planned_events":null,"users":null,"entries":null,"created_at":"0001-01-01T00:00:00Z","modified_at":"0001-01-01T00:00:00Z","from_a_product":{"z":1.50,"a":[3,2,{"k":12345678901234567890}]},"zz_later":"kept","children":["c"]}`
	if string(again) != want {
		t.Fatalf("re-encoded as\n%s\nwant\n%s", again, want)
	}
}

// countingCodec decodes and encodes a JSON object, counting both.
type countingCodec struct{ decodes, encodes int }

func (c *countingCodec) Decode(raw json.RawMessage) (any, error) {
	c.decodes++
	var value map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	return value, decoder.Decode(&value)
}

func (c *countingCodec) Encode(v any) (json.RawMessage, error) {
	c.encodes++
	return json.Marshal(v)
}

func slotFixture(t *testing.T, codec extension.Codec, plant json.RawMessage) (*Server, extension.Host, string) {
	t.Helper()
	server, dir := newStockServer(t)
	if plant != nil {
		if err := plantAndPersist(server, func() error {
			server.forest.Slots(slots.Token{}).SetRaw("ledger", plant)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	var host extension.Host
	ext := testExtension{spec: extension.Spec{Name: "ledger", Slot: extension.SlotSpec{RootKeys: []extension.SlotKey{{Name: "ledger", Codec: codec}}}},
		attach: func(h extension.Host) (extension.Instance, error) { host = h; return testInstance{}, nil }}
	if err := server.AttachExtensions([]extension.Extension{ext}); err != nil {
		t.Fatal(err)
	}
	return server, host, dir
}

func TestClaimedKeyDecodesLazilyAndEncodesOnlyWhenDirty(t *testing.T) {
	codec := &countingCodec{}
	server, host, dir := slotFixture(t, codec, json.RawMessage(`{"count":1.50}`))
	root := server.forest.ID
	read := func() any {
		var value any
		_ = host.Read(func(tx extension.ReadTx) error { value, _ = tx.Slot(root, "ledger"); return nil })
		return value
	}
	if codec.decodes != 0 {
		t.Fatal("the key was decoded before anyone read it")
	}
	first, second := read(), read()
	if codec.decodes != 1 || first.(map[string]any)["count"] != json.Number("1.50") || second == nil {
		t.Fatalf("decodes %d, value %v", codec.decodes, first)
	}
	if err := server.changeForest(addRootChild(server, "unrelated")); err != nil {
		t.Fatal(err)
	}
	if codec.encodes != 0 {
		t.Fatal("a key nobody set was encoded")
	}
	if _, err := host.Change(context.Background(), extension.WriteOp{Key: "set"}, func(tx extension.Tx) error {
		return tx.SetSlot(root, "ledger", map[string]any{"count": 2})
	}); err != nil {
		t.Fatal(err)
	}
	if codec.encodes != 1 {
		t.Fatalf("a set key was encoded %d times", codec.encodes)
	}
	reloaded := reloadServer(t, dir)
	held, _ := reloaded.forest.Slots(slots.Token{}).Get("ledger")
	if held == nil || string(held.Raw) != `{"count":2}` {
		t.Fatalf("the set key did not land with its change: %v", held)
	}
}

// A key is the declaring extension's: another extension cannot read or set it, and a set of an
// undeclared key is refused.
func TestSlotsAreTheDeclaringExtensionsOnly(t *testing.T) {
	server, host, _ := slotFixture(t, nil, json.RawMessage(`{"secret":true}`))
	root := server.forest.ID
	stranger := forestTx{server: server, owner: "stranger"}
	if _, held := stranger.Slot(root, "ledger"); held {
		t.Fatal("an undeclared reader read the key")
	}
	if _, err := host.Change(context.Background(), extension.WriteOp{Key: "other"}, func(tx extension.Tx) error {
		return tx.SetSlot(root, "not-mine", json.RawMessage(`1`))
	}); err == nil {
		t.Fatal("an undeclared key was set")
	}
	var raw any
	_ = host.Read(func(tx extension.ReadTx) error { raw, _ = tx.Slot(root, "ledger"); return nil })
	if string(raw.(json.RawMessage)) != `{"secret":true}` {
		t.Fatalf("a codec-less key read as %v", raw)
	}
}

func TestSlotKeyCollisionRefusedAtOpen(t *testing.T) {
	claim := func(name string) extension.Extension {
		return testExtension{spec: extension.Spec{Name: "claims-" + strings.ReplaceAll(name, "_", "-"), Slot: extension.SlotSpec{RootKeys: []extension.SlotKey{{Name: name}}}}}
	}
	if _, err := validateExtensions([]extension.Extension{claim("metadata")}, false); !errors.Is(err, ErrExtensionSet) {
		t.Fatalf("a typed field was claimable: %v", err)
	}
	if _, err := validateExtensions([]extension.Extension{claim("account_security")}, false); err != nil {
		t.Fatalf("a key the engine no longer types was not claimable: %v", err)
	}
	if _, err := validateExtensions([]extension.Extension{claim("ledger"), testExtension{spec: extension.Spec{Name: "again", Slot: extension.SlotSpec{RootKeys: []extension.SlotKey{{Name: "ledger"}}}}}}, false); !errors.Is(err, ErrExtensionSet) {
		t.Fatalf("two extensions claimed one key: %v", err)
	}
}

// The outbox's own keys survive a change to the outbox, and an extension that declares one reads it
// through OutboxSlots.
func TestOutboxSlotKeyPreserved(t *testing.T) {
	server := compatOpenFixture(t, "plain-state2-all-fields.ljstate")
	before, _ := server.forest.Correspondence.Slots(slots.Token{}).Get("feed")
	if before == nil {
		t.Fatal("the fixture's outbox feed is missing")
	}
	feed := append(json.RawMessage(nil), before.Raw...)
	var host extension.Host
	ext := testExtension{spec: extension.Spec{Name: "workspace-like", Slot: extension.SlotSpec{OutboxKeys: []extension.SlotKey{{Name: "feed"}}}},
		attach: func(h extension.Host) (extension.Instance, error) { host = h; return testInstance{}, nil }}
	if err := server.AttachExtensions([]extension.Extension{ext}); err != nil {
		t.Fatal(err)
	}
	if err := server.changeForest(func() error {
		return server.enqueueOutboxLocked(core.OutboxChange{ID: "x", PinID: "p", Path: "p"})
	}); err != nil {
		t.Fatal(err)
	}
	document, err := encodeState(server.forest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(document, append([]byte(`"correspondence":{"feed":`), feed...)) {
		t.Fatal("the outbox's feed did not survive a change to the outbox, in place")
	}
	var read any
	_ = host.Read(func(tx extension.ReadTx) error { read, _ = tx.Slot(extension.OutboxSlots, "feed"); return nil })
	if !bytes.Equal(read.(json.RawMessage), feed) {
		t.Fatalf("the declared outbox key read as %s", read)
	}
}

// An encrypted store written legacy gives the same records it was read with, the conversations
// section reassembled into the root's slot and sealed inside the root from then on (§7.8.4).
func TestEncryptedFixturesWrittenLegacyGiveEqualRecords(t *testing.T) {
	for _, name := range []string{"enc-v3", "enc-v4"} {
		t.Run(name, func(t *testing.T) {
			var entry compatManifestEntry
			for _, candidate := range compatManifest(t) {
				if candidate.Fixture == name {
					entry = candidate
				}
			}
			compatUseFixtureKey(t)
			dir := t.TempDir()
			path := filepath.Join(dir, "stock.dat")
			if err := os.WriteFile(path, compatRead(t, entry), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(StateLockPath(path), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			loaded := compatLoadEncrypted(t, compatRead(t, entry))
			server := reloadServer(t, dir)
			if err := server.persistState(server.statePath()); err != nil {
				t.Fatal(err)
			}
			rewritten, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			version := compatEnvelopeVersion(t, rewritten[len(encryptedStateMagic):])
			if want := map[string]int{"enc-v3": 3, "enc-v4": 4}[name]; version != want {
				t.Fatalf("written as envelope %d, want %d (legacy)", version, want)
			}
			if again := compatLoadEncrypted(t, rewritten); !bytes.Equal(again, loaded) {
				t.Fatalf("the records changed across a legacy write at byte %d", compatFirstDifference(again, loaded))
			}
		})
	}
}
