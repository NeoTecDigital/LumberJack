// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/NeoTecDigital/LumberJack/core"
	"github.com/NeoTecDigital/LumberJack/extension"
	"github.com/NeoTecDigital/LumberJack/internal/compat"
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

// countingCodec decodes and encodes a JSON object, counting both atomically.
type countingCodec struct {
	decodes atomic.Int32
	encodes atomic.Int32
}

func (c *countingCodec) Decode(raw json.RawMessage) (any, error) {
	c.decodes.Add(1)
	var value map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	return value, decoder.Decode(&value)
}

func (c *countingCodec) Encode(v any) (json.RawMessage, error) {
	c.encodes.Add(1)
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
	if codec.decodes.Load() != 0 {
		t.Fatal("the key was decoded before anyone read it")
	}
	first, second := read(), read()
	if codec.decodes.Load() != 1 || first.(map[string]any)["count"] != json.Number("1.50") || second == nil {
		t.Fatalf("decodes %d, value %v", codec.decodes.Load(), first)
	}
	if err := server.changeForest(addRootChild(server, "unrelated")); err != nil {
		t.Fatal(err)
	}
	if codec.encodes.Load() != 0 {
		t.Fatal("a key nobody set was encoded")
	}
	if _, err := host.Change(context.Background(), extension.WriteOp{Key: "set"}, func(tx extension.Tx) error {
		return tx.SetSlot(root, "ledger", map[string]any{"count": 2})
	}); err != nil {
		t.Fatal(err)
	}
	if codec.encodes.Load() != 1 {
		t.Fatalf("a set key was encoded %d times", codec.encodes.Load())
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
			server := reloadWithStorage(t, dir, cutStorageConfig(t))
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

type coldACLFixture struct {
	server                            *Server
	host                              extension.Host
	roomNode                          *core.Node
	aliceID, aliceToken, bobToken     string
	rootCodec, nodeCodec, outboxCodec *countingCodec
}

func coldACLCheck(roomID string) extension.EventDeliveryFunc {
	return func(tx extension.ReadTx, principal, scope string, _ json.RawMessage) (bool, error) {
		rootVal, ok1 := tx.Slot(tx.Root().ID, "root_acl")
		nodeVal, ok2 := tx.Slot(roomID, "node_acl")
		outboxVal, ok3 := tx.Slot(extension.OutboxSlots, "outbox_acl")
		if !ok1 || !ok2 || !ok3 {
			return false, nil
		}
		rootMap, _ := rootVal.(map[string]any)
		nodeMap, _ := nodeVal.(map[string]any)
		outboxMap, _ := outboxVal.(map[string]any)
		allow, _ := nodeMap["allow"].([]any)
		return rootMap["room"] == scope && outboxMap["channel"] == "live" && len(allow) == 1 && allow[0] == principal, nil
	}
}

func setupColdACLFixture(t *testing.T) coldACLFixture {
	t.Helper()
	seed, dir := newStockServer(t)
	alice, bob := addLoginUser(t, seed, "alice", nil), addLoginUser(t, seed, "bob", nil)
	aliceToken, _, err := seed.mintApplicationSession(alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	bobToken, _, err := seed.mintApplicationSession(bob.ID)
	if err != nil {
		t.Fatal(err)
	}
	room := core.NewNode(core.LeafNode, "room")
	room.CommandReceipts = map[string]any{compat.OwnedScopeMarker: map[string]any{}}
	if err := plantAndPersist(seed, func() error {
		room.Parents = map[string]string{seed.forest.ID: seed.forest.Name}
		seed.forest.Children[room.ID] = room
		seed.forest.Slots(slots.Token{}).SetRaw("root_acl", json.RawMessage(`{"room":"alpha","rev":2.50}`))
		room.Slots(slots.Token{}).SetRaw("node_acl", json.RawMessage(`{"allow":["`+alice.ID+`"],"rev":1.50}`))
		seed.correspondenceState().Slots(slots.Token{}).SetRaw("outbox_acl", json.RawMessage(`{"channel":"live","rev":3.50}`))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	reloaded := reloadServer(t, dir)
	fx := coldACLFixture{
		server: reloaded, roomNode: reloaded.forest.Children[room.ID],
		aliceID: alice.ID, aliceToken: aliceToken, bobToken: bobToken,
		rootCodec: &countingCodec{}, nodeCodec: &countingCodec{}, outboxCodec: &countingCodec{},
	}
	slotSpec := extension.SlotSpec{
		RootKeys:   []extension.SlotKey{{Name: "root_acl", Codec: fx.rootCodec}},
		NodeKeys:   []extension.SlotKey{{Name: "node_acl", Codec: fx.nodeCodec}},
		OutboxKeys: []extension.SlotKey{{Name: "outbox_acl", Codec: fx.outboxCodec}},
	}
	ext := testExtension{
		spec:   extension.Spec{Name: "cold-acl", Slot: slotSpec, EventDelivery: coldACLCheck(room.ID)},
		attach: func(h extension.Host) (extension.Instance, error) { fx.host = h; return testInstance{}, nil },
	}
	if err := reloaded.AttachExtensions([]extension.Extension{ext}); err != nil {
		t.Fatal(err)
	}
	return fx
}

func verifyColdACLRead(fx coldACLFixture) error {
	var rootVal, nodeVal, outboxVal any
	var ok1, ok2, ok3 bool
	err := fx.host.Read(func(tx extension.ReadTx) error {
		rootVal, ok1 = tx.Slot(tx.Root().ID, "root_acl")
		nodeVal, ok2 = tx.Slot(fx.roomNode.ID, "node_acl")
		outboxVal, ok3 = tx.Slot(extension.OutboxSlots, "outbox_acl")
		return nil
	})
	if err != nil || !ok1 || !ok2 || !ok3 {
		return fmt.Errorf("read failed: err=%v ok=%v/%v/%v", err, ok1, ok2, ok3)
	}
	rootMap, _ := rootVal.(map[string]any)
	nodeMap, _ := nodeVal.(map[string]any)
	outboxMap, _ := outboxVal.(map[string]any)
	allow, _ := nodeMap["allow"].([]any)
	if rootMap["room"] != "alpha" || rootMap["rev"] != json.Number("2.50") ||
		len(allow) != 1 || allow[0] != fx.aliceID || nodeMap["rev"] != json.Number("1.50") ||
		outboxMap["channel"] != "live" || outboxMap["rev"] != json.Number("3.50") {
		return fmt.Errorf("unexpected slots: root=%v node=%v outbox=%v", rootVal, nodeVal, outboxVal)
	}
	return nil
}

func pollColdChanges(server *Server, token string, after uint64, epoch string) (scopedChangesAnswer, error) {
	reqBody, _ := json.Marshal(map[string]any{"after": after, "epoch": epoch})
	headers := map[string]string{"Authorization": "Bearer " + token, "Content-Type": "application/json"}
	reply := server.ApplicationCall(ApplicationRequest{Method: "POST", Target: "/changes", Headers: headers, Body: reqBody})
	if reply.Status != http.StatusOK {
		return scopedChangesAnswer{}, fmt.Errorf("POST /changes status %d: %s", reply.Status, reply.Body)
	}
	var out scopedChangesAnswer
	return out, json.Unmarshal(reply.Body, &out)
}

func checkColdChangesTask(server *Server, token string, after uint64, epoch string, wantDelivered bool) func() error {
	return func() error {
		ans, err := pollColdChanges(server, token, after, epoch)
		if err != nil {
			return err
		}
		if wantDelivered && (len(ans.Events) != 1 || !bytes.Contains(ans.Events[0], []byte(`"payload":{"ok":true}`))) {
			return fmt.Errorf("member poll got %s", ans.Events)
		}
		if !wantDelivered && (len(ans.Events) != 0 || ans.After <= after) {
			return fmt.Errorf("non-member poll got events=%d after=%d", len(ans.Events), ans.After)
		}
		return nil
	}
}

func runBarrierWorker(task func() error, ready, done *sync.WaitGroup, start <-chan struct{}, errs chan<- error) {
	defer done.Done()
	ready.Done()
	<-start
	if err := task(); err != nil {
		errs <- err
	}
}

func runBarrierTasks(t *testing.T, tasks []func() error) {
	t.Helper()
	var ready, done sync.WaitGroup
	ready.Add(len(tasks))
	done.Add(len(tasks))
	start, errs := make(chan struct{}), make(chan error, len(tasks))
	for _, task := range tasks {
		go runBarrierWorker(task, &ready, &done, start, errs)
	}
	ready.Wait()
	close(start)
	done.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

func TestColdCodecSlotsDecodeOnceUnderConcurrentReaders(t *testing.T) {
	fx := setupColdACLFixture(t)
	initAlice := pollChangesRaw(t, fx.server, fx.aliceToken, 0, fx.server.mutations.epoch, nil)
	initBob := pollChangesRaw(t, fx.server, fx.bobToken, 0, fx.server.mutations.epoch, nil)
	if err := fx.host.PublishScoped("acl.ping", "alpha", json.RawMessage(`{"ok":true}`)); err != nil {
		t.Fatal(err)
	}
	if fx.rootCodec.decodes.Load() != 0 || fx.nodeCodec.decodes.Load() != 0 || fx.outboxCodec.decodes.Load() != 0 {
		t.Fatal("cold slots decoded before any reader ran")
	}
	var tasks []func() error
	for i := 0; i < 16; i++ {
		tasks = append(tasks, func() error { return verifyColdACLRead(fx) })
	}
	for i := 0; i < 8; i++ {
		tasks = append(tasks, checkColdChangesTask(fx.server, fx.aliceToken, initAlice.After, initAlice.Epoch, true))
		tasks = append(tasks, checkColdChangesTask(fx.server, fx.bobToken, initBob.After, initBob.Epoch, false))
	}
	runBarrierTasks(t, tasks)
	if fx.rootCodec.decodes.Load() != 1 || fx.nodeCodec.decodes.Load() != 1 || fx.outboxCodec.decodes.Load() != 1 {
		t.Fatalf("decodes = %d/%d/%d, want 1/1/1", fx.rootCodec.decodes.Load(), fx.nodeCodec.decodes.Load(), fx.outboxCodec.decodes.Load())
	}
	if err := fx.server.changeForest(addRootChild(fx.server, "unrelated")); err != nil {
		t.Fatal(err)
	}
	if fx.rootCodec.encodes.Load() != 0 || fx.nodeCodec.encodes.Load() != 0 || fx.outboxCodec.encodes.Load() != 0 {
		t.Fatalf("encodes = %d/%d/%d, want 0/0/0", fx.rootCodec.encodes.Load(), fx.nodeCodec.encodes.Load(), fx.outboxCodec.encodes.Load())
	}
	requireRefused(t, "owned slot tamper", fx.server.changeForest(func() error {
		fx.roomNode.Name = "tampered"
		fx.roomNode.Slots(slots.Token{}).Delete("node_acl")
		return nil
	}))
	if err := verifyColdACLRead(fx); err != nil {
		t.Fatalf("after owned_guard CopyFrom restore: %v", err)
	}
	var copied slots.Store
	copied.CopyFrom(fx.server.forest.Slots(slots.Token{}))
	val, ok := copied.Get("root_acl")
	if !ok {
		t.Fatal("CopyFrom lost decoded root_acl")
	}
	if got, ok := val.Decode(fx.rootCodec.Decode); !ok || fx.rootCodec.decodes.Load() != 1 || got == nil {
		t.Fatalf("CopyFrom did not preserve decoded state: ok=%v decodes=%d", ok, fx.rootCodec.decodes.Load())
	}
}

type failingCodec struct{ decodes atomic.Int32 }

func (c *failingCodec) Decode(raw json.RawMessage) (any, error) {
	c.decodes.Add(1)
	if len(raw) > 0 {
		raw[0] = 'X'
	}
	return nil, errors.New("corrupt slot payload")
}

func (c *failingCodec) Encode(v any) (json.RawMessage, error) { return json.Marshal(v) }

func failingReadTask(host extension.Host) func() error {
	return func() error {
		var got any
		var ok bool
		_ = host.Read(func(tx extension.ReadTx) error { got, ok = tx.Slot(tx.Root().ID, "broken_acl"); return nil })
		if ok || got != nil {
			return fmt.Errorf("failing codec answered (%v, %v)", got, ok)
		}
		return nil
	}
}

func TestColdFailingCodecConcurrentReadsFailClosedAndKeepRaw(t *testing.T) {
	const planted = `{"raw_number":1.50}`
	seed, dir := newStockServer(t)
	alice := addLoginUser(t, seed, "alice", nil)
	token, _, err := seed.mintApplicationSession(alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := plantAndPersist(seed, func() error {
		seed.forest.Slots(slots.Token{}).SetRaw("broken_acl", json.RawMessage(planted))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	reloaded := reloadServer(t, dir)
	codec := &failingCodec{}
	var host extension.Host
	check := func(tx extension.ReadTx, _, _ string, _ json.RawMessage) (bool, error) {
		_, ok := tx.Slot(tx.Root().ID, "broken_acl")
		return ok, nil
	}
	spec := extension.Spec{
		Name: "broken-acl", EventDelivery: check,
		Slot: extension.SlotSpec{RootKeys: []extension.SlotKey{{Name: "broken_acl", Codec: codec}}},
	}
	ext := testExtension{
		spec:   spec,
		attach: func(h extension.Host) (extension.Instance, error) { host = h; return testInstance{}, nil },
	}
	if err := reloaded.AttachExtensions([]extension.Extension{ext}); err != nil {
		t.Fatal(err)
	}
	initAlice := pollChangesRaw(t, reloaded, token, 0, reloaded.mutations.epoch, nil)
	if err := host.PublishScoped("acl.ping", "alpha", json.RawMessage(`{"ok":true}`)); err != nil {
		t.Fatal(err)
	}
	var tasks []func() error
	for i := 0; i < 8; i++ {
		tasks = append(tasks, failingReadTask(host))
		tasks = append(tasks, checkColdChangesTask(reloaded, token, initAlice.After, initAlice.Epoch, false))
	}
	runBarrierTasks(t, tasks)
	held, ok := reloaded.forest.Slots(slots.Token{}).Get("broken_acl")
	if !ok || string(held.Raw) != planted || codec.decodes.Load() < 16 {
		t.Fatalf("raw=%q ok=%v decodes=%d", held.Raw, ok, codec.decodes.Load())
	}
}
