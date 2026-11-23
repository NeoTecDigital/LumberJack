// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/NeoTecDigital/LumberJack/core"
	"github.com/NeoTecDigital/LumberJack/extension"
)

type scopedChangesAnswer struct {
	Events   []json.RawMessage `json:"events"`
	Epoch    string            `json:"epoch"`
	After    uint64            `json:"after"`
	CaughtUp bool              `json:"caught_up"`
	Resync   bool              `json:"resync"`
	Visible  []string          `json:"visible"`
}

type decodedChangeEvent struct {
	Sequence   uint64          `json:"sequence"`
	Type       string          `json:"type"`
	NodePath   string          `json:"node_path"`
	EntryIndex int             `json:"entry_index"`
	Payload    json.RawMessage `json:"payload"`
}

func pollChangesRaw(t *testing.T, server *Server, token string, after uint64, epoch string, visible []string) scopedChangesAnswer {
	t.Helper()
	reqBody, _ := json.Marshal(map[string]any{"after": after, "epoch": epoch, "visible": visible})
	reply := server.ApplicationCall(ApplicationRequest{
		Method:  "POST",
		Target:  "/changes",
		Headers: map[string]string{"Authorization": "Bearer " + token, "Content-Type": "application/json"},
		Body:    reqBody,
	})
	if reply.Status != http.StatusOK {
		t.Fatalf("POST /changes answered %d: %s", reply.Status, reply.Body)
	}
	var out scopedChangesAnswer
	if err := json.Unmarshal(reply.Body, &out); err != nil {
		t.Fatalf("decode /changes: %v", err)
	}
	return out
}

func decodeChangeEvent(t *testing.T, raw json.RawMessage) decodedChangeEvent {
	t.Helper()
	var ev decodedChangeEvent
	if err := json.Unmarshal(raw, &ev); err != nil {
		t.Fatalf("decode event %s: %v", raw, err)
	}
	return ev
}

func roomMemberCheck(mutatePayload bool) extension.EventDeliveryFunc {
	return func(tx extension.ReadTx, principal, scope string, payload json.RawMessage) (bool, error) {
		if mutatePayload && len(payload) > 0 {
			payload[0] = '!'
		}
		raw, ok := tx.Slot(tx.Root().ID, "rooms")
		if !ok {
			return false, nil
		}
		var rooms map[string][]string
		if err := json.Unmarshal(raw.(json.RawMessage), &rooms); err != nil {
			return false, err
		}
		for _, member := range rooms[scope] {
			if member == principal {
				return true, nil
			}
		}
		return false, nil
	}
}

func setRoomMembers(t *testing.T, host extension.Host, rooms map[string][]string) {
	t.Helper()
	encoded, err := json.Marshal(rooms)
	if err != nil {
		t.Fatal(err)
	}
	_, err = host.Change(context.Background(), extension.WriteOp{Key: "set-rooms"}, func(tx extension.Tx) error {
		return tx.SetSlot(tx.Root().ID, "rooms", json.RawMessage(encoded))
	})
	if err != nil {
		t.Fatal(err)
	}
}

func setupRoomServer(t *testing.T, check extension.EventDeliveryFunc) (*Server, extension.Host) {
	t.Helper()
	server, _ := newStockServer(t)
	var host extension.Host
	spec := extension.Spec{
		Name:          "room-bus",
		Slot:          extension.SlotSpec{RootKeys: []extension.SlotKey{{Name: "rooms"}}},
		EventDelivery: check,
	}
	ext := testExtension{spec: spec, attach: func(h extension.Host) (extension.Instance, error) {
		host = h
		return testInstance{}, nil
	}}
	if err := server.AttachExtensions([]extension.Extension{ext}); err != nil {
		t.Fatal(err)
	}
	return server, host
}

func startAuthenticatedStreamServer(t *testing.T, server *Server) *httptest.Server {
	t.Helper()
	listener := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+r.Header.Get("X-Test-User"))
		server.authMiddleware(server.handleStream)(w, r)
	}))
	t.Cleanup(listener.Close)
	return listener
}

func openConnectedStream(t *testing.T, url, token string) *streamReader {
	t.Helper()
	reader := openStream(t, url, token, "")
	if !readsComment(t, reader, "connected", streamWait) {
		reader.close()
		t.Fatal("stream did not announce connected")
	}
	return reader
}

func TestScopedEventDeliveredVerbatimToMemberAndWithheldFromNonMember(t *testing.T) {
	server, host := setupRoomServer(t, roomMemberCheck(true))
	alice := addLoginUser(t, server, "alice", nil)
	bob := addLoginUser(t, server, "bob", nil)
	aliceToken, _, _ := server.mintApplicationSession(alice.ID)
	bobToken, _, _ := server.mintApplicationSession(bob.ID)
	setRoomMembers(t, host, map[string][]string{"room/alpha": {alice.ID}})

	initAlice := pollChangesRaw(t, server, aliceToken, 0, server.mutations.epoch, nil)
	initBob := pollChangesRaw(t, server, bobToken, 0, server.mutations.epoch, nil)
	streamSrv := startAuthenticatedStreamServer(t, server)
	aliceStream := openConnectedStream(t, streamSrv.URL, aliceToken)
	defer aliceStream.close()
	bobStream := openConnectedStream(t, streamSrv.URL, bobToken)
	defer bobStream.close()

	const wantPayload = `{"seq":7,"tags":["x","y"],"nested":{"ok":true}}`
	callerBuf := []byte(wantPayload)
	if err := host.PublishScoped("room.note", "room/alpha", callerBuf); err != nil {
		t.Fatalf("PublishScoped: %v", err)
	}
	callerBuf[0] = 'X'

	aliceChanges := pollChangesRaw(t, server, aliceToken, initAlice.After, initAlice.Epoch, initAlice.Visible)
	if len(aliceChanges.Events) != 1 || aliceChanges.Resync {
		t.Fatalf("alice /changes = %+v", aliceChanges)
	}
	rawEvent := string(aliceChanges.Events[0])
	if strings.Contains(rawEvent, "extensionOwner") || strings.Contains(rawEvent, `"scope"`) {
		t.Fatalf("internal routing fields leaked onto wire: %s", rawEvent)
	}
	ev := decodeChangeEvent(t, aliceChanges.Events[0])
	if ev.Type != "room.note" || ev.NodePath != "" || ev.EntryIndex != -1 || string(ev.Payload) != wantPayload {
		t.Fatalf("alice event = %+v, payload = %s", ev, ev.Payload)
	}
	bobChanges := pollChangesRaw(t, server, bobToken, initBob.After, initBob.Epoch, initBob.Visible)
	if len(bobChanges.Events) != 0 || bobChanges.Resync || bobChanges.After != ev.Sequence {
		t.Fatalf("bob /changes = %+v, want empty at after=%d", bobChanges, ev.Sequence)
	}
	if streamEv := aliceStream.nextEvent(t, streamWait); streamEv.Type != "room.note" || string(streamEv.Payload) != wantPayload {
		t.Fatalf("alice /stream event = %+v, payload = %s", streamEv, streamEv.Payload)
	}
	bobStream.silentFor(t, 60*time.Millisecond)
}

func TestScopedEventMembershipRemovalTakesEffectAtNextPoll(t *testing.T) {
	server, host := setupRoomServer(t, roomMemberCheck(false))
	alice := addLoginUser(t, server, "alice", nil)
	aliceToken, _, _ := server.mintApplicationSession(alice.ID)
	setRoomMembers(t, host, map[string][]string{"room/alpha": {alice.ID}})

	base := pollChangesRaw(t, server, aliceToken, 0, server.mutations.epoch, nil)
	if err := host.PublishScoped("room.note", "room/alpha", json.RawMessage(`{"step":1}`)); err != nil {
		t.Fatal(err)
	}
	first := pollChangesRaw(t, server, aliceToken, base.After, base.Epoch, base.Visible)
	if len(first.Events) != 1 {
		t.Fatalf("member poll got %d events, want 1", len(first.Events))
	}

	// Publish step 2 while alice is still listed, then revoke membership BEFORE alice polls,
	// and publish step 3 after revocation: live poll-time evaluation must withhold both.
	if err := host.PublishScoped("room.note", "room/alpha", json.RawMessage(`{"step":2}`)); err != nil {
		t.Fatal(err)
	}
	setRoomMembers(t, host, map[string][]string{"room/alpha": {}})
	if err := host.PublishScoped("room.note", "room/alpha", json.RawMessage(`{"step":3}`)); err != nil {
		t.Fatal(err)
	}

	afterRevoke := pollChangesRaw(t, server, aliceToken, first.After, first.Epoch, first.Visible)
	if len(afterRevoke.Events) != 0 || afterRevoke.After <= first.After || afterRevoke.Resync {
		t.Fatalf("post-revocation poll = %+v (prev after=%d)", afterRevoke, first.After)
	}

	setRoomMembers(t, host, map[string][]string{"room/alpha": {alice.ID}})
	if err := host.PublishScoped("room.note", "room/alpha", json.RawMessage(`{"step":4}`)); err != nil {
		t.Fatal(err)
	}
	restored := pollChangesRaw(t, server, aliceToken, afterRevoke.After, afterRevoke.Epoch, afterRevoke.Visible)
	if len(restored.Events) != 1 || string(decodeChangeEvent(t, restored.Events[0]).Payload) != `{"step":4}` {
		t.Fatalf("re-added member poll = %+v", restored)
	}
}

func createPrivateSubnode(t *testing.T, host extension.Host, ownerID, name string) string {
	t.Helper()
	var path string
	_, err := host.Change(context.Background(), extension.WriteOp{Key: "mk-" + name}, func(tx extension.Tx) error {
		root := tx.Root()
		child := core.NewNode(core.BranchNode, name)
		child.Parents = map[string]string{root.ID: root.Name}
		child.CreatedBy = ownerID
		child.Users = []core.User{{ID: ownerID, Permissions: []core.Permission{core.AdminPermission}}}
		root.Children[child.ID] = child
		path = root.Name + "/" + name
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func TestScopedAndUnscopedEventsShareOneMonotonicCursorInOrder(t *testing.T) {
	server, host := setupRoomServer(t, roomMemberCheck(false))
	admin := adminID(t, server)
	alice := addLoginUser(t, server, "alice", nil)
	aliceToken, _, _ := server.mintApplicationSession(alice.ID)
	setRoomMembers(t, host, map[string][]string{"room/open": {alice.ID}})

	privatePath := createPrivateSubnode(t, host, admin, "secret-branch")
	alicePath := createPrivateSubnode(t, host, alice.ID, "alice-branch")
	base := pollChangesRaw(t, server, aliceToken, 0, server.mutations.epoch, nil)

	host.Publish("custom_unscoped", alicePath)
	_ = host.PublishScoped("room.secret", "room/closed", json.RawMessage(`{"n":1}`))
	_ = host.PublishScoped("room.open", "room/open", json.RawMessage(`{"n":2}`))
	host.Publish("private_unscoped", privatePath)
	_ = host.PublishScoped("room.open", "room/open", json.RawMessage(`{"n":3}`))
	_ = host.PublishScoped("room.secret", "room/closed", json.RawMessage(`{"n":4}`))
	wantFinalAfter := server.mutations.sequence

	polled := pollChangesRaw(t, server, aliceToken, base.After, base.Epoch, base.Visible)
	if len(polled.Events) != 3 || polled.After != wantFinalAfter || polled.Resync {
		t.Fatalf("interleaved poll = %+v, want 3 events and after=%d", polled, wantFinalAfter)
	}
	if strings.Contains(string(polled.Events[0]), `"payload"`) {
		t.Fatalf("unscoped event carried payload field: %s", polled.Events[0])
	}
	e0 := decodeChangeEvent(t, polled.Events[0])
	e1 := decodeChangeEvent(t, polled.Events[1])
	e2 := decodeChangeEvent(t, polled.Events[2])
	if !(e0.Sequence < e1.Sequence && e1.Sequence < e2.Sequence && e2.Sequence < polled.After) {
		t.Fatalf("non-monotonic sequences: %d, %d, %d, after=%d", e0.Sequence, e1.Sequence, e2.Sequence, polled.After)
	}
	if e0.Type != "custom_unscoped" || string(e1.Payload) != `{"n":2}` || string(e2.Payload) != `{"n":3}` {
		t.Fatalf("unexpected delivered events: %+v %+v %+v", e0, e1, e2)
	}

	steady := pollChangesRaw(t, server, aliceToken, polled.After, polled.Epoch, polled.Visible)
	if len(steady.Events) != 0 || steady.After != polled.After || steady.Resync {
		t.Fatalf("follow-up poll regressed or stalled: %+v", steady)
	}
	lostVis := pollChangesRaw(t, server, aliceToken, polled.After, polled.Epoch, append(polled.Visible, privatePath))
	if !lostVis.Resync {
		t.Fatal("lost unscoped path visibility did not set resync")
	}
}

func TestScopedEventFailsClosedWithoutCheckOrOnCallbackError(t *testing.T) {
	nilServer, nilHost := setupRoomServer(t, nil)
	adminTok, _, _ := nilServer.mintApplicationSession(adminID(t, nilServer))
	base := pollChangesRaw(t, nilServer, adminTok, 0, nilServer.mutations.epoch, nil)
	if err := nilHost.PublishScoped("room.note", "room/any", json.RawMessage(`{"x":1}`)); err != nil {
		t.Fatalf("PublishScoped with nil check: %v", err)
	}
	got := pollChangesRaw(t, nilServer, adminTok, base.After, base.Epoch, base.Visible)
	if len(got.Events) != 0 || got.After <= base.After {
		t.Fatalf("nil EventDelivery leaked or failed to advance cursor: %+v", got)
	}

	mode := "err"
	errServer, errHost := setupRoomServer(t, func(extension.ReadTx, string, string, json.RawMessage) (bool, error) {
		if mode == "panic" {
			panic("unexpected callback failure")
		}
		return true, errors.New("boom")
	})
	errTok, _, _ := errServer.mintApplicationSession(adminID(t, errServer))
	errBase := pollChangesRaw(t, errServer, errTok, 0, errServer.mutations.epoch, nil)
	if err := errHost.PublishScoped("room.note", "room/any", json.RawMessage(`{"x":2}`)); err != nil {
		t.Fatal(err)
	}
	mode = "panic"
	if err := errHost.PublishScoped("room.note", "room/any", json.RawMessage(`{"x":3}`)); err != nil {
		t.Fatal(err)
	}
	errGot := pollChangesRaw(t, errServer, errTok, errBase.After, errBase.Epoch, errBase.Visible)
	if len(errGot.Events) != 0 || errGot.After != errBase.After+2 {
		t.Fatalf("error/panic EventDelivery leaked or stalled: %+v", errGot)
	}
}

func TestPublishScopedValidatesBoundsAndJSON(t *testing.T) {
	server, host := setupRoomServer(t, func(extension.ReadTx, string, string, json.RawMessage) (bool, error) {
		return true, nil
	})
	exactMax := append([]byte(`"`), bytes.Repeat([]byte("a"), extension.MaxEventPayloadBytes-2)...)
	exactMax = append(exactMax, '"')
	if len(exactMax) != extension.MaxEventPayloadBytes {
		t.Fatalf("exactMax len = %d", len(exactMax))
	}
	if err := host.PublishScoped("room.max", "room/ok", exactMax); err != nil {
		t.Fatalf("4096-byte JSON payload refused: %v", err)
	}

	beforeSeq := server.mutations.sequence
	overMax := append([]byte(`"`), bytes.Repeat([]byte("a"), extension.MaxEventPayloadBytes-1)...)
	overMax = append(overMax, '"')
	invalidCases := []struct {
		name, kind, scope string
		payload           json.RawMessage
	}{
		{"4097-byte payload", "room.note", "room/ok", overMax},
		{"empty payload", "room.note", "room/ok", nil},
		{"whitespace payload", "room.note", "room/ok", json.RawMessage("   ")},
		{"malformed json", "room.note", "room/ok", json.RawMessage(`{"unclosed":1`)},
		{"empty kind", "", "room/ok", json.RawMessage(`{}`)},
		{"newline in kind", "room\nnote", "room/ok", json.RawMessage(`{}`)},
		{"space in kind", "room note", "room/ok", json.RawMessage(`{}`)},
		{"empty scope", "room.note", "", json.RawMessage(`{}`)},
		{"control char in scope", "room.note", "room/\x00bad", json.RawMessage(`{}`)},
		{"overlong scope", "room.note", strings.Repeat("s", 513), json.RawMessage(`{}`)},
	}
	for _, tc := range invalidCases {
		if err := host.PublishScoped(tc.kind, tc.scope, tc.payload); err == nil {
			t.Errorf("%s was accepted", tc.name)
		}
	}
	if server.mutations.sequence != beforeSeq {
		t.Fatalf("refused PublishScoped advanced sequence (%d -> %d)", beforeSeq, server.mutations.sequence)
	}

	if err := server.CloseExtensions(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := host.PublishScoped("room.note", "room/ok", json.RawMessage(`{}`)); !errors.Is(err, errExtensionsClosed) {
		t.Fatalf("PublishScoped after CloseExtensions = %v, want errExtensionsClosed", err)
	}
}
