package internal

import (
	"bytes"
	"testing"
)

// A rejected command restores a decoded snapshot. The acknowledgement must still
// identify exactly the already durable state, including typed command receipts.
func TestWorkspaceCodecDiagnostic(t *testing.T) {
	s := setupTestForest(t)
	path := workTestCommand(t, s, "admin", WorkCommand{Command: "create", Path: "root", Title: "Fixture", Kind: "goal", ClientID: "codec-create"}, 200)["path"].(string)
	workTestCommand(t, s, "admin", WorkCommand{Command: "timer_start", Path: path, ClientID: "codec-start"}, 200)
	raw, err := encodeState(s.forest)
	if err != nil {
		t.Fatal(err)
	}
	clone, err := decodeState(raw)
	if err != nil {
		t.Fatal(err)
	}
	next, err := encodeState(clone)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, next) {
		t.Fatal("rollback changed the durable acknowledgement identity")
	}
}
