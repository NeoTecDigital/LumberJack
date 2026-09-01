package internal

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// THE DEFECT: entry attachments were WRITE-ONLY.
//
// POST /events/{id}/entries/{index}/attachments stored the file on the ENTRY and answered 200 with
// an id. GET /attachments/{id} resolved that id against Node.Attachments alone, so it answered 404
// for that id forever — a success response for something the caller could never fetch. DELETE had
// the same one-place lookup and reported 500 for an id it simply could not see.
//
// A file that goes up and cannot come down is the same defect class as an upload that stores
// nothing: the status says yes and the bytes are unreachable.

// uploadToEntry puts bytes on an event entry through the route that does it.
func uploadToEntry(t *testing.T, server *Server, userID, path, eventID string, index int, name string, contents []byte) *httptest.ResponseRecorder {
	t.Helper()

	body, contentType := uploadForm(t, name, contents, nil)
	target := fmt.Sprintf("/events/%s/entries/%d/attachments?path=%s", eventID, index, path)
	request := withUser(httptest.NewRequest("POST", target, body), userID)
	request.Header.Set("Content-Type", contentType)

	recorder := httptest.NewRecorder()
	attachmentRouter(server).ServeHTTP(recorder, request)
	return recorder
}

// deleteFile removes an attachment the way a client does: by id, with no idea where it is kept.
func deleteFile(t *testing.T, server *Server, userID, path, attachmentID string) *httptest.ResponseRecorder {
	t.Helper()

	target := fmt.Sprintf("/attachments/%s?path=%s", attachmentID, path)
	recorder := httptest.NewRecorder()
	attachmentRouter(server).ServeHTTP(recorder, withUser(httptest.NewRequest("DELETE", target, nil), userID))
	return recorder
}

// receiptFrom reads an upload receipt, failing loudly when the route did not answer with one.
func receiptFrom(t *testing.T, what string, recorder *httptest.ResponseRecorder) attachmentView {
	t.Helper()

	if recorder.Code != http.StatusOK {
		t.Fatalf("%s: got %d, want %d: %s", what, recorder.Code, http.StatusOK, recorder.Body.String())
	}
	var receipt attachmentView
	if err := json.Unmarshal(recorder.Body.Bytes(), &receipt); err != nil {
		t.Fatalf("%s: the receipt was not JSON: %v: %s", what, err, recorder.Body.String())
	}
	return receipt
}

// eventWithAnEntry is a leaf carrying one started event with one entry on it, which is the address
// an entry attachment needs.
func eventWithAnEntry(t *testing.T, server *Server, userID, path, eventID string) string {
	t.Helper()

	leafFor(t, server, userID, path)
	if code := post(t, server.handleStartEvent, userID, map[string]interface{}{
		"path": path, "event_id": eventID,
	}).Code; code != http.StatusOK {
		t.Fatalf("Start event %s: got %d, want %d", eventID, code, http.StatusOK)
	}
	if code := post(t, server.handleAppendToEvent, userID, map[string]interface{}{
		"path": path, "event_id": eventID, "content": "an entry to hang a file on",
	}).Code; code != http.StatusOK {
		t.Fatalf("Append to %s: got %d, want %d", eventID, code, http.StatusOK)
	}
	return path
}

// What an entry upload is FOR: the bytes come back, byte for byte, from the id the receipt named.
func TestAnEntryAttachmentComesBackByteForByte(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)
	path := eventWithAnEntry(t, server, userID, "work/entry-files", "shift")

	contents := binaryPayload(2048)
	digest := sha256.Sum256(contents)
	wantHash := hex.EncodeToString(digest[:])

	receipt := receiptFrom(t, "POST entry attachment",
		uploadToEntry(t, server, userID, path, "shift", 0, "on-entry.bin", contents))
	if receipt.Hash != wantHash {
		t.Errorf("The receipt hashes the file as %q, want %q", receipt.Hash, wantHash)
	}

	fetched := fetchFile(t, server, userID, path, receipt.ID)
	if fetched.Code != http.StatusOK {
		t.Fatalf("GET /attachments/%s for a file stored on an ENTRY: got %d, want %d: %s",
			receipt.ID, fetched.Code, http.StatusOK, fetched.Body.String())
	}
	if got := fetched.Body.Bytes(); !bytes.Equal(got, contents) {
		t.Fatalf("The entry file came back as %d bytes, want the %d that went up (first difference at %d)",
			len(got), len(contents), firstDifference(got, contents))
	}
	returned := sha256.Sum256(fetched.Body.Bytes())
	if hex.EncodeToString(returned[:]) != wantHash {
		t.Errorf("The entry file came back hashing to %s, want %s",
			hex.EncodeToString(returned[:]), wantHash)
	}
}

// ONE ROUTE, either holder. A caller has an id and a node; where the file is kept is the engine's
// business, and an id that resolves only when the caller already knows the entry is an id the
// caller cannot use.
func TestTheDownloadRouteResolvesBothStorageLocationsByIDAlone(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)
	path := eventWithAnEntry(t, server, userID, "work/both-holders", "shift")

	onNode := binaryPayload(64)
	onEntry := binaryPayload(128)

	nodeReceipt := receiptFrom(t, "POST /attachments/upload",
		uploadFile(t, server, userID, path, "node.bin", onNode))
	entryReceipt := receiptFrom(t, "POST entry attachment",
		uploadToEntry(t, server, userID, path, "shift", 0, "entry.bin", onEntry))

	if nodeReceipt.ID == entryReceipt.ID {
		t.Fatal("The two uploads were given the same id, so this proves nothing about either holder")
	}

	for _, held := range []struct {
		where    string
		id       string
		contents []byte
	}{
		{"the node", nodeReceipt.ID, onNode},
		{"an entry", entryReceipt.ID, onEntry},
	} {
		fetched := fetchFile(t, server, userID, path, held.id)
		if fetched.Code != http.StatusOK {
			t.Fatalf("GET /attachments/%s (stored on %s): got %d, want %d: %s",
				held.id, held.where, fetched.Code, http.StatusOK, fetched.Body.String())
		}
		if !bytes.Equal(fetched.Body.Bytes(), held.contents) {
			t.Fatalf("The file stored on %s came back as %d bytes, want %d",
				held.where, fetched.Body.Len(), len(held.contents))
		}
	}
}

// DELETE agrees with GET about what an id names: it removes the file from either holder, and the
// id stops resolving afterwards.
func TestDeletingAnAttachmentWorksForEitherHolder(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)
	path := eventWithAnEntry(t, server, userID, "work/deletable", "shift")

	nodeReceipt := receiptFrom(t, "POST /attachments/upload",
		uploadFile(t, server, userID, path, "node.bin", binaryPayload(96)))
	entryReceipt := receiptFrom(t, "POST entry attachment",
		uploadToEntry(t, server, userID, path, "shift", 0, "entry.bin", binaryPayload(192)))

	for _, held := range []struct {
		where string
		id    string
	}{
		{"the node", nodeReceipt.ID},
		{"an entry", entryReceipt.ID},
	} {
		removed := deleteFile(t, server, userID, path, held.id)
		if removed.Code != http.StatusOK {
			t.Fatalf("DELETE /attachments/%s (stored on %s): got %d, want %d: %s",
				held.id, held.where, removed.Code, http.StatusOK, removed.Body.String())
		}

		gone := fetchFile(t, server, userID, path, held.id)
		if gone.Code != http.StatusNotFound {
			t.Fatalf("GET /attachments/%s after deleting it from %s: got %d, want %d",
				held.id, held.where, gone.Code, http.StatusNotFound)
		}
	}

	node, err := server.getNodeFromPath(path)
	if err != nil {
		t.Fatalf("Failed to find the node: %v", err)
	}
	if len(node.Attachments) != 0 {
		t.Errorf("The node still holds %d attachments after both deletes", len(node.Attachments))
	}
	if held := len(node.Events["shift"].Entries[0].Attachments); held != 0 {
		t.Errorf("The entry still holds %d attachments after both deletes", held)
	}
}

// A delete of an id nobody stored is NOT FOUND. It answered 500 — the server saying it broke over
// a request that was merely about something that is not there, which a client cannot tell from a
// real failure and will retry.
func TestDeletingAnAttachmentThatIsNotThereIsNotFound(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)
	path := leafFor(t, server, userID, "work/nothing-here")

	refused := deleteFile(t, server, userID, path,
		"0000000000000000000000000000000000000000000000000000000000000000")
	if refused.Code != http.StatusNotFound {
		t.Fatalf("DELETE of an absent attachment: got %d, want %d: %s",
			refused.Code, http.StatusNotFound, refused.Body.String())
	}
}

// An entry attachment survives a restart and is STILL resolvable by id alone: the lookup has to
// agree with the state file, not just with the in-memory forest it was written into.
func TestAnEntryAttachmentResolvesAfterARestart(t *testing.T) {
	server, dir := newStockServer(t)
	userID := adminID(t, server)
	path := eventWithAnEntry(t, server, userID, "work/durable-entry-files", "shift")

	contents := binaryPayload(777)
	receipt := receiptFrom(t, "POST entry attachment",
		uploadToEntry(t, server, userID, path, "shift", 0, "durable.bin", contents))

	reloaded := reloadServer(t, dir)
	fetched := fetchFile(t, reloaded, userID, path, receipt.ID)
	if fetched.Code != http.StatusOK {
		t.Fatalf("GET /attachments/%s after a restart: got %d, want %d: %s",
			receipt.ID, fetched.Code, http.StatusOK, fetched.Body.String())
	}
	if !bytes.Equal(fetched.Body.Bytes(), contents) {
		t.Fatalf("The entry file came back as %d bytes after a restart, want %d",
			fetched.Body.Len(), len(contents))
	}
}
