package internal

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/NeoTecDigital/LumberJack/internal/core"
)

// THE DEFECT: POST /attachments/upload answered 200 and kept NOTHING. It built the attachment out
// of the multipart HEADER — name, declared type, declared size — and never read the file. Data was
// nil and Hash was "", so the receipt said `"size":25,"hash":""` and GET /attachments/{id} answered
// 200 with a zero-length body. core.AttachmentStore.Store, which reads the bytes, hashes them and
// enforces the cap, was reached by the ENTRY attachment route and by nothing else: two upload
// routes, opposite behaviour.
//
// It is a REGRESSION and not merely an old hole. Before c95ef33 the route looked the node up with
// forest.GetNode on a value that is a PATH, so it could only ever answer 404 — it failed. Switching
// it to changeNode turned a route that always failed into one that answers 200 and silently loses
// the file, which is the exact defect class this effort exists to remove.
//
// These tests assert the bytes, not the status: a 200 is not evidence that anything was stored.

// attachmentRouter is the attachment surface with the caller already in context, mirroring how
// routes() registers it. The id and the entry address are PATH variables, so these routes cannot be
// driven by calling the handler directly.
func attachmentRouter(server *Server) *mux.Router {
	router := mux.NewRouter()
	router.HandleFunc("/attachments/upload", server.handleUploadAttachment).Methods("POST")
	router.HandleFunc("/attachments/{id}", server.handleGetAttachment).Methods("GET")
	router.HandleFunc("/attachments/{id}", server.handleDeleteAttachment).Methods("DELETE")
	router.HandleFunc("/events/{eventId}/entries/{entryIndex}/attachments",
		server.handleAddEntryAttachment).Methods("POST")
	return router
}

// uploadForm builds a multipart body carrying one file and the fields that go with it.
func uploadForm(t *testing.T, name string, contents []byte, fields map[string]string) (*bytes.Buffer, string) {
	t.Helper()

	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	for key, value := range fields {
		if err := form.WriteField(key, value); err != nil {
			t.Fatalf("Failed to write the %s field: %v", key, err)
		}
	}
	part, err := form.CreateFormFile("file", name)
	if err != nil {
		t.Fatalf("Failed to build the file part: %v", err)
	}
	if _, err := part.Write(contents); err != nil {
		t.Fatalf("Failed to write the file part: %v", err)
	}
	if err := form.Close(); err != nil {
		t.Fatalf("Failed to close the form: %v", err)
	}
	return &body, form.FormDataContentType()
}

// uploadFile puts bytes on a node through the route that does it and returns the whole exchange.
func uploadFile(t *testing.T, server *Server, userID, path, name string, contents []byte) *httptest.ResponseRecorder {
	t.Helper()

	body, contentType := uploadForm(t, name, contents, map[string]string{"path": path})
	request := withUser(httptest.NewRequest("POST", "/attachments/upload", body), userID)
	request.Header.Set("Content-Type", contentType)

	recorder := httptest.NewRecorder()
	attachmentRouter(server).ServeHTTP(recorder, request)
	return recorder
}

// fetchFile asks for an attachment's contents the way a client downloading it does.
func fetchFile(t *testing.T, server *Server, userID, path, attachmentID string) *httptest.ResponseRecorder {
	t.Helper()

	target := fmt.Sprintf("/attachments/%s?path=%s", attachmentID, path)
	recorder := httptest.NewRecorder()
	attachmentRouter(server).ServeHTTP(recorder, withUser(httptest.NewRequest("GET", target, nil), userID))
	return recorder
}

// binaryPayload is deliberately not text: a NUL, a byte above 0x7f and a newline, so a round trip
// that goes through a string, a text encoding or a line-oriented copy cannot pass by accident.
func binaryPayload(size int) []byte {
	payload := make([]byte, size)
	for index := range payload {
		payload[index] = byte(index * 7 % 251)
	}
	if size > 3 {
		payload[0], payload[1], payload[2], payload[3] = 0x00, 0xff, '\n', 0x80
	}
	return payload
}

// What an upload is FOR: the bytes come back, byte for byte.
func TestAnUploadedFileComesBackByteForByte(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)
	path := leafFor(t, server, userID, "work/files")

	contents := binaryPayload(25)
	digest := sha256.Sum256(contents)
	wantHash := hex.EncodeToString(digest[:])

	uploaded := uploadFile(t, server, userID, path, "receipt.bin", contents)
	if uploaded.Code != http.StatusOK {
		t.Fatalf("POST /attachments/upload: got %d, want %d: %s",
			uploaded.Code, http.StatusOK, uploaded.Body.String())
	}

	var receipt attachmentView
	if err := json.Unmarshal(uploaded.Body.Bytes(), &receipt); err != nil {
		t.Fatalf("The upload receipt was not JSON: %v: %s", err, uploaded.Body.String())
	}
	if receipt.Size != int64(len(contents)) {
		t.Errorf("The receipt says the file is %d bytes, want %d", receipt.Size, len(contents))
	}
	if receipt.Hash != wantHash {
		t.Errorf("The receipt hashes the file as %q, want %q", receipt.Hash, wantHash)
	}

	fetched := fetchFile(t, server, userID, path, receipt.ID)
	if fetched.Code != http.StatusOK {
		t.Fatalf("GET /attachments/%s: got %d, want %d: %s",
			receipt.ID, fetched.Code, http.StatusOK, fetched.Body.String())
	}
	if got := fetched.Body.Bytes(); !bytes.Equal(got, contents) {
		t.Fatalf("The file came back as %d bytes, want the %d that went up (first difference at %d)",
			len(got), len(contents), firstDifference(got, contents))
	}
	returned := sha256.Sum256(fetched.Body.Bytes())
	if hex.EncodeToString(returned[:]) != wantHash {
		t.Errorf("The file came back hashing to %s, want %s", hex.EncodeToString(returned[:]), wantHash)
	}
}

// firstDifference names where two byte strings part company, or -1.
func firstDifference(got, want []byte) int {
	for index := 0; index < len(got) && index < len(want); index++ {
		if got[index] != want[index] {
			return index
		}
	}
	if len(got) != len(want) {
		return min(len(got), len(want))
	}
	return -1
}

// The stored attachment carries the bytes, so a restart still has the file.
//
// The receipt is a PROJECTION and never carries data, so asserting on it alone cannot tell a stored
// file from a stored husk. This reads what is actually on the node.
func TestAnUploadedFileIsOnTheNodeAndSurvivesARestart(t *testing.T) {
	server, dir := newStockServer(t)
	userID := adminID(t, server)
	path := leafFor(t, server, userID, "work/durable-files")

	contents := binaryPayload(4096)
	uploaded := uploadFile(t, server, userID, path, "durable.bin", contents)
	if uploaded.Code != http.StatusOK {
		t.Fatalf("POST /attachments/upload: got %d, want %d: %s",
			uploaded.Code, http.StatusOK, uploaded.Body.String())
	}
	var receipt attachmentView
	if err := json.Unmarshal(uploaded.Body.Bytes(), &receipt); err != nil {
		t.Fatalf("The upload receipt was not JSON: %v", err)
	}

	reloaded := reloadServer(t, dir)
	node, err := reloaded.getNodeFromPath(path)
	if err != nil {
		t.Fatalf("Failed to find the node after a restart: %v", err)
	}
	stored, err := node.GetAttachment(receipt.ID)
	if err != nil {
		t.Fatalf("The attachment is not on the node after a restart: %v", err)
	}
	if !bytes.Equal(stored.Data, contents) {
		t.Fatalf("The stored file is %d bytes, want %d", len(stored.Data), len(contents))
	}
	if stored.Size != int64(len(contents)) {
		t.Errorf("The stored file declares %d bytes, want %d", stored.Size, len(contents))
	}
	if stored.UploadedBy != userID {
		t.Errorf("The stored file names %q as its uploader, want %q", stored.UploadedBy, userID)
	}
	if stored.UploadedAt.IsZero() {
		t.Error("The stored file has no upload time")
	}
}

// BOTH upload routes go through one path, so they cannot answer differently about the same bytes.
func TestBothUploadRoutesStoreTheSameFileTheSameWay(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)
	path := leafFor(t, server, userID, "work/two-routes")

	if code := post(t, server.handleStartEvent, userID, map[string]interface{}{
		"path": path, "event_id": "shift",
	}).Code; code != http.StatusOK {
		t.Fatalf("Start an event: got %d, want %d", code, http.StatusOK)
	}
	if code := post(t, server.handleAppendToEvent, userID, map[string]interface{}{
		"path": path, "event_id": "shift", "content": "an entry to hang a file on",
	}).Code; code != http.StatusOK {
		t.Fatalf("Append to the event: got %d, want %d", code, http.StatusOK)
	}

	contents := binaryPayload(512)

	onNode := uploadFile(t, server, userID, path, "same.bin", contents)
	if onNode.Code != http.StatusOK {
		t.Fatalf("POST /attachments/upload: got %d, want %d: %s",
			onNode.Code, http.StatusOK, onNode.Body.String())
	}
	var nodeReceipt attachmentView
	if err := json.Unmarshal(onNode.Body.Bytes(), &nodeReceipt); err != nil {
		t.Fatalf("The node upload receipt was not JSON: %v", err)
	}

	body, contentType := uploadForm(t, "same.bin", contents, nil)
	request := withUser(httptest.NewRequest("POST",
		"/events/shift/entries/0/attachments?path="+path, body), userID)
	request.Header.Set("Content-Type", contentType)
	onEntry := httptest.NewRecorder()
	attachmentRouter(server).ServeHTTP(onEntry, request)
	if onEntry.Code != http.StatusOK {
		t.Fatalf("POST entry attachment: got %d, want %d: %s",
			onEntry.Code, http.StatusOK, onEntry.Body.String())
	}
	var entryReceipt attachmentView
	if err := json.Unmarshal(onEntry.Body.Bytes(), &entryReceipt); err != nil {
		t.Fatalf("The entry upload receipt was not JSON: %v", err)
	}

	if nodeReceipt.Hash != entryReceipt.Hash {
		t.Errorf("The two routes hashed the same bytes as %q and %q",
			nodeReceipt.Hash, entryReceipt.Hash)
	}
	if nodeReceipt.Size != entryReceipt.Size {
		t.Errorf("The two routes sized the same bytes as %d and %d",
			nodeReceipt.Size, entryReceipt.Size)
	}
	if nodeReceipt.ID != entryReceipt.ID {
		t.Errorf("The two routes identified the same bytes as %q and %q",
			nodeReceipt.ID, entryReceipt.ID)
	}

	node, err := server.getNodeFromPath(path)
	if err != nil {
		t.Fatalf("Failed to find the node: %v", err)
	}
	stored, err := node.GetEntryAttachment("shift", 0, entryReceipt.ID)
	if err != nil {
		t.Fatalf("The entry attachment is not on the entry: %v", err)
	}
	if !bytes.Equal(stored.Data, contents) {
		t.Fatalf("The entry file is %d bytes, want %d", len(stored.Data), len(contents))
	}
}

// A file over the cap is REFUSED, not accepted and lost.
//
// ParseMultipartForm's argument is a MEMORY budget — past it the form spills to a temporary file
// and parsing succeeds — so it never was a limit. The only real cap lived in AttachmentStore, which
// this route did not reach.
func TestAnUploadOverTheCapIsRefused(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)
	path := leafFor(t, server, userID, "work/oversized")

	contents := binaryPayload(int(core.MaxAttachmentSize) + 1)
	refused := uploadFile(t, server, userID, path, "too-big.bin", contents)
	if refused.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("POST /attachments/upload with %d bytes: got %d, want %d: %s",
			len(contents), refused.Code, http.StatusRequestEntityTooLarge, refused.Body.String())
	}

	node, err := server.getNodeFromPath(path)
	if err != nil {
		t.Fatalf("Failed to find the node: %v", err)
	}
	if len(node.Attachments) != 0 {
		t.Fatalf("A refused upload left %d attachments on the node", len(node.Attachments))
	}
}

// A file AT the cap is accepted whole. The refusal above has to be a limit and not an off-by-one
// that also turns away the largest legal file.
func TestAnUploadAtTheCapIsAcceptedWhole(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)
	path := leafFor(t, server, userID, "work/at-the-cap")

	contents := binaryPayload(int(core.MaxAttachmentSize))
	accepted := uploadFile(t, server, userID, path, "exact.bin", contents)
	if accepted.Code != http.StatusOK {
		t.Fatalf("POST /attachments/upload with %d bytes: got %d, want %d: %s",
			len(contents), accepted.Code, http.StatusOK, accepted.Body.String())
	}

	var receipt attachmentView
	if err := json.Unmarshal(accepted.Body.Bytes(), &receipt); err != nil {
		t.Fatalf("The upload receipt was not JSON: %v", err)
	}
	if receipt.Size != core.MaxAttachmentSize {
		t.Errorf("The receipt says %d bytes, want %d", receipt.Size, core.MaxAttachmentSize)
	}

	fetched := fetchFile(t, server, userID, path, receipt.ID)
	if fetched.Code != http.StatusOK {
		t.Fatalf("GET /attachments/%s: got %d, want %d", receipt.ID, fetched.Code, http.StatusOK)
	}
	if !bytes.Equal(fetched.Body.Bytes(), contents) {
		t.Fatalf("The file at the cap came back as %d bytes, want %d",
			fetched.Body.Len(), len(contents))
	}
}
