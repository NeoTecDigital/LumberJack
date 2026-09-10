// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
// Non-commercial use only; see LICENSE.

// The bounds that keep one caller, or one crafted file, from consuming the process without limit:
// the gzip decompression cap, the worker-queue admission timeout, and the served HTTP timeouts.
package internal

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// gzipOf compresses payload so a test can feed readCappedGzip a real gzip stream.
func gzipOf(t *testing.T, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(payload); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

// readCappedGzip refuses a stream that decompresses past its limit — the decompression-bomb defense.
// A small limit stands in for the 1 GiB production ceiling so the boundary is testable: a payload
// one byte over is rejected, and one exactly at the limit is returned whole.
func TestReadCappedGzipRefusesABomb(t *testing.T) {
	const limit = 1024
	over := gzipOf(t, bytes.Repeat([]byte("A"), limit+1))
	if _, err := readCappedGzip(bytes.NewReader(over), limit); err == nil {
		t.Fatalf("readCappedGzip accepted a stream past its limit; an unbounded io.ReadAll is a decompression bomb")
	}
}

func TestReadCappedGzipReturnsExactlyAtLimit(t *testing.T) {
	const limit = 1024
	payload := bytes.Repeat([]byte("A"), limit)
	data, err := readCappedGzip(bytes.NewReader(gzipOf(t, payload)), limit)
	if err != nil {
		t.Fatalf("readCappedGzip rejected a stream exactly at its limit: %v", err)
	}
	if !bytes.Equal(data, payload) {
		t.Fatalf("readCappedGzip returned %d bytes, want %d intact", len(data), len(payload))
	}
}

// enqueue must not block forever on a full queue. With a queue of capacity two and no workers to
// drain it, a third send cannot proceed, cannot see a shutdown, and must return errServerBusy within
// its timeout rather than pinning the caller. Without the timeout case this send blocks forever and
// the test times out on the guard below.
func TestEnqueueBoundsAFullQueue(t *testing.T) {
	server := &Server{apiQueue: &APIQueue{
		queue:    make(chan APIRequest, 2),
		shutdown: make(chan struct{}),
	}}
	server.apiQueue.queue <- APIRequest{}
	server.apiQueue.queue <- APIRequest{}

	done := make(chan error, 1)
	go func() { done <- server.enqueue(APIRequest{}, 20*time.Millisecond) }()

	select {
	case err := <-done:
		if err != errServerBusy {
			t.Fatalf("enqueue on a full queue returned %v, want errServerBusy", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("enqueue did not return on a full queue: the send is unbounded and pinned the caller")
	}
}

// A free slot is taken at once, and a torn-down pool is reported rather than waited on — the other
// two arms of the bounded send.
func TestEnqueueAcceptsAndReportsShutdown(t *testing.T) {
	server := &Server{apiQueue: &APIQueue{
		queue:    make(chan APIRequest, 1),
		shutdown: make(chan struct{}),
	}}
	if err := server.enqueue(APIRequest{}, time.Second); err != nil {
		t.Fatalf("enqueue into a free slot returned %v, want nil", err)
	}

	close(server.apiQueue.shutdown) // queue is now full AND shutting down
	if err := server.enqueue(APIRequest{}, time.Second); err != errServerShuttingDown {
		t.Fatalf("enqueue during teardown returned %v, want errServerShuttingDown", err)
	}
}

// errServerBusy must carry 429, not 503: the FFI's statusForError distinguishes a saturated pool
// (LJ_BUSY) from a tearing-down runtime (LJ_CLOSED) by exactly this code, across a package boundary
// it cannot reach into. Revert this to 503 and a busy server silently reports LJ_CLOSED again.
func TestErrServerBusyCarries429(t *testing.T) {
	if got := errServerBusy.Status(); got != http.StatusTooManyRequests {
		t.Fatalf("errServerBusy status = %d, want 429 so the FFI maps it to LJ_BUSY", got)
	}
}

// A 429 SHOULD carry Retry-After (RFC 6585 §4); a 503 (shutting down) carries none. The header has to
// be set before http.Error freezes the header block, which is what writeAPIError does.
func TestWriteAPIErrorSetsRetryAfterOnBusy(t *testing.T) {
	busy := httptest.NewRecorder()
	writeAPIError(busy, errServerBusy)
	if busy.Code != http.StatusTooManyRequests {
		t.Fatalf("busy response code = %d, want 429", busy.Code)
	}
	if got := busy.Header().Get("Retry-After"); got != retryAfterBusySeconds {
		t.Fatalf("Retry-After = %q, want %q (RFC 6585 §4)", got, retryAfterBusySeconds)
	}

	shutting := httptest.NewRecorder()
	writeAPIError(shutting, errServerShuttingDown)
	if got := shutting.Header().Get("Retry-After"); got != "" {
		t.Fatalf("Retry-After = %q on a 503, want none — only the 429 busy path carries it", got)
	}
}

// The served HTTP server bounds a slow client on the read side, and deliberately does NOT bound the
// write side because /stream holds one SSE response open for a subscription's whole life. Without
// the fix these are all zero — the slowloris door is open.
func TestNewHTTPServerBoundsSlowClients(t *testing.T) {
	srv := newHTTPServer(coreConfig())

	if srv.ReadHeaderTimeout <= 0 {
		t.Fatal("ReadHeaderTimeout is unset: a client that dribbles headers is never cut (slowloris)")
	}
	if srv.ReadTimeout <= 0 {
		t.Fatal("ReadTimeout is unset: a slow request body is never cut")
	}
	if srv.IdleTimeout <= 0 {
		t.Fatal("IdleTimeout is unset: an idle keep-alive is held forever")
	}
	if srv.MaxHeaderBytes <= 0 {
		t.Fatal("MaxHeaderBytes is unset: the header block is unbounded")
	}
	if srv.WriteTimeout != 0 {
		t.Fatalf("WriteTimeout = %v, want 0: a write deadline would sever every live /stream feed", srv.WriteTimeout)
	}
}
