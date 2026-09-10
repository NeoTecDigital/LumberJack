// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
// Non-commercial use only; see LICENSE.

// The bounds that keep one caller, or one crafted file, from consuming the process without limit:
// the gzip decompression cap, the worker-queue admission timeout, and the served HTTP timeouts.
package internal

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

// maxPageLimit is REFUSED rather than clamped, which is only a meaningful promise at its edge: the
// declared maximum must be accepted and one past it refused. Nothing tested either, so the bound
// could have been off by one — or silently clamping — with the whole suite green.
func TestResolvePageAtAndPastTheMaximum(t *testing.T) {
	limit, _, err := resolvePage(&pageRequest{Limit: maxPageLimit})
	if err != nil {
		t.Fatalf("resolvePage(%d) refused the declared maximum: %v", maxPageLimit, err)
	}
	if limit != maxPageLimit {
		t.Fatalf("resolvePage(%d) = %d; the maximum must be honoured whole, not clamped", maxPageLimit, limit)
	}

	// One past it is a 400 the caller is answerable for, not a silently smaller page.
	_, _, err = resolvePage(&pageRequest{Limit: maxPageLimit + 1})
	if err == nil {
		t.Fatalf("resolvePage(%d) was accepted; a caller that asked for more than the maximum and "+
			"quietly received it would page as if it had them all", maxPageLimit+1)
	}
	var carried *apiError
	if !asAPIError(err, &carried) || carried.Status() != http.StatusBadRequest {
		t.Fatalf("a limit past the maximum answered %v, want a 400", err)
	}

	// A NEGATIVE limit is its own refusal, and must not be read as "unlimited" or reach the slicing
	// arithmetic in paginate, where start+limit would run backwards.
	_, _, err = resolvePage(&pageRequest{Limit: -1})
	if err == nil {
		t.Fatal("resolvePage(-1) was accepted; a negative limit reaches paginate's start+limit arithmetic")
	}
	if !asAPIError(err, &carried) || carried.Status() != http.StatusBadRequest {
		t.Fatalf("a negative limit answered %v, want a 400", err)
	}

	// Zero is not a refusal — it means "unstated" and takes the default.
	if limit, _, err := resolvePage(&pageRequest{Limit: 0}); err != nil || limit != defaultPageLimit {
		t.Fatalf("resolvePage(0) = (%d, %v), want (%d, nil)", limit, err, defaultPageLimit)
	}
}

// The bound is only real if it survives the whole query path, not just the helper that computes it.
func TestQueryRefusesAPageLimitPastTheMaximum(t *testing.T) {
	server, _ := newStockServer(t)
	defer server.Shutdown(context.Background())
	userID := adminID(t, server)

	if _, err := server.runQuery(userID, queryRequest{
		Select: selectNodes, Page: &pageRequest{Limit: maxPageLimit},
	}); err != nil {
		t.Fatalf("a query at the declared page maximum was refused: %v", err)
	}

	_, err := server.runQuery(userID, queryRequest{
		Select: selectNodes, Page: &pageRequest{Limit: maxPageLimit + 1},
	})
	if err == nil {
		t.Fatalf("a query asking for %d rows was served; the bound does not reach the query surface",
			maxPageLimit+1)
	}
	var carried *apiError
	if !asAPIError(err, &carried) || carried.Status() != http.StatusBadRequest {
		t.Fatalf("an over-limit query answered %v, want a 400", err)
	}
}

// The worker pool's two declared numbers, pinned. They are the whole reason a full queue is
// reachable at all — one hundred slots and five drainers for EVERY client of the process — and
// nothing anywhere states them, so a change to either would move the saturation point silently.
func TestAPIQueueIsAHundredDeepBehindFiveWorkers(t *testing.T) {
	server := newServerCore(coreConfig())
	defer server.Shutdown(context.Background())

	if got := cap(server.apiQueue.queue); got != 100 {
		t.Errorf("the API queue is %d deep, want 100", got)
	}
	if got := server.apiQueue.workers; got != 5 {
		t.Errorf("the API queue has %d workers, want 5", got)
	}
}

// A SATURATED pool answers errServerBusy through the real read path, not just through enqueue.
//
// This is the only place a 429 is produced by the engine at all, and it is what the FFI's LJ_BUSY
// is mapped from. The queue is filled to its declared depth with no worker able to take anything,
// so the read cannot be admitted, cannot see a teardown, and must come back busy — carrying 429 —
// within apiQueueSendTimeout rather than pinning the caller.
func TestQueuedNodeViewAnswersBusyWhenThePoolIsSaturated(t *testing.T) {
	server := newServerCore(coreConfig())
	defer server.Shutdown(context.Background())

	// Replace the pool with one that has the production depth and NO workers, so nothing drains it.
	// Stopping the real workers first keeps them from consuming the fill.
	close(server.apiQueue.shutdown)
	server.apiQueue.wg.Wait()
	server.apiQueue = &APIQueue{queue: make(chan APIRequest, 100), workers: 0, shutdown: make(chan struct{})}
	for i := 0; i < 100; i++ {
		server.apiQueue.queue <- APIRequest{}
	}

	done := make(chan error, 1)
	start := time.Now()
	go func() {
		_, err := server.queuedNodeView("forest", SystemUserID)
		done <- err
	}()

	select {
	case err := <-done:
		if err != errServerBusy {
			t.Fatalf("a read against a saturated pool returned %v, want errServerBusy", err)
		}
		var carried *apiError
		if !asAPIError(err, &carried) || carried.Status() != http.StatusTooManyRequests {
			t.Fatalf("the busy read's error carries %v, want a 429 so the FFI reads it as LJ_BUSY", err)
		}
		if waited := time.Since(start); waited < apiQueueSendTimeout {
			t.Fatalf("the read gave up after %v, before the %v admission window", waited, apiQueueSendTimeout)
		}
	case <-time.After(apiQueueSendTimeout + 5*time.Second):
		t.Fatal("a read against a saturated pool never returned: the send is unbounded and pinned the caller")
	}

	// Restore a queue Shutdown can close exactly once.
	server.apiQueue = &APIQueue{queue: make(chan APIRequest, 1), shutdown: make(chan struct{})}
}

// One long log line does NOT fell the whole GET /logs read. bufio.Scanner refuses a token past its
// 64 KiB buffer, and updateLogCache once returned that refusal — so a single line long enough to trip
// it made GET /logs a 500 for the ENTIRE file, and every good line behind the long one went unread. A
// log line is now read whole however long it is, which is what a caller produces merely by logging a
// large %v-formatted argument (a stack trace, a marshalled request). The file is this process's own
// and is already read into memory in full, so a long line costs no bound the read did not already
// have.
//
// This REPLACES TestOneLongLogLineFailsTheWholeLogRead, which asserted the opposite — that an
// over-long line reported bufio.ErrTooLong, abandoned the whole file (0 entries), and POISONED the
// cache by stamping LastOffset and LastModTime on the way out.
func TestOneLongLogLineDoesNotFailTheWholeLogRead(t *testing.T) {
	dir := t.TempDir()
	server := newServerInDirs(t, dir, dir)
	defer server.Shutdown(context.Background())

	logPath := server.logFilePath()
	if logPath == "" {
		t.Fatal("the stock server has no log file to page")
	}

	const prefix = "2024/01/02 03:04:05 " // the fixed-width stamp splitLogTimestamp reads
	writeTwoLines := func(t *testing.T, firstLen int) {
		t.Helper()
		file, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			t.Fatalf("open the log file: %v", err)
		}
		body := strings.Repeat("A", firstLen-len(prefix))
		if _, err := fmt.Fprintf(file, "%s%s\n%sa line after the long one\n", prefix, body, prefix); err != nil {
			t.Fatalf("write the log file: %v", err)
		}
		file.Close()
		server.logCache = &LogCache{PageSize: 100, Logs: make([]LogEntry, 0)}
	}

	// A line well PAST bufio.Scanner's 64 KiB token limit — the exact size that used to fell the whole
	// read — is now read whole, and the good line behind it is reached.
	overTheOldCliff := bufio.MaxScanTokenSize + 4096
	writeTwoLines(t, overTheOldCliff)
	if err := server.updateLogCache(""); err != nil {
		t.Fatalf("a %d-byte line failed the read: %v — one long line must not fell the endpoint", overTheOldCliff, err)
	}
	if got := len(server.logCache.Logs); got != 2 {
		t.Fatalf("a %d-byte line yielded %d entries, want 2 (the long line AND the one behind it)", overTheOldCliff, got)
	}

	// The resume point is stamped only after a clean read, and to the END of the file — so a second
	// refresh over the same unchanged file adds nothing rather than re-reading or skipping.
	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("stat the log file: %v", err)
	}
	if server.logCache.LastOffset != info.Size() {
		t.Fatalf("LastOffset is %d after a clean read, want the file size %d", server.logCache.LastOffset, info.Size())
	}
	if !server.logCache.LastModTime.Equal(info.ModTime()) {
		t.Fatalf("LastModTime is %v, want the file's %v", server.logCache.LastModTime, info.ModTime())
	}
}

// A FAILED log read leaves the resume point untouched. updateLogCache once stamped LastOffset and
// LastModTime BEFORE it returned the read error, so a failure advanced the resume point past bytes it
// never delivered and marked the file already-seen — which refreshLogCache then short-circuits on,
// making the unread tail unrecoverable by any later read. The stamp now happens only after a clean
// read.
//
// A directory in the log file's place is the injection: os.Stat and os.Open both succeed on it, and
// the read fails only once updateLogCache is scanning — the one shape that reaches the ordering the
// fix is about. It is planted before the server is built, so the logger falls back to stderr and the
// server still comes up.
func TestAFailedLogReadLeavesTheResumePointUntouched(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "stock_process.log"), 0o700); err != nil {
		t.Fatalf("plant a directory in the log file's place: %v", err)
	}
	server := newServerInDirs(t, dir, dir)
	defer server.Shutdown(context.Background())

	if got := server.logFilePath(); got != filepath.Join(dir, "stock_process.log") {
		t.Fatalf("the log file path is %q, not the planted directory", got)
	}

	// A resume point from an earlier good read. The failing read must move neither field.
	seenAt := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	server.logCache = &LogCache{PageSize: 100, Logs: make([]LogEntry, 0), LastOffset: 4096, LastModTime: seenAt}

	if err := server.updateLogCache(""); err == nil {
		t.Fatal("reading a directory as a log file reported no error")
	}
	if server.logCache.LastOffset != 4096 {
		t.Fatalf("a failed read moved LastOffset to %d, want it left at 4096 — the resume point must "+
			"not advance past bytes a failed read never delivered", server.logCache.LastOffset)
	}
	if !server.logCache.LastModTime.Equal(seenAt) {
		t.Fatalf("a failed read stamped LastModTime to %v, want it left at %v — a stamped failure reads "+
			"as an up-to-date log and refreshLogCache short-circuits on it", server.logCache.LastModTime, seenAt)
	}
}
