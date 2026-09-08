// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
// Non-commercial use only; see LICENSE.

// Tests for the constructor split and the three defects fixed alongside the event extraction.
//
// The constructor split lets an embedded runtime exist without a session signing key it has no
// sessions to sign, WITHOUT weakening the HTTP path's fail-closed rule. These assert both halves:
// the HTTP constructor still refuses without the key, the core constructor does not need it, and a
// core-only server cannot be Started because it has no HTTP server — the safety property holds by
// construction, not by a new guard.
package internal

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/NeoTecDigital/LumberJack/internal/core"
	"github.com/NeoTecDigital/LumberJack/types"
)

// withoutJWTSecret runs body with LUMBERJACK_JWT_SECRET unset, restoring it afterwards. The suite
// sets the key globally in TestMain, so a test about its absence has to take it away first.
func withoutJWTSecret(t *testing.T, body func()) {
	t.Helper()
	saved, had := os.LookupEnv(jwtSecretEnv)
	if err := os.Unsetenv(jwtSecretEnv); err != nil {
		t.Fatalf("failed to unset %s: %v", jwtSecretEnv, err)
	}
	defer func() {
		if had {
			os.Setenv(jwtSecretEnv, saved)
		}
	}()
	body()
}

// coreConfig is a config with no HTTP or disk dependencies, enough to build a core-only server.
func coreConfig() types.ServerConfig {
	return types.ServerConfig{
		Organization: "test_org",
		Process:      types.ProcessInfo{Name: "core_test", ServerPort: "0"},
	}
}

func TestNewServerRefusesWithoutJWTSecret(t *testing.T) {
	withoutJWTSecret(t, func() {
		server, err := NewServer(coreConfig(), core.User{Username: "admin", Password: "admin"})
		if err == nil {
			t.Fatalf("NewServer must fail closed without %s, got a server", jwtSecretEnv)
		}
		if server != nil {
			t.Fatalf("NewServer returned a server alongside its refusal")
		}
	})
}

func TestNewServerCoreSucceedsWithoutJWTSecret(t *testing.T) {
	withoutJWTSecret(t, func() {
		server := newServerCore(coreConfig())
		if server == nil {
			t.Fatal("newServerCore returned nil")
		}
		defer server.Shutdown(context.Background())
		// The core carries a forest, a state writer and a live runtime (queue, cache, mutation
		// stream); it carries no HTTP server and no signing key, which is exactly why it did not need
		// the env the HTTP constructor demands.
		if server.forest == nil {
			t.Error("newServerCore built no forest")
		}
		if server.stateWriter == nil {
			t.Error("newServerCore built no state writer")
		}
		if server.apiQueue == nil {
			t.Error("newServerCore built no worker queue; an embedded runtime needs one to serve reads")
		}
		if server.mutations == nil {
			t.Error("newServerCore built no mutation stream; an embedded runtime needs one to poll")
		}
		if server.server != nil {
			t.Error("newServerCore built an HTTP server; a core-only runtime must have none")
		}
	})
}

func TestStartRefusesCoreOnlyServer(t *testing.T) {
	withoutJWTSecret(t, func() {
		server := newServerCore(coreConfig())
		defer server.Shutdown(context.Background())
		// The safety property, asserted rather than newly guarded: a core-only server has no HTTP
		// server, and Start already refuses that.
		if err := server.Start(); err == nil {
			t.Fatal("Start must refuse a core-only server with no HTTP server")
		}
	})
}

func TestShutdownClosesCoreOnlyServer(t *testing.T) {
	// A core-only server is what Runtime.Close shuts down in the embedded path. Shutdown's very first
	// act is close(apiQueue.shutdown); if newServerCore had skipped startRuntime the queue would be
	// nil and this FIRST call would nil-panic — the shutdownOnce guard cannot help a panic on the
	// first call. It must tear down cleanly, and twice.
	server := newServerCore(coreConfig())
	if err := server.Shutdown(context.Background()); err != nil {
		t.Fatalf("first Shutdown of a core-only server errored: %v", err)
	}
	if err := server.Shutdown(context.Background()); err != nil {
		t.Fatalf("second Shutdown of a core-only server errored: %v", err)
	}
}

func TestShutdownTwiceDoesNotPanic(t *testing.T) {
	server := setupTestForest(t)

	// A C caller has every reason to be defensive and call Shutdown twice. The first call closes the
	// worker shutdown channel; without the sync.Once guard the second closes it again and panics on
	// close-of-closed-channel. Two calls in a row must both return cleanly.
	if err := server.Shutdown(context.Background()); err != nil {
		t.Fatalf("first Shutdown returned error: %v", err)
	}
	if err := server.Shutdown(context.Background()); err != nil {
		t.Fatalf("second Shutdown returned error: %v", err)
	}
}

func TestEndEventRequiresEventID(t *testing.T) {
	server := setupTestForest(t)
	defer server.Shutdown(context.Background())

	// /events/end had no event_id guard while /events/start and /events/plan did. An empty id used
	// to reach core.EndEvent, which answered "event not found" as a 500 — a server fault reported
	// for a request the caller malformed. It is a 400 now, matching the other two verbs.
	_, err := server.endEvent("admin", endEventRequest{Path: "test-node", EventID: ""})
	if err == nil {
		t.Fatal("endEvent accepted an empty event_id")
	}
	var carried *apiError
	if !errors.As(err, &carried) {
		t.Fatalf("endEvent error is not an apiError: %v", err)
	}
	if carried.status != 400 {
		t.Errorf("empty event_id must be 400, got %d", carried.status)
	}
	if carried.message != eventIDRequired {
		t.Errorf("message = %q, want %q", carried.message, eventIDRequired)
	}
}

func TestAppendedEntryGuardsMissingEvent(t *testing.T) {
	node := core.NewNode(core.LeafNode, "n")
	node.Events["present"] = core.Event{Entries: []core.Entry{{ID: "first"}, {ID: "second"}}}

	// The happy path: the last entry's id and its index.
	id, index, err := appendedEntry(node, "present")
	if err != nil {
		t.Fatalf("appendedEntry on a populated event errored: %v", err)
	}
	if id != "second" || index != 1 {
		t.Fatalf("appendedEntry = (%q, %d), want (\"second\", 1)", id, index)
	}

	// The guard: a map miss yields a zero Event whose Entries is nil, so len-1 is -1 and the old
	// blind index panicked. It must be an error, not a crash — a panic in a handler under a C caller
	// is a dead process, not a failed call.
	if _, _, err := appendedEntry(node, "absent"); err == nil {
		t.Fatal("appendedEntry did not guard a missing event")
	}
}
