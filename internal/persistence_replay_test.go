// Written by Richard Christopher, Copyright 2026 Richard Christopher

package internal

import (
	"net/http"
	"testing"

	"github.com/NeoTecDigital/LumberJack/types"
)

// What a failed write leaves behind, in both modes, as a client meets it over HTTP.
//
// A write whose persist fails is answered 5xx and stays in memory; the store reports itself
// behind its disk. Nothing written after it is acknowledged until it is durable too, and the
// first write that lands once the disk takes writes again carries it there. The disk is refused
// with refuseDisk.

// A workspace command whose write failed is in memory and not on the disk. A retry of the SAME
// client id finds its receipt and would answer the stored result — but the answer must wait for
// the write, in both modes: a 200 is a promise that the command is durable, and a kill before the
// next successful write would otherwise lose a command the caller was told it could forget.
func TestAReplayIsNotAcknowledgedUntilTheCommandIsDurable(t *testing.T) {
	inEachMode(t, replayWaitsForTheDisk)
}

func replayWaitsForTheDisk(t *testing.T, config types.ServerConfig) {
	server := newServerWith(t, config)
	token := storeAdmin(t, server)
	status, body := storeCall(t, server, token, "POST", "/nodes", map[string]string{"path": "work/a", "type": "leaf"})
	requireOK(t, "seed", status, body)

	restore := refuseDisk(t, server, config)
	command := workLog("log-while-down", "work/a", "written while the disk refused it")
	if status, body := storeCall(t, server, token, "POST", "/workspace/commands", command); status < 500 {
		t.Fatalf("the write landed on a read-only directory: %d %v", status, body)
	}
	if !server.persistBehind() {
		t.Fatal("the forest is not reported ahead of its store")
	}
	status, body = storeCall(t, server, token, "POST", "/workspace/commands", command)
	if status < 500 {
		t.Fatalf("a replay was acknowledged while the command was not durable: %d %v", status, body)
	}
	if got := entriesOn(server, "work/a"); got != 1 {
		t.Fatalf("the retry applied the command again: %d entries", got)
	}

	restore()
	status, body = storeCall(t, server, token, "POST", "/workspace/commands", command)
	if status != http.StatusOK || entriesOn(server, "work/a") != 1 {
		t.Fatalf("retry after the disk returned: %d %v, %d entries", status, body, entriesOn(server, "work/a"))
	}
	if server.persistBehind() {
		t.Fatal("the store is still reported behind after the replay was acknowledged")
	}

	// A kill after that 200 loses nothing: the reopened store holds the command.
	expected := fingerprint(server.forest)
	reopened := reopenWith(t, server, config, false)
	if got := fingerprint(reopened.forest); got != expected {
		t.Fatal("the reopened forest does not hold the replayed command")
	}
	status, body = storeCall(t, reopened, storeAdmin(t, reopened), "POST", "/workspace/commands", command)
	if status != http.StatusOK || entriesOn(reopened, "work/a") != 1 {
		t.Fatalf("replay after reopen: %d %v, %d entries", status, body, entriesOn(reopened, "work/a"))
	}
}

// "Until a write lands" is ANY write. No later write can be acknowledged without the failed one:
// in snapshot mode its file holds the whole forest, and in tiered mode its record is behind the
// failed one in the log. So while the disk refuses, a write by another route is answered 5xx too;
// once the disk takes writes again the next write lands and takes the failed ones with it, and a
// caller that no longer knows what failed needs nothing else.
func TestTheNextWriteThatLandsCarriesTheFailedOnes(t *testing.T) {
	inEachMode(t, nextWriteCarriesTheFailedOnes)
}

func nextWriteCarriesTheFailedOnes(t *testing.T, config types.ServerConfig) {
	server := newServerWith(t, config)
	token := storeAdmin(t, server)
	status, body := storeCall(t, server, token, "POST", "/nodes", map[string]string{"path": "work/a", "type": "leaf"})
	requireOK(t, "seed", status, body)

	restore := refuseDisk(t, server, config)
	if status, body := storeCall(t, server, token, "PATCH", "/nodes/work/a/metadata", map[string]interface{}{"label": "answered 500"}); status < 500 {
		t.Fatalf("a write whose persist failed: %d %v", status, body)
	}
	if status, body := storeCall(t, server, token, "POST", "/nodes", map[string]string{"path": "work/b", "type": "leaf"}); status < 500 {
		t.Fatalf("a later write was acknowledged while an earlier one was not durable: %d %v", status, body)
	}
	if !server.persistBehind() {
		t.Fatal("the forest is not reported ahead of its store")
	}

	restore()
	status, body = storeCall(t, server, token, "POST", "/nodes", map[string]string{"path": "work/c", "type": "leaf"})
	requireOK(t, "a write once the disk returned", status, body)
	if server.persistBehind() {
		t.Fatal("the store is still reported behind after a write landed")
	}

	expected := fingerprint(server.forest)
	reopened := reopenWith(t, server, config, false)
	if got := fingerprint(reopened.forest); got != expected {
		t.Fatal("the reopened forest does not hold the writes that were answered 5xx")
	}
	node, err := reopened.getNodeFromPath("work/a")
	if err != nil || node.Metadata["label"] != "answered 500" {
		t.Fatalf("the metadata answered 500 did not reach the disk: %v %v", err, node)
	}
	for _, path := range []string{"work/b", "work/c"} {
		if _, err := reopened.getNodeFromPath(path); err != nil {
			t.Fatalf("%s is not on the disk: %v", path, err)
		}
	}
}
