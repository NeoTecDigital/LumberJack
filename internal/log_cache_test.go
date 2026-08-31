package internal

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"
)

// The log reader and the log route had no unit coverage at all, which is what made splitting them
// into smaller pieces unverifiable. These pin the behaviour the split had to preserve: what one
// written line parses into, what the level filter does, and how a page is cut.

// One written line becomes one entry, of the kind the writer meant.
func TestParseLogEntryReadsWhatTheLoggerWrites(t *testing.T) {
	server, _ := newStockServer(t)

	for _, testCase := range []struct {
		name    string
		line    string
		level   string
		content string
		kind    string
		indent  int
	}{
		{"info glyph", "2024/01/02 03:04:05 ℹ a plain message", "INFO", "a plain message", "message", 0},
		{"success glyph", "2024/01/02 03:04:05 ✓ it worked", "SUCCESS", "it worked", "message", 0},
		{"failure glyph", "2024/01/02 03:04:05 ✗ it did not", "FAILURE", "it did not", "message", 0},
		{"debug glyph", "2024/01/02 03:04:05 🔍 a detail", "DEBUG", "a detail", "message", 0},
		{"notice glyph", "2024/01/02 03:04:05 📝 noted", "NOTICE", "noted", "message", 0},
		{"warning glyph", "2024/01/02 03:04:05 ⚠ careful", "WARNING", "careful", "message", 0},
		{"error glyph", "2024/01/02 03:04:05 ❌ broken", "ERROR", "broken", "message", 0},
		{"critical glyph", "2024/01/02 03:04:05 🔥 on fire", "CRITICAL", "on fire", "message", 0},
		{"alert glyph", "2024/01/02 03:04:05 🚨 wake up", "ALERT", "wake up", "message", 0},
		{"emergency glyph", "2024/01/02 03:04:05 💀 over", "EMERGENCY", "over", "message", 0},
		{"span open", "2024/01/02 03:04:05 ┌─ BEGIN: NewServer", "INFO", "NewServer", "begin", 2},
		{"span close", "2024/01/02 03:04:05 └─ END: NewServer", "INFO", "NewServer", "end", 2},
		// Indent counts CONSECUTIVE box characters and stops at the first space, so the logger's
		// "│  " units count as one however many there are. That is what this has always done; it is
		// recorded here as the behaviour the split had to preserve, not endorsed.
		{"nested", "2024/01/02 03:04:05 │  │  ℹ two deep", "INFO", "two deep", "message", 1},
		{"no glyph", "2024/01/02 03:04:05 bare text", "INFO", "bare text", "message", 0},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			entry, err := server.parseLogEntry(testCase.line, "")
			if err != nil {
				t.Fatalf("Failed to parse %q: %v", testCase.line, err)
			}
			if entry == nil {
				t.Fatalf("%q parsed to nothing", testCase.line)
			}

			if entry.Level != testCase.level {
				t.Errorf("Level is %q, want %q", entry.Level, testCase.level)
			}
			if entry.Message != testCase.content {
				t.Errorf("Message is %q, want %q", entry.Message, testCase.content)
			}
			if entry.Type != testCase.kind {
				t.Errorf("Type is %q, want %q", entry.Type, testCase.kind)
			}
			if entry.Indent != testCase.indent {
				t.Errorf("Indent is %d, want %d", entry.Indent, testCase.indent)
			}
			if want := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC); !entry.Timestamp.Equal(want) {
				t.Errorf("Timestamp is %v, want %v", entry.Timestamp, want)
			}
		})
	}
}

// A line that is not a log line is an error; a line the level filter excludes is not.
func TestParseLogEntryTellsRefusalFromFiltering(t *testing.T) {
	server, _ := newStockServer(t)

	for _, line := range []string{"", "short", "not a timestamp at all"} {
		if _, err := server.parseLogEntry(line, ""); err == nil {
			t.Errorf("%q was accepted as a log line", line)
		}
	}

	line := "2024/01/02 03:04:05 ⚠ careful"

	entry, err := server.parseLogEntry(line, "warning")
	if err != nil || entry == nil {
		t.Fatalf("A matching level filter dropped the line: entry=%v err=%v", entry, err)
	}

	entry, err = server.parseLogEntry(line, "ERROR")
	if err != nil {
		t.Errorf("A non-matching level filter reported an error: %v", err)
	}
	if entry != nil {
		t.Errorf("A non-matching level filter returned %+v", entry)
	}
}

// A page is 100 entries, the last page says there is no more, and a page past the end is empty
// rather than a fault.
func TestPageOfLogsCutsAPage(t *testing.T) {
	entries := make([]LogEntry, 250)
	for i := range entries {
		entries[i] = LogEntry{Message: fmt.Sprintf("entry-%d", i)}
	}

	for _, testCase := range []struct {
		page    int
		count   int
		first   string
		hasMore bool
	}{
		{1, 100, "entry-0", true},
		{2, 100, "entry-100", true},
		{3, 50, "entry-200", false},
		{4, 0, "", false},
		{99, 0, "", false},
	} {
		logs, hasMore := pageOfLogs(entries, testCase.page)
		if len(logs) != testCase.count {
			t.Errorf("Page %d holds %d entries, want %d", testCase.page, len(logs), testCase.count)
		}
		if testCase.count > 0 && logs[0].Message != testCase.first {
			t.Errorf("Page %d starts at %q, want %q", testCase.page, logs[0].Message, testCase.first)
		}
		if hasMore != testCase.hasMore {
			t.Errorf("Page %d reports has_more %v, want %v", testCase.page, hasMore, testCase.hasMore)
		}
	}
}

// last_event_id hands back only what the caller has not seen. An id that is not a number is ignored
// rather than refused: the caller gets everything, exactly as if it had sent none.
func TestLogsAfterNarrowsToUnseenEntries(t *testing.T) {
	server, _ := newStockServer(t)
	server.initLogCacheIfNeeded()

	base := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	server.logCache.Logs = []LogEntry{
		{Message: "first", Timestamp: base},
		{Message: "second", Timestamp: base.Add(time.Second)},
		{Message: "third", Timestamp: base.Add(2 * time.Second)},
	}

	if got := server.logsAfter(""); len(got) != 3 {
		t.Errorf("No id returned %d entries, want 3", len(got))
	}

	got := server.logsAfter(fmt.Sprint(base.UnixNano()))
	if len(got) != 2 || got[0].Message != "second" {
		t.Errorf("Filtering after the first entry returned %+v", got)
	}

	if got := server.logsAfter(fmt.Sprint(base.Add(time.Hour).UnixNano())); len(got) != 0 {
		t.Errorf("Filtering after everything returned %+v", got)
	}

	if got := server.logsAfter("not-a-number"); len(got) != 3 {
		t.Errorf("An unparseable id returned %d entries, want all 3", len(got))
	}
}

// The route itself pages, and reports the page that follows.
func TestLogsRoutePagesTheFile(t *testing.T) {
	server, _ := newStockServer(t)
	adminUserID := adminID(t, server)

	// Enough lines that a second page has to exist. They go into the real file, through the real
	// logger, so what is under test is the whole read path and not a hand-built cache.
	for i := 0; i < 250; i++ {
		server.logger.Info("a line to page over: %d", i)
	}
	if _, err := os.Stat(server.logFilePath()); err != nil {
		t.Fatalf("No log file was written: %v", err)
	}

	first := decodeLogsPage(t, server, adminUserID, "/logs?page=1")
	if len(first.Logs) != logsPageSize {
		t.Errorf("Page 1 holds %d entries, want %d", len(first.Logs), logsPageSize)
	}
	if !first.HasMore {
		t.Fatal("Page 1 reports no further pages over a file of 250 lines")
	}
	if first.NextPage != 2 {
		t.Errorf("Page 1 points at page %d, want 2", first.NextPage)
	}

	second := decodeLogsPage(t, server, adminUserID, "/logs?page=2")
	if len(second.Logs) != logsPageSize {
		t.Errorf("Page 2 holds %d entries, want %d", len(second.Logs), logsPageSize)
	}
	if len(second.Logs) > 0 && len(first.Logs) > 0 && second.Logs[0] == first.Logs[0] {
		t.Error("Page 2 starts where page 1 does")
	}

	// A page past the end is empty and final, not a fault.
	past := decodeLogsPage(t, server, adminUserID, "/logs?page=9999")
	if len(past.Logs) != 0 || past.HasMore || past.NextPage != 0 {
		t.Errorf("A page past the end reported %d entries, has_more %v, next_page %d",
			len(past.Logs), past.HasMore, past.NextPage)
	}
}

type logsPage struct {
	Logs     []LogEntry `json:"logs"`
	HasMore  bool       `json:"has_more"`
	NextPage int        `json:"next_page"`
}

func decodeLogsPage(t *testing.T, server *Server, userID, target string) logsPage {
	t.Helper()

	recorder := get(t, server.handleGetLogs, userID, target)
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET %s: got %d, want %d: %s", target, recorder.Code, http.StatusOK, recorder.Body.String())
	}

	var page logsPage
	if err := json.Unmarshal(recorder.Body.Bytes(), &page); err != nil {
		t.Fatalf("Failed to decode %q: %v", recorder.Body.String(), err)
	}
	return page
}
