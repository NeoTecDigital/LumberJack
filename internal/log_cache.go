package internal

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// The in-memory view of the log file that GET /logs pages: reading it, parsing a line of it into a
// LogEntry, and handing out a page of the result.

func (server *Server) getPaginatedLogs(page int) ([]LogEntry, bool) {
	server.logCache.mutex.RLock()
	defer server.logCache.mutex.RUnlock()

	start := (page - 1) * server.logCache.PageSize
	end := start + server.logCache.PageSize

	if start >= len(server.logCache.Logs) {
		return []LogEntry{}, false
	}

	if end > len(server.logCache.Logs) {
		end = len(server.logCache.Logs)
	}

	hasMore := end < len(server.logCache.Logs)
	return server.logCache.Logs[start:end], hasMore
}

func (server *Server) updateLogCache(level string) error {
	server.logCache.mutex.Lock()
	defer server.logCache.mutex.Unlock()

	logPath := server.logFilePath()
	if logPath == "" {
		return errNoLogFile
	}

	fileInfo, err := os.Stat(logPath)
	if err != nil {
		return err
	}

	// Only read new content since last update
	file, err := os.Open(logPath)
	if err != nil {
		return err
	}
	defer file.Close()

	// If cache exists, seek to last read position
	if server.logCache.LastOffset > 0 {
		file.Seek(server.logCache.LastOffset, 0)
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		entry, err := server.parseLogEntry(scanner.Text(), level)
		if err != nil {
			continue // Skip invalid entries
		}
		if entry != nil { // nil means filtered out by level
			server.logCache.Logs = append(server.logCache.Logs, *entry)
		}
	}

	// Update cache metadata
	server.logCache.LastOffset, _ = file.Seek(0, io.SeekCurrent)
	server.logCache.LastModTime = fileInfo.ModTime()

	return scanner.Err()
}

// Initialize cache only when needed
func (server *Server) initLogCacheIfNeeded() {
	if server.logCache == nil {
		server.logCache = &LogCache{
			PageSize: 100,
			Logs:     make([]LogEntry, 0),
		}
	}
}

// logTimestampLayout is the stdlib default log prefix, which is the format the file logger writes
// and therefore the only one that ever appears in the file.
const logTimestampLayout = "2006/01/02 15:04:05"

// logLevelSymbols maps the glyph a LogInfo prints to the level name it stands for. It is one shared
// table rather than a map literal rebuilt for every line of every read of the file.
//
// No symbol is a prefix of another, so the single first-match-wins scan over it has one answer
// regardless of the order the runtime happens to range in.
var logLevelSymbols = map[string]string{
	"ℹ": "INFO",
	"✓": "SUCCESS",
	"✗": "FAILURE",
	"🔍": "DEBUG",
	"📝": "NOTICE",
	"⚠": "WARNING",
	"❌": "ERROR",
	"🔥": "CRITICAL",
	"🚨": "ALERT",
	"💀": "EMERGENCY",
}

// parseLogEntry turns one written line back into the entry GET /logs serves.
//
// It reports (nil, nil) for a line that the requested level filters out, which is not an error, and
// (nil, err) for a line that is not a log line at all.
func (server *Server) parseLogEntry(line string, level string) (*LogEntry, error) {
	timestamp, remainder, err := splitLogTimestamp(line)
	if err != nil {
		return nil, err
	}

	indent := countTreeIndent(remainder)
	logLevel, content, entryType := classifyLogMessage(strings.TrimLeft(remainder, "│└┌─ "))

	// Filter by level if specified
	if level != "" && !strings.EqualFold(level, logLevel) {
		return nil, nil
	}

	return &LogEntry{
		Timestamp: timestamp,
		Level:     logLevel,
		Message:   content,
		Type:      entryType,
		Indent:    indent,
	}, nil
}

// splitLogTimestamp reads the fixed-width timestamp off the front of a line and returns the rest.
func splitLogTimestamp(line string) (time.Time, string, error) {
	if len(line) < len(logTimestampLayout) {
		return time.Time{}, "", fmt.Errorf("line too short")
	}

	timestamp, err := time.Parse(logTimestampLayout, line[:len(logTimestampLayout)])
	if err != nil {
		return time.Time{}, "", fmt.Errorf("invalid timestamp: %v", err)
	}

	return timestamp, strings.TrimSpace(line[len(logTimestampLayout):]), nil
}

// countTreeIndent counts the leading box-drawing characters, which are how the logger records how
// deep in its Enter/Exit nesting the line was written.
func countTreeIndent(remainder string) int {
	count := 0
	for _, char := range remainder {
		if char != '│' && char != '└' && char != '┌' && char != '─' {
			break
		}
		count++
	}
	return count
}

// classifyLogMessage reads a message stripped of its tree characters and says what kind of line it
// is: the span markers Enter and Exit write, or an ordinary line carrying a level glyph. A line
// with neither is INFO, which is what an unprefixed line has always been reported as.
func classifyLogMessage(message string) (level, content, entryType string) {
	if strings.HasPrefix(message, "BEGIN:") {
		return "INFO", strings.TrimSpace(strings.TrimPrefix(message, "BEGIN:")), "begin"
	}
	if strings.HasPrefix(message, "END:") {
		return "INFO", strings.TrimSpace(strings.TrimPrefix(message, "END:")), "end"
	}

	for symbol, symbolLevel := range logLevelSymbols {
		if strings.HasPrefix(message, symbol) {
			return symbolLevel, strings.TrimSpace(strings.TrimPrefix(message, symbol)), "message"
		}
	}

	return "INFO", message, "message"
}
