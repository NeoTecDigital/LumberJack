package internal

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strconv"
)

// The log route, which pages the file this process writes.

// errNoLogFile is what the log machinery reports when this install has no log file to page. It is a
// 404, not a fault: there is nothing wrong with a server that was not configured to log to disk.
var errNoLogFile = errors.New("no log file is configured for this server")

// logsPageSize is how many entries one page of GET /logs carries.
const logsPageSize = 100

// handleGetLogs pages the process log.
//
// It answered 500 ON EVERY CALL, on every install, forever: it stats {LogPath}/{ID}.log and nothing
// opened that file — the logger wrote to standard error only. The logger now opens a real sink when
// a log path is configured, and this route answers 404 when one is not, rather than reporting a
// guaranteed condition as a server fault.
//
// It is an ADMIN route. The file names users, paths and failures, and now that it genuinely exists
// it is operator data rather than a route that could never return anything.
func (server *Server) handleGetLogs(w http.ResponseWriter, r *http.Request) {
	if _, ok := server.requireAdmin(w, r); !ok {
		return
	}

	server.initLogCacheIfNeeded()

	query := r.URL.Query()
	page := pageNumber(query.Get("page"))
	level := query.Get("level")

	if status, err := server.refreshLogCache(level); err != nil {
		http.Error(w, err.Error(), status)
		return
	}

	entries := server.logsAfter(query.Get("last_event_id"))
	logs, hasMore := pageOfLogs(entries, page)

	response := struct {
		Logs    []LogEntry `json:"logs"`
		HasMore bool       `json:"has_more"`

		NextPage int `json:"next_page,omitempty"`
	}{
		Logs:    logs,
		HasMore: hasMore,
	}
	if hasMore {
		response.NextPage = page + 1
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// pageNumber reads the requested page. Anything that is not a page — absent, unparseable, zero,
// negative — is the first one.
func pageNumber(raw string) int {
	page, _ := strconv.Atoi(raw)
	if page < 1 {
		return 1
	}
	return page
}

// refreshLogCache brings the cache up to date with the file, and reports the HTTP status that goes
// with a failure to do so.
//
// A server configured with nowhere to log, and one whose log file has not been written yet, are both
// 404: there is no resource, and neither is a fault of the server. Only an unreadable file is a 500.
func (server *Server) refreshLogCache(level string) (int, error) {
	logPath := server.logFilePath()
	if logPath == "" {
		return http.StatusNotFound, errNoLogFile
	}

	fileInfo, err := os.Stat(logPath)
	if errors.Is(err, os.ErrNotExist) {
		// Configured, but nothing has been written yet. That is a missing resource, not a fault.
		return http.StatusNotFound, errors.New("no log file has been written yet")
	}
	if err != nil {
		server.logger.Error("Failed to stat log file: %v", err)
		return http.StatusInternalServerError, errors.New("Failed to access logs")
	}

	if server.logCache.LastModTime == fileInfo.ModTime() {
		return 0, nil
	}

	if err := server.updateLogCache(level); err != nil {
		server.logger.Error("Failed to update log cache: %v", err)
		return http.StatusInternalServerError, errors.New("Failed to update logs")
	}

	return 0, nil
}

// logsAfter narrows the cache to the entries a caller has not seen, where lastEventID is a Unix
// nanosecond timestamp taken from an entry it already has.
//
// An id that is not a number is reported and then IGNORED rather than refused: the caller gets the
// whole cache, which is what it would have got had it sent no id at all.
func (server *Server) logsAfter(lastEventID string) []LogEntry {
	if lastEventID == "" {
		return server.logCache.Logs
	}

	after, err := strconv.ParseInt(lastEventID, 10, 64)
	if err != nil {
		server.logger.Error("Invalid last_event_id: %v", err)
		return server.logCache.Logs
	}

	var filtered []LogEntry
	for _, entry := range server.logCache.Logs {
		if entry.Timestamp.UnixNano() > after {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}

// pageOfLogs cuts one page out of entries, and says whether another one follows. A page past the
// end is empty rather than an error.
func pageOfLogs(entries []LogEntry, page int) ([]LogEntry, bool) {
	start := (page - 1) * logsPageSize
	if start >= len(entries) {
		return nil, false
	}

	end := start + logsPageSize
	if end > len(entries) {
		end = len(entries)
	}

	return entries[start:end], end < len(entries)
}
