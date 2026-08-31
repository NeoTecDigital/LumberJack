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

	// Get query parameters
	query := r.URL.Query()
	page, _ := strconv.Atoi(query.Get("page"))
	lastEventID := query.Get("last_event_id")
	level := query.Get("level")

	if page < 1 {
		page = 1
	}

	// Check if cache needs refresh
	logPath := server.logFilePath()
	if logPath == "" {
		http.Error(w, errNoLogFile.Error(), http.StatusNotFound)
		return
	}

	fileInfo, err := os.Stat(logPath)
	if errors.Is(err, os.ErrNotExist) {
		// Configured, but nothing has been written yet. That is a missing resource, not a fault.
		http.Error(w, "no log file has been written yet", http.StatusNotFound)
		return
	}
	if err != nil {
		server.logger.Error("Failed to stat log file: %v", err)
		http.Error(w, "Failed to access logs", http.StatusInternalServerError)
		return
	}

	if server.logCache.LastModTime != fileInfo.ModTime() {
		if err := server.updateLogCache(level); err != nil {
			server.logger.Error("Failed to update log cache: %v", err)
			http.Error(w, "Failed to update logs", http.StatusInternalServerError)
			return
		}
	}

	// Get logs after the last event ID if provided
	var filteredLogs []LogEntry
	if lastEventID != "" {
		lastEventTimestamp, err := strconv.ParseInt(lastEventID, 10, 64)
		if err != nil {
			server.logger.Error("Invalid last_event_id: %v", err)
			filteredLogs = server.logCache.Logs
		} else {
			// Only include logs that come after the lastEventTimestamp
			for _, log := range server.logCache.Logs {
				if log.Timestamp.UnixNano() > lastEventTimestamp {
					filteredLogs = append(filteredLogs, log)
				}
			}
		}
	} else {
		filteredLogs = server.logCache.Logs
	}

	// Return paginated results
	startIdx := (page - 1) * 100
	endIdx := startIdx + 100
	if endIdx > len(filteredLogs) {
		endIdx = len(filteredLogs)
	}

	hasMore := endIdx < len(filteredLogs)
	var logs []LogEntry
	if startIdx < len(filteredLogs) {
		logs = filteredLogs[startIdx:endIdx]
	}

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
