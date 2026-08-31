package internal

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
)

// The log route, which pages the file this process writes.

// Lazy loading approach
func (server *Server) handleGetLogs(w http.ResponseWriter, r *http.Request) {
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
	logPath := filepath.Join(server.config.Process.LogPath, fmt.Sprintf("%s.log", server.config.Process.ID))
	fileInfo, err := os.Stat(logPath)
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
