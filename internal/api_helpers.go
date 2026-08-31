package internal

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
	"github.com/vaziolabs/lumberjack/internal/core"
	"github.com/vaziolabs/lumberjack/types"
)

// compares two byte slices for equality
func compareHashes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// getNodeFromPath traverses the forest to find a node by its path
func (server *Server) getNodeFromPath(path string) (*core.Node, error) {
	// Try cache first
	if node, err := server.getFromCache(path); err == nil {
		return node, nil
	}

	// Cache miss, get from forest
	if path == "" {
		return server.forest, nil
	}

	parts := strings.Split(path, "/")
	current := server.forest

	for _, part := range parts {
		found := false
		for _, child := range current.Children {
			if child.Name == part {
				current = child
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("node not found: %s", path)
		}
	}

	// Update cache after fetch
	server.updateCache()
	return current, nil
}

// statePath is this database's own state file, which is where every handler persists to.
//
// It is anchored to the database's own directory: the handlers used to pass the relative name
// "state_file.dat" to writeChangesToFile, which dropped the database into whatever directory the
// process was started from, and the ones that passed DatabasePath wrote to the directory itself.
// The anchor is only as absolute as DatabasePath — the CLI always sets it under
// /var/lib/lumberjack; a config without one keeps the old relative behaviour.
func (server *Server) statePath() string {
	return filepath.Join(server.config.Process.DatabasePath, server.config.Process.Name+".dat")
}

// logFilePath is the file this process logs to, and the file GET /logs pages.
//
// It is EMPTY when the configuration does not say where to log or which process this is, which is
// the honest answer for an install that has no log file rather than a path that will never exist.
func (server *Server) logFilePath() string {
	logPath := server.config.Process.LogPath
	id := server.config.Process.ID
	if logPath == "" || id == "" {
		return ""
	}
	return filepath.Join(logPath, id+".log")
}

// newServerLogger opens the logger a server runs with.
//
// A configured log path gets a real file sink, because the log route serves that file and nothing
// ever opened one. A path that cannot be opened is NOT fatal — losing the ability to page logs over
// HTTP is not a reason to refuse to serve — but it is reported, and the server falls back to
// standard error, where GET /logs will honestly answer that there is no log file.
func newServerLogger(config types.ServerConfig) (types.Logger, io.Closer) {
	logPath := config.Process.LogPath
	id := config.Process.ID
	if logPath == "" || id == "" {
		return types.NewLogger(), nil
	}

	fileLogger, err := types.NewFileLogger(filepath.Join(logPath, id+".log"))
	if err != nil {
		fallback := types.NewLogger()
		fallback.Warn("Logging to standard error only: %v", err)
		return fallback, nil
	}
	return fileLogger, fileLogger
}

// UpdateSettings updates server configuration parameters
func (server *Server) UpdateSettings(userID string, settings types.ServerConfig) error {
	// Update user-specific settings
	for i := range server.forest.Users {
		if server.forest.Users[i].ID == userID {
			server.forest.Users[i].Organization = settings.Organization
			break
		}
	}

	// Update server settings if values are provided
	if settings.Process.ServerPort != "" {
		server.config.Process.ServerPort = settings.Process.ServerPort
	}
	if settings.Process.DashboardPort != "" {
		server.config.Process.DashboardPort = settings.Process.DashboardPort
	}
	if settings.Process.ServerURL != "" {
		server.config.Process.ServerURL = settings.Process.ServerURL
	}
	if settings.Process.DatabasePath != "" {
		server.config.Process.DatabasePath = settings.Process.DatabasePath
	}
	if settings.Process.LogPath != "" {
		server.config.Process.LogPath = settings.Process.LogPath
	}
	if settings.Organization != "" {
		server.config.Organization = settings.Organization
	}
	if settings.Phone != "" {
		server.config.Phone = settings.Phone
	}

	// Save updated configuration
	return server.saveConfig()

	// TODO: Trigger a refresh of the dashboard and a reload of the server if needed
}

// saveConfig writes the current configuration to disk
func (server *Server) saveConfig() error {
	viper.Set("databases."+server.config.Process.Name, server.config)
	return viper.WriteConfig()
}
