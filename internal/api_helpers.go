package internal

import (
	"fmt"
	"io"
	"path/filepath"

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

// getNodeFromPath traverses the forest to find a node by its path.
//
// The path may arrive in either form — see node_path.go. It is reduced to the segments BELOW the
// root before anything is looked up, so `forest/momentum/x` and `momentum/x` reach the same node
// instead of one of them answering 404, and `forest` names the root rather than a child that is not
// there.
func (server *Server) getNodeFromPath(path string) (*core.Node, error) {
	segments := server.segmentsFrom(path)
	if len(segments) == 0 {
		return server.forest, nil
	}

	// Try cache first
	if node, err := server.getFromCache(segments); err == nil {
		return node, nil
	}

	// Cache miss, get from forest
	node, found := walkNames(server.forest, segments)
	if !found {
		return nil, fmt.Errorf("node not found: %s", path)
	}

	// Update cache after fetch
	server.updateCache()
	return node, nil
}

// walkNames resolves path segments by NAME from a root, which is the one rule for what a path
// means.
//
// It used to be two rules. The cache resolved the whole path string through core.GetNode, which
// searches by ID and answers the ROOT for the literal string "forest" whatever the caller meant —
// so `forest/forest` resolved to the root while the forest walk resolved it to a child of that
// name, and a lookup that missed searched the entire DAG by id before walking it again by name.
//
// The caller must hold the forest for reading.
func walkNames(root *core.Node, segments []string) (*core.Node, bool) {
	current := root
	for _, part := range segments {
		found := false
		for _, child := range current.Children {
			if child.Name == part {
				current = child
				found = true
				break
			}
		}
		if !found {
			return nil, false
		}
	}
	return current, true
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
