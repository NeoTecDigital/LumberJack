package internal

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
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

// Update the auth middleware to handle user_id from token claims
func (server *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if tokenString == "" {
			http.Error(w, "No token provided", http.StatusUnauthorized)
			return
		}

		token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return server.jwtConfig.SecretKey, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		claims, ok := token.Claims.(*TokenClaims)
		if !ok || claims.TokenType != "session" {
			http.Error(w, "Invalid session token", http.StatusUnauthorized)
			return
		}

		// Add user info to context
		ctx := context.WithValue(r.Context(), "user_id", claims.UserID)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// userIDFrom reads the caller that authMiddleware put in the request context.
//
// The unchecked `r.Context().Value("user_id").(string)` this replaces PANICKED on a nil interface
// conversion whenever a handler was reached without one, which takes the whole process down instead
// of answering 401.
func userIDFrom(r *http.Request) (string, bool) {
	userID, ok := r.Context().Value("user_id").(string)
	return userID, ok && userID != ""
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

func (server *Server) generateTokenPair(user *core.User) (*TokenPair, error) {
	// Generate session token (short-lived)
	sessionClaims := TokenClaims{
		UserID:    user.ID,
		Username:  user.Username,
		TokenType: "session",
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
			IssuedAt:  time.Now().Unix(),
		},
	}

	sessionToken := jwt.NewWithClaims(jwt.SigningMethodHS256, sessionClaims)
	sessionTokenString, err := sessionToken.SignedString(server.jwtConfig.SecretKey)
	if err != nil {
		return nil, err
	}

	// Generate refresh token (long-lived)
	refreshClaims := TokenClaims{
		UserID:    user.ID,
		Username:  user.Username,
		TokenType: "refresh",
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(7 * 24 * time.Hour).Unix(),
			IssuedAt:  time.Now().Unix(),
		},
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString(server.jwtConfig.SecretKey)
	if err != nil {
		return nil, err
	}

	return &TokenPair{
		SessionToken: sessionTokenString,
		RefreshToken: refreshTokenString,
	}, nil
}

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

	logPath := filepath.Join(server.config.Process.LogPath, fmt.Sprintf("%s.log", server.config.Process.ID))
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

func (server *Server) parseLogEntry(line string, level string) (*LogEntry, error) {
	// Skip empty lines
	if len(line) < 19 {
		return nil, fmt.Errorf("line too short")
	}

	// Parse timestamp
	timestamp, err := time.Parse("2006/01/02 15:04:05", line[:19])
	if err != nil {
		return nil, fmt.Errorf("invalid timestamp: %v", err)
	}

	// Get remainder after timestamp
	remainder := strings.TrimSpace(line[19:])

	// Parse indentation level and message
	indentCount := 0
	for _, char := range remainder {
		if char == '│' || char == '└' || char == '┌' || char == '─' {
			indentCount++
		} else {
			break
		}
	}

	// Remove tree characters and spaces
	message := strings.TrimLeft(remainder, "│└┌─ ")

	// Parse log level and message
	var logLevel string
	var content string
	var entryType string

	// Check for BEGIN/END messages
	if strings.HasPrefix(message, "BEGIN:") {
		logLevel = "INFO"
		content = strings.TrimSpace(strings.TrimPrefix(message, "BEGIN:"))
		entryType = "begin"
	} else if strings.HasPrefix(message, "END:") {
		logLevel = "INFO"
		content = strings.TrimSpace(strings.TrimPrefix(message, "END:"))
		entryType = "end"
	} else {
		// Map of symbols to log levels
		levelMap := map[string]string{
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

		// Check for level symbols
		found := false
		for symbol, lvl := range levelMap {
			if strings.HasPrefix(message, symbol) {
				logLevel = lvl
				content = strings.TrimSpace(strings.TrimPrefix(message, symbol))
				found = true
				break
			}
		}

		if !found {
			logLevel = "INFO"
			content = message
		}
		entryType = "message"
	}

	// Filter by level if specified
	if level != "" && !strings.EqualFold(level, logLevel) {
		return nil, nil
	}

	return &LogEntry{
		Timestamp: timestamp,
		Level:     logLevel,
		Message:   content,
		Type:      entryType,
		Indent:    indentCount,
	}, nil
}

func (server *Server) initCache() {
	server.cache = &Cache{
		Forest: core.NewForest("forest"),
	}
}

func (server *Server) initAPIQueue(workers int) {
	server.apiQueue = &APIQueue{
		queue:    make(chan APIRequest, 100),
		workers:  workers,
		shutdown: make(chan struct{}),
	}

	// Start workers
	for i := 0; i < workers; i++ {
		server.apiQueue.wg.Add(1)
		go server.worker()
	}
}

func (server *Server) getFromCache(path string) (*core.Node, error) {
	server.cache.mutex.RLock()
	defer server.cache.mutex.RUnlock()

	if server.cache.Forest == nil || !compareHashes(server.cache.LastHash, server.lastHash) {
		return nil, fmt.Errorf("cache miss")
	}

	if path == "" {
		return server.cache.Forest, nil
	}

	return server.cache.Forest.GetNode(path)
}

func (server *Server) updateCache() error {
	server.cache.mutex.Lock()
	defer server.cache.mutex.Unlock()

	server.cache.Forest = server.forest
	server.cache.LastHash = server.lastHash
	server.cache.LastUpdate = time.Now()
	return nil
}

func (server *Server) worker() {
	defer server.apiQueue.wg.Done()

	for {
		select {
		case req := <-server.apiQueue.queue:
			response := APIResponse{}
			response.Data = req.Callback(server.forest)
			req.Response <- response
		case <-server.apiQueue.shutdown:
			return
		}
	}
}

// queuedGetNode reads a node through the worker pool.
//
// The callback used to wrap its answer in a SECOND APIResponse, which the worker then stored in the
// Data field of the one it sends back. So Data was never a *core.Node and the unchecked assertion
// here panicked on every call — GET /forest/tree took the process down rather than answering.
func (server *Server) queuedGetNode(path string) (*core.Node, error) {
	responseChan := make(chan APIResponse, 1)

	request := APIRequest{
		Type: "GET_NODE",
		Path: path,
		Callback: func(forest *core.Node) interface{} {
			node, err := server.getNodeFromPath(path)
			if err != nil {
				return err
			}
			return node
		},
		Response: responseChan,
	}

	server.apiQueue.queue <- request
	response := <-responseChan

	if response.Error != nil {
		return nil, response.Error
	}

	switch result := response.Data.(type) {
	case error:
		return nil, result
	case *core.Node:
		return result, nil
	default:
		return nil, fmt.Errorf("unexpected response reading node %q", path)
	}
}
