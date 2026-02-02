package internal

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/vaziolabs/lumberjack/internal/core"
	"github.com/vaziolabs/lumberjack/types"

	"github.com/golang-jwt/jwt"
	"github.com/gorilla/mux"
)

// HTTP handler for assigning a user
func (server *Server) handleAssignUser(w http.ResponseWriter, r *http.Request) {
	server.logger.Enter("AssignUser")
	defer server.logger.Exit("AssignUser")

	userID := r.Context().Value("user_id").(string)

	var request struct {
		Path       string          `json:"path"`
		AssigneeID string          `json:"assignee_id"`
		Permission core.Permission `json:"permission"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	node, err := server.forest.GetNode(request.Path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	// Check if user has admin permission
	if !node.CheckPermission(userID, core.AdminPermission) {
		http.Error(w, "Insufficient permissions", http.StatusForbidden)
		return
	}

	assigneeUser := core.User{ID: request.AssigneeID}
	if err := node.AssignUser(assigneeUser, request.Permission); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Log activity
	node.AddActivity("assign_user", map[string]interface{}{
		"assignee_id": request.AssigneeID,
		"permission":  request.Permission,
	}, userID)

	// Write changes to file
	if err := server.writeChangesToFile(node, "state_file.dat"); err != nil {
		http.Error(w, "Failed to save state", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// HTTP handler for starting time tracking
func (server *Server) handleStartTimeTracking(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)

	var request struct {
		Path string `json:"path"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	node, err := server.forest.GetNode(request.Path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	node.StartTimeTracking(userID)

	// Write changes to file
	if err := server.writeChangesToFile(node, "state_file.dat"); err != nil {
		http.Error(w, "Failed to save state", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// HTTP handler for stopping time tracking
func (server *Server) handleStopTimeTracking(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)

	var request struct {
		Path string `json:"path"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	node, err := server.forest.GetNode(request.Path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	node.StopTimeTracking(userID)

	summary := node.GetTimeTrackingSummary(userID)
	json.NewEncoder(w).Encode(summary)

	// Write changes to file
	if err := server.writeChangesToFile(node, "state_file.dat"); err != nil {
		http.Error(w, "Failed to save state", http.StatusInternalServerError)
		return
	}
}

// HTTP handler for getting time tracking summary
func (server *Server) handleGetTimeTracking(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)

	var request struct {
		Path string `json:"path"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	node, err := server.forest.GetNode(request.Path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	summary := node.GetTimeTrackingSummary(userID)
	json.NewEncoder(w).Encode(summary)
}

// HTTP handler for starting an event
func (server *Server) handleStartEvent(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)

	var request struct {
		Path     string                 `json:"path"`
		EventID  string                 `json:"event_id"`
		Metadata map[string]interface{} `json:"metadata"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	node, err := server.getNodeFromPath(request.Path)
	if err != nil {
		http.Error(w, fmt.Sprintf("Path error: %v", err), http.StatusNotFound)
		return
	}

	if err := node.StartEvent(request.EventID, userID, nil, nil, request.Metadata); err != nil {
		http.Error(w, fmt.Sprintf("Start event error: %v", err), http.StatusInternalServerError)
		return
	}

	// Save state after event creation
	if err := server.writeChangesToFile(server.forest, "state_file.dat"); err != nil {
		http.Error(w, "Failed to save state", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// HTTP handler for ending an event
func (server *Server) handleEndEvent(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)

	var request struct {
		Path    string `json:"path"`
		EventID string `json:"event_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	node, err := server.getNodeFromPath(request.Path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	if !node.CheckPermission(userID, core.WritePermission) {
		http.Error(w, "Insufficient permissions", http.StatusForbidden)
		return
	}

	if err := node.EndEvent(request.EventID, userID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// HTTP handler for appending to an event
func (server *Server) handleAppendToEvent(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)

	var request struct {
		Path     string                 `json:"path"`
		EventID  string                 `json:"event_id"`
		Content  string                 `json:"content"`
		Metadata map[string]interface{} `json:"metadata"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		log.Printf("Failed to decode request: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	log.Printf("Looking for node at path: %s", request.Path)
	node, err := server.getNodeFromPath(request.Path)
	if err != nil {
		log.Printf("Failed to get node: %v", err)
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	log.Printf("Appending to event %s", request.EventID)
	entry := core.Entry{
		Content:   request.Content,
		Metadata:  request.Metadata,
		UserID:    userID,
		Timestamp: time.Now(),
		CreatedBy: userID,
		CreatedAt: time.Now(),
	}

	if err := node.AppendToEvent(request.EventID, userID, entry, request.Metadata); err != nil {
		log.Printf("Failed to append to event: %v", err)
		http.Error(w, fmt.Sprintf("Failed to append to event: %v", err), http.StatusInternalServerError)
		return
	}

	if err := server.writeChangesToFile(server.forest, "state_file.dat"); err != nil {
		log.Printf("Failed to save state: %v", err)
		http.Error(w, "Failed to save state", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// HTTP handler for getting event entries
func (server *Server) handleGetEventEntries(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Path    string `json:"path"`
		EventID string `json:"event_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	node, err := server.getNodeFromPath(request.Path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	entries, err := node.GetEventEntries(request.EventID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entries)
}

// HTTP handler for getting tree
func (server *Server) handleGetForest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(server.forest)
}

// HTTP handler for getting users
func (server *Server) handleGetUsers(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(server.forest.Users)
}

// HTTP handler for creating a user
func (server *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	server.logger.Enter("CreateUser")
	defer server.logger.Exit("CreateUser")

	var request struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		server.logger.Failure("Failed to decode request: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Create new user
	user := core.User{
		ID:       core.GenerateID(),
		Username: request.Username,
		Email:    request.Email,
	}

	if err := user.SetPassword(request.Password); err != nil {
		server.logger.Failure("Failed to set password: %v", err)
		http.Error(w, "Failed to set password", http.StatusInternalServerError)
		return
	}

	// Add user to the root node
	if err := server.forest.AssignUser(user, core.ReadPermission); err != nil {
		server.logger.Failure("Failed to assign user: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Save state
	if err := server.writeChangesToFile(server.forest, "state_file.dat"); err != nil {
		server.logger.Failure("Failed to save state: %v", err)
		http.Error(w, "Failed to save state", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	server.logger.Success("User created successfully")
}

func (server *Server) handlePlanEvent(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)

	var request struct {
		Path      string                 `json:"path"`
		EventID   string                 `json:"event_id"`
		StartTime string                 `json:"start_time"`
		EndTime   string                 `json:"end_time"`
		Metadata  map[string]interface{} `json:"metadata"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	startTime, err := time.Parse(time.RFC3339, request.StartTime)
	if err != nil {
		http.Error(w, "Invalid start time format", http.StatusBadRequest)
		return
	}

	endTime, err := time.Parse(time.RFC3339, request.EndTime)
	if err != nil {
		http.Error(w, "Invalid end time format", http.StatusBadRequest)
		return
	}

	node, err := server.getNodeFromPath(request.Path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	if err := node.PlanEvent(request.EventID, userID, &startTime, &endTime, request.Metadata); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// Add new handlers
func (server *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	server.logger.Enter("handleLogin")
	defer server.logger.Exit("handleLogin")

	var credentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
		server.logger.Failure("Invalid request: %v", err)
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	server.logger.Info("Attempting login for user: %s", credentials.Username)

	// Get pointer to user to avoid copying
	var foundUser *core.User
	for i := range server.forest.Users {
		if server.forest.Users[i].Username == credentials.Username {
			foundUser = &server.forest.Users[i]
			break
		}
	}

	if foundUser == nil {
		server.logger.Failure("User not found: %s", credentials.Username)
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	if !foundUser.VerifyPassword(credentials.Password) {
		server.logger.Failure("Invalid password for user: %s", credentials.Username)
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Generate token pair
	tokenPair, err := server.generateTokenPair(foundUser)
	if err != nil {
		server.logger.Failure("Failed to generate tokens: %v", err)
		http.Error(w, "Failed to generate tokens", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"session_token": tokenPair.SessionToken,
		"refresh_token": tokenPair.RefreshToken,
	})
	server.logger.Success("Login successful for user %s", foundUser.Username)
}

// Add new handler for token refresh
func (server *Server) handleRefreshToken(w http.ResponseWriter, r *http.Request) {
	var request struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	token, err := jwt.ParseWithClaims(request.RefreshToken, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return server.jwtConfig.SecretKey, nil
	})

	if err != nil || !token.Valid {
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	claims, ok := token.Claims.(*TokenClaims)
	if !ok || claims.TokenType != "refresh" {
		http.Error(w, "Invalid token type", http.StatusUnauthorized)
		return
	}

	// Generate new session token
	user := &core.User{ID: claims.UserID, Username: claims.Username}
	tokenPair, err := server.generateTokenPair(user)
	if err != nil {
		http.Error(w, "Failed to generate tokens", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"session_token": tokenPair.SessionToken,
	})
}

func (server *Server) handleGetUserProfile(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)

	user, err := server.forest.GetUserProfile(userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"username":     user.Username,
		"email":        user.Email,
		"organization": user.Organization,
		"phone":        user.Phone,
		"permissions":  user.Permissions,
	})
}

// HTTP handler for getting a specific tree
func (server *Server) handleGetTree(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")

	node, err := server.queuedGetNode(path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(node)
}

// HTTP handler for getting server settings
func (server *Server) handleGetServerSettings(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)

	// Check if user has admin permission on root node
	if !server.forest.CheckPermission(userID, core.AdminPermission) {
		http.Error(w, "Insufficient permissions", http.StatusForbidden)
		return
	}

	// Return safe subset of server settings
	settings := map[string]interface{}{
		"organization":  server.config.Organization,
		"server_port":   server.config.Process.ServerPort,
		"dashboard_url": server.config.Process.DashboardURL,
		"phone":         server.config.Phone,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(settings)
}

// HTTP handler for updating server settings
func (server *Server) handleUpdateServerSettings(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)

	// Check if user has admin permission on root node
	if !server.forest.CheckPermission(userID, core.AdminPermission) {
		http.Error(w, "Insufficient permissions", http.StatusForbidden)
		return
	}

	var settings types.ServerConfig
	if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Use the UpdateSettings helper instead of direct assignment
	if err := server.UpdateSettings(userID, settings); err != nil {
		http.Error(w, fmt.Sprintf("Failed to update settings: %v", err), http.StatusInternalServerError)
		return
	}

	// Save state after settings update
	if err := server.writeChangesToFile(server.forest, server.config.Process.DatabasePath); err != nil {
		http.Error(w, "Failed to save state", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

// Add these structures for token management
type TokenPair struct {
	SessionToken string `json:"session_token"`
	RefreshToken string `json:"refresh_token"`
}

type TokenClaims struct {
	UserID    string `json:"user_id"`
	Username  string `json:"username"`
	TokenType string `json:"token_type"` // "session" or "refresh"
	jwt.StandardClaims
}

// handleUploadAttachment handles file uploads and creates attachments
func (server *Server) handleUploadAttachment(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)

	// Parse multipart form with 10MB max memory
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, "File too large", http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Invalid file upload", http.StatusBadRequest)
		return
	}
	defer file.Close()

	path := r.FormValue("path")
	node, err := server.forest.GetNode(path)
	if err != nil {
		http.Error(w, "Node not found", http.StatusNotFound)
		return
	}

	if !node.CheckPermission(userID, core.WritePermission) {
		http.Error(w, "Insufficient permissions", http.StatusForbidden)
		return
	}

	attachment := &core.Attachment{
		ID:         fmt.Sprintf("att-%d", time.Now().UnixNano()),
		Name:       header.Filename,
		Type:       header.Header.Get("Content-Type"),
		Size:       header.Size,
		UploadedBy: userID,
		UploadedAt: time.Now(),
	}

	if err := node.AddAttachment(attachment, userID); err != nil {
		http.Error(w, "Failed to add attachment to node", http.StatusInternalServerError)
		return
	}

	// Save state after attachment upload
	if err := server.writeChangesToFile(server.forest, server.config.Process.DatabasePath); err != nil {
		http.Error(w, "Failed to save state", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(attachment)
}

// handleGetAttachment retrieves an attachment
func (server *Server) handleGetAttachment(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)
	vars := mux.Vars(r)
	attachmentID := vars["id"]
	path := r.URL.Query().Get("path")

	node, err := server.forest.GetNode(path)
	if err != nil {
		http.Error(w, "Node not found", http.StatusNotFound)
		return
	}

	if !node.CheckPermission(userID, core.ReadPermission) {
		http.Error(w, "Insufficient permissions", http.StatusForbidden)
		return
	}

	attachment, err := node.GetAttachment(attachmentID)
	if err != nil {
		http.Error(w, "Attachment not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", attachment.Type)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", attachment.Name))
	w.Write(attachment.Data)
}

// handleAddEntryAttachment adds an attachment to a specific event entry
func (server *Server) handleAddEntryAttachment(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)
	vars := mux.Vars(r)
	eventID := vars["eventId"]
	entryIndex := vars["entryIndex"]

	path := r.URL.Query().Get("path")
	node, err := server.forest.GetNode(path)
	if err != nil {
		http.Error(w, "Node not found", http.StatusNotFound)
		return
	}

	if !node.CheckPermission(userID, core.WritePermission) {
		http.Error(w, "Insufficient permissions", http.StatusForbidden)
		return
	}

	// Parse multipart form
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, "File too large", http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Invalid file upload", http.StatusBadRequest)
		return
	}
	defer file.Close()

	index, err := strconv.Atoi(entryIndex)
	if err != nil {
		http.Error(w, "Invalid entry index", http.StatusBadRequest)
		return
	}

	attachment, err := core.NewAttachmentStore().Store(file, header, userID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to store attachment: %v", err), http.StatusInternalServerError)
		return
	}

	if err := node.AddEntryAttachment(eventID, index, attachment, userID); err != nil {
		http.Error(w, "Failed to add attachment to entry", http.StatusInternalServerError)
		return
	}

	// Save state
	if err := server.writeChangesToFile(server.forest, server.config.Process.DatabasePath); err != nil {
		http.Error(w, "Failed to save state", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(attachment)
}

// handleDeleteAttachment deletes an attachment
func (server *Server) handleDeleteAttachment(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)
	vars := mux.Vars(r)
	attachmentID := vars["id"]
	path := r.URL.Query().Get("path")

	node, err := server.forest.GetNode(path)
	if err != nil {
		http.Error(w, "Node not found", http.StatusNotFound)
		return
	}

	if !node.CheckPermission(userID, core.WritePermission) {
		http.Error(w, "Insufficient permissions", http.StatusForbidden)
		return
	}

	if err := node.DeleteAttachment(attachmentID, userID); err != nil {
		http.Error(w, fmt.Sprintf("Failed to delete attachment: %v", err), http.StatusInternalServerError)
		return
	}

	// Save state after deletion
	if err := server.writeChangesToFile(server.forest, server.config.Process.DatabasePath); err != nil {
		http.Error(w, "Failed to save state", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// HTTP handler for creating a node with metadata
func (server *Server) handleCreateNode(w http.ResponseWriter, r *http.Request) {
	server.logger.Enter("CreateNode")
	defer server.logger.Exit("CreateNode")

	userID := r.Context().Value("user_id").(string)

	var request struct {
		Path     string                 `json:"path"`
		Name     string                 `json:"name"`
		Type     core.NodeType          `json:"type"` // 0=LeafNode, 1=BranchNode
		Metadata map[string]interface{} `json:"metadata"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		server.logger.Failure("Failed to decode request: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Parse path to find parent node
	parts := strings.Split(strings.Trim(request.Path, "/"), "/")
	parentPath := ""
	if len(parts) > 1 {
		parentPath = strings.Join(parts[:len(parts)-1], "/")
	}

	server.logger.Info("Creating node at path: %s (parent: %s)", request.Path, parentPath)

	// Get or create parent node
	parent := server.forest
	if parentPath != "" {
		var err error
		parent, err = server.getNodeFromPath(parentPath)
		if err != nil {
			server.logger.Failure("Parent not found: %v", err)
			http.Error(w, fmt.Sprintf("Parent not found: %v", err), http.StatusNotFound)
			return
		}
	}

	// Check permissions on parent - user needs write or admin permission
	hasWritePermission := parent.CheckPermission(userID, core.WritePermission)
	hasAdminPermission := parent.CheckPermission(userID, core.AdminPermission)

	if !hasWritePermission && !hasAdminPermission {
		server.logger.Failure("User %s lacks write or admin permission on parent", userID)
		http.Error(w, "Insufficient permissions", http.StatusForbidden)
		return
	}

	// Create new node
	newNode := core.NewNode(request.Type, request.Name)
	server.logger.Info("Created new node: ID=%s, Name=%s, Type=%d", newNode.ID, newNode.Name, newNode.Type)

	// Add metadata as initial activity
	if request.Metadata != nil {
		newNode.AddActivity("node_created", request.Metadata, userID)
		server.logger.Info("Added metadata with %d fields", len(request.Metadata))
	}

	// Assign creator with write permission
	user := core.User{ID: userID}
	if err := newNode.AssignUser(user, core.WritePermission); err != nil {
		server.logger.Failure("Failed to assign user: %v", err)
		http.Error(w, "Failed to assign user", http.StatusInternalServerError)
		return
	}

	// Add to parent
	if err := parent.AddChild(newNode); err != nil {
		server.logger.Failure("Failed to add child: %v", err)
		http.Error(w, fmt.Sprintf("Failed to add child: %v", err), http.StatusInternalServerError)
		return
	}

	// Persist to disk
	dbPath := filepath.Join(server.config.Process.DatabasePath, server.config.Process.Name+".dat")
	if err := server.writeChangesToFile(server.forest, dbPath); err != nil {
		server.logger.Failure("Failed to save state: %v", err)
		http.Error(w, "Failed to save state", http.StatusInternalServerError)
		return
	}

	server.logger.Success("Node created and persisted at path: %s", request.Path)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":   newNode.ID,
		"path": request.Path,
		"name": newNode.Name,
		"type": newNode.Type,
	})
}

// Handler for getting node metadata by path
func (server *Server) handleGetNodeByPath(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)

	path := r.URL.Query().Get("path")
	if path == "" {
		http.Error(w, "path parameter required", http.StatusBadRequest)
		return
	}

	node, err := server.getNodeFromPath(path)
	if err != nil {
		http.Error(w, fmt.Sprintf("Node not found: %v", err), http.StatusNotFound)
		return
	}

	// Check read permission
	if !node.CheckPermission(userID, core.ReadPermission) &&
	   !node.CheckPermission(userID, core.AdminPermission) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(node)
}

// Handler for updating node metadata
func (server *Server) handleUpdateNodeMetadata(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)

	var request struct {
		Path     string                 `json:"path"`
		Metadata map[string]interface{} `json:"metadata"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	node, err := server.getNodeFromPath(request.Path)
	if err != nil {
		http.Error(w, "Node not found", http.StatusNotFound)
		return
	}

	if !node.CheckPermission(userID, core.WritePermission) && !node.CheckPermission(userID, core.AdminPermission) {
		http.Error(w, "Insufficient permissions", http.StatusForbidden)
		return
	}

	// Add metadata as new activity
	node.AddActivity("metadata_updated", request.Metadata, userID)

	// Persist to disk
	dbPath := filepath.Join(server.config.Process.DatabasePath, server.config.Process.Name+".dat")
	if err := server.writeChangesToFile(server.forest, dbPath); err != nil {
		http.Error(w, "Failed to save state", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

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
