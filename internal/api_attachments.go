package internal

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/vaziolabs/lumberjack/internal/core"
)

// The attachment routes: files on a node and on an entry of one of its events.

// handleUploadAttachment handles file uploads and creates attachments
func (server *Server) handleUploadAttachment(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFrom(r)
	if !ok {
		http.Error(w, "No user in session", http.StatusUnauthorized)
		return
	}

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
	if err := server.writeChangesToFile(server.statePath()); err != nil {
		http.Error(w, "Failed to save state", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(attachment)
}

// handleGetAttachment retrieves an attachment
func (server *Server) handleGetAttachment(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFrom(r)
	if !ok {
		http.Error(w, "No user in session", http.StatusUnauthorized)
		return
	}
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
	userID, ok := userIDFrom(r)
	if !ok {
		http.Error(w, "No user in session", http.StatusUnauthorized)
		return
	}
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
	if err := server.writeChangesToFile(server.statePath()); err != nil {
		http.Error(w, "Failed to save state", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(attachment)
}

// handleDeleteAttachment deletes an attachment
func (server *Server) handleDeleteAttachment(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFrom(r)
	if !ok {
		http.Error(w, "No user in session", http.StatusUnauthorized)
		return
	}
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
	if err := server.writeChangesToFile(server.statePath()); err != nil {
		http.Error(w, "Failed to save state", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}
