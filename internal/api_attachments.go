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

	attachment := &core.Attachment{
		ID:         fmt.Sprintf("att-%d", time.Now().UnixNano()),
		Name:       header.Filename,
		Type:       header.Header.Get("Content-Type"),
		Size:       header.Size,
		UploadedBy: userID,
		UploadedAt: time.Now(),
	}

	// getNodeFromPath by way of changeNode, not forest.GetNode: the form field is a PATH and
	// GetNode matches a generated node id, so this route could only ever answer "Node not found".
	err = server.changeNode(r.FormValue("path"), userID, core.WritePermission, func(node *core.Node) error {
		if err := node.AddAttachment(attachment, userID); err != nil {
			return apiErrorf(http.StatusInternalServerError, "Failed to add attachment to node")
		}
		return nil
	})
	if err != nil {
		writeAPIError(w, err)
		return
	}

	// PROJECTED: core.Attachment carries the file's bytes in a field tagged `json:"data"`, so
	// encoding the stored value handed the uploader its own upload back inside the receipt — and
	// every other route that echoes one would hand back somebody else's.
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(newAttachmentView(*attachment))
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

	// The bytes are COPIED out under the read hold and written afterwards. This is the one route
	// whose whole purpose is the file's contents, so it is also the one place they may leave.
	var attachment *core.Attachment
	if err := server.readNode(path, userID, core.ReadPermission, func(node *core.Node) error {
		stored, err := node.GetAttachment(attachmentID)
		if err != nil {
			return apiErrorf(http.StatusNotFound, "Attachment not found")
		}
		copied := *stored
		copied.Data = append([]byte(nil), stored.Data...)
		attachment = &copied
		return nil
	}); err != nil {
		writeAPIError(w, err)
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

	if err := server.changeNode(path, userID, core.WritePermission, func(node *core.Node) error {
		if err := node.AddEntryAttachment(eventID, index, attachment, userID); err != nil {
			return apiErrorf(http.StatusInternalServerError, "Failed to add attachment to entry")
		}
		return nil
	}); err != nil {
		writeAPIError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(newAttachmentView(*attachment))
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

	if err := server.changeNode(path, userID, core.WritePermission, func(node *core.Node) error {
		if err := node.DeleteAttachment(attachmentID, userID); err != nil {
			return apiErrorf(http.StatusInternalServerError, "Failed to delete attachment: %v", err)
		}
		return nil
	}); err != nil {
		writeAPIError(w, err)
		return
	}

	w.WriteHeader(http.StatusOK)
}
