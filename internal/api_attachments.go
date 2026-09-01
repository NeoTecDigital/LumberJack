package internal

import (
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/vaziolabs/lumberjack/internal/core"
)

// The attachment routes: files on a node and on an entry of one of its events.
//
// EVERY ONE OF THEM THAT WRITES ANNOUNCES ITSELF. This file had no publish call in it at all, so
// GET /stream — which is documented as emitting on every mutation — was silent about a file
// appearing on a node and about one going away. A client told about every OTHER mutation stops
// polling, so a silent route is worse than no feed.

// handleUploadAttachment handles file uploads and creates attachments
func (server *Server) handleUploadAttachment(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFrom(r)
	if !ok {
		http.Error(w, "No user in session", http.StatusUnauthorized)
		return
	}

	file, header, err := readUpload(r)
	if err != nil {
		writeAPIError(w, err)
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
	path := r.FormValue("path")
	err = server.changeNode(path, userID, core.WritePermission, func(node *core.Node) error {
		if err := node.AddAttachment(attachment, userID); err != nil {
			return apiErrorf(http.StatusInternalServerError, "Failed to add attachment to node")
		}
		return nil
	})
	if err != nil {
		writeAPIError(w, err)
		return
	}

	server.publish(mutation(mutationAttachmentAdded, path))

	// PROJECTED: core.Attachment carries the file's bytes in a field tagged `json:"data"`, so
	// encoding the stored value handed the uploader its own upload back inside the receipt — and
	// every other route that echoes one would hand back somebody else's.
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(newAttachmentView(*attachment))
}

// readUpload takes the one file a multipart request carries. The caller closes it.
//
// TEN MEGABYTES are held in memory; anything past that spills to a temporary file the form owns.
func readUpload(r *http.Request) (multipart.File, *multipart.FileHeader, error) {
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		return nil, nil, apiErrorf(http.StatusBadRequest, "File too large")
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		return nil, nil, apiErrorf(http.StatusBadRequest, "Invalid file upload")
	}
	return file, header, nil
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
	path, eventID, index, err := entryAddress(r)
	if err != nil {
		writeAPIError(w, err)
		return
	}

	file, header, err := readUpload(r)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	defer file.Close()

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

	// The entry is NAMED, the way an append names the entry it added: a client that keeps one
	// entry open needs to know this landed on that one and not on some other.
	announced := mutation(mutationAttachmentAdded, path)
	announced.EventID = eventID
	announced.EntryIndex = index
	server.publish(announced)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(newAttachmentView(*attachment))
}

// entryAddress is where an entry attachment goes: the node, the event on it, and which entry of
// that event.
func entryAddress(r *http.Request) (string, string, int, error) {
	vars := mux.Vars(r)

	index, err := strconv.Atoi(vars["entryIndex"])
	if err != nil {
		return "", "", 0, apiErrorf(http.StatusBadRequest, "Invalid entry index")
	}
	return r.URL.Query().Get("path"), vars["eventId"], index, nil
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

	server.publish(mutation(mutationAttachmentRemoved, path))
	w.WriteHeader(http.StatusOK)
}
