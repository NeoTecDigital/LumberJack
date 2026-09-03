package internal

import (
	"encoding/json"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/vaziolabs/lumberjack/internal/core"
)

// The attachment routes: files on a node and on an entry of one of its events.
//
// EVERY ONE OF THEM THAT WRITES ANNOUNCES ITSELF. This file had no publish call in it at all, so
// GET /stream — which is documented as emitting on every mutation — was silent about a file
// appearing on a node and about one going away. A client told about every OTHER mutation stops
// polling, so a silent route is worse than no feed.

// multipartMemoryBudget is how much of a multipart body is held in memory; past it the form spills
// to a temporary file it owns and cleans up. It is a BUDGET and never was a limit — the limit is
// maxUploadBody, enforced on the body, and core.MaxAttachmentSize, enforced on the file.
const multipartMemoryBudget = 1 << 20

// maxUploadBody is the largest request an upload route will read: the file cap plus room for the
// multipart envelope — boundaries, part headers, and the `path` field that says where the file
// goes. The slack is deliberately generous, because the body cap exists to stop an unbounded read
// and the exact refusal belongs to core.AttachmentStore, which measures the file itself.
const maxUploadBody = core.MaxAttachmentSize + (1 << 16)

// handleUploadAttachment handles file uploads and creates attachments
func (server *Server) handleUploadAttachment(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFrom(r)
	if !ok {
		http.Error(w, "No user in session", http.StatusUnauthorized)
		return
	}

	attachment, err := storeUpload(w, r, userID)
	if err != nil {
		writeAPIError(w, err)
		return
	}

	// getNodeFromPath by way of changeNode, not forest.GetNode: the form field is a PATH and
	// GetNode matches a generated node id, so this route could only ever answer "Node not found".
	//
	// The path is read AFTER storeUpload because it is a form field, and there is no parsed form to
	// read it out of until the multipart body has been parsed.
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

// storeUpload is HOW A FILE GETS INTO THE ENGINE, and it is the only way.
//
// THE DEFECT it closes: POST /attachments/upload built the attachment from the multipart HEADER —
// the declared name, type and size — and never read the file. Data was nil, Hash was "", and the
// route answered 200 with a receipt describing bytes it had thrown away. The entry attachment route
// called core.AttachmentStore.Store, which reads and hashes and measures. Two upload routes, one
// verb, opposite meanings. Both go through here now so they cannot part company again.
func storeUpload(w http.ResponseWriter, r *http.Request, userID string) (*core.Attachment, error) {
	file, header, err := readUpload(w, r)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	attachment, err := core.NewAttachmentStore().Store(file, header, userID)
	if err != nil {
		if errors.Is(err, core.ErrAttachmentTooLarge) {
			return nil, tooLarge()
		}
		return nil, apiErrorf(http.StatusInternalServerError, "Failed to store attachment")
	}
	return attachment, nil
}

// readUpload takes the one file a multipart request carries. The caller closes it.
//
// THE CAP IS ON THE BODY, before anything is buffered. ParseMultipartForm's argument is a MEMORY
// budget and not a limit — past it the form SPILLS TO A TEMPORARY FILE and parsing succeeds — so an
// oversized upload used to be accepted, written to the server's disk, and then measured. The only
// real cap lived in AttachmentStore, which the node route never reached. MaxBytesReader is what
// makes it a refusal: the request is cut off at the cap plus the envelope the form needs around
// it, and core.AttachmentStore.Store then decides on the file itself.
func readUpload(w http.ResponseWriter, r *http.Request) (multipart.File, *multipart.FileHeader, error) {
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBody)

	if err := r.ParseMultipartForm(multipartMemoryBudget); err != nil {
		var oversized *http.MaxBytesError
		if errors.As(err, &oversized) {
			return nil, nil, tooLarge()
		}
		return nil, nil, apiErrorf(http.StatusBadRequest, "Invalid file upload")
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		return nil, nil, apiErrorf(http.StatusBadRequest, "Invalid file upload")
	}
	return file, header, nil
}

// tooLarge is the ONE refusal both upload routes give for a file over the cap, and it names the
// cap: a caller told only "413" cannot tell how much smaller to make the file.
func tooLarge() error {
	return apiErrorf(http.StatusRequestEntityTooLarge,
		"File too large: the limit is %d bytes", core.MaxAttachmentSize)
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

	// RESOLVED BY ID ALONE, wherever the file is kept. This route used to search Node.Attachments
	// and nothing else, so every file uploaded to an ENTRY answered 404 here — for an id this
	// server had just handed out. A caller has an id and a node; which entry of which event holds
	// the bytes is the engine's bookkeeping and not something the caller can be asked to remember.
	//
	// The bytes are COPIED out under the read hold and written afterwards. This is the one route
	// whose whole purpose is the file's contents, so it is also the one place they may leave.
	var attachment *core.Attachment
	if err := server.readNode(path, userID, core.ReadPermission, func(node *core.Node) error {
		found, _, err := node.FindAttachment(attachmentID)
		if err != nil {
			return apiErrorf(http.StatusNotFound, "Attachment not found")
		}
		attachment = found
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

	attachment, err := storeUpload(w, r, userID)
	if err != nil {
		writeAPIError(w, err)
		return
	}

	entryID := ""
	if err := server.changeNode(path, userID, core.WritePermission, func(node *core.Node) error {
		if err := node.AddEntryAttachment(eventID, index, attachment, userID); err != nil {
			return apiErrorf(http.StatusInternalServerError, "Failed to add attachment to entry")
		}
		// The entry this landed on, NAMED. The route addresses it by index because that is the URL
		// it has always had; the feed says the id, because an index is invalidated by the deletes
		// that now exist and a client watching one entry needs a name that is not.
		entryID = node.Events[eventID].Entries[index].ID
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
	announced.EntryID = entryID
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

	// The SAME resolution the download route uses, and the same refusal: an id that is not there
	// is 404 and not 500. Both used to be wrong here — the delete searched the node's own map
	// alone, so an entry attachment could not be removed, and it reported that as the server
	// having broken, which is a thing a client retries forever.
	if err := server.changeNode(path, userID, core.WritePermission, func(node *core.Node) error {
		err := node.DeleteAttachment(attachmentID, userID)
		if errors.Is(err, core.ErrAttachmentNotFound) {
			return apiErrorf(http.StatusNotFound, "Attachment not found")
		}
		if err != nil {
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
