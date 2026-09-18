package internal

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/NeoTecDigital/LumberJack/internal/core"
)

// POST /entries and PATCH /entries/{id}/metadata — writing an entry, and reordering or reparenting
// one after the fact.
//
// These are the write half of what DELETE /entries/{id} was the delete half of, and they exist for
// the same reason the id does: an entry addressed by (node_path, event_id, entry_index) could be
// created and removed but never NESTED or REORDERED, because an index is not a place you can move a
// thing to. POST writes a node-level entry the way /events/append writes an event-level one — the
// AUTHOR IS THE SESSION, never a field in the body, so a caller cannot forge who wrote a record.
// PATCH addresses the entry by its id (the lookup handleDeleteEntry uses) and merges.

// handleCreateEntry writes one node-level entry and answers it, minted id and all.
//
// AUTHORED BY THE CALLER. AddEntry stamps Entry.UserID with the session's user, exactly as
// /events/append does; there is no user_id in the body to read, because a body that named the author
// would let one caller write a record in another's name.
func (server *Server) handleCreateEntry(w http.ResponseWriter, r *http.Request) {
	server.logger.Enter("CreateEntry")
	defer server.logger.Exit("CreateEntry")

	userID, ok := userIDFrom(r)
	if !ok {
		http.Error(w, "No user in session", http.StatusUnauthorized)
		return
	}

	var request struct {
		Path     string                 `json:"path"`
		Content  string                 `json:"content"`
		Metadata map[string]interface{} `json:"metadata"`
		ParentID string                 `json:"parent_id"`
		Rank     string                 `json:"rank"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var created core.Entry
	entryIndex := -1
	err := server.changeNode(request.Path, userID, core.WritePermission, func(node *core.Node) error {
		created = node.AddEntry(request.Content, request.Metadata, userID, request.ParentID, request.Rank)
		// The index of what was just appended, read INSIDE the hold. It is this entry's index only
		// until the next append, which is exactly why the id is what a client is expected to hold —
		// the index is reported for the feed's benefit and is history the moment this returns.
		entryIndex = len(node.Entries) - 1
		return nil
	})
	if err != nil {
		writeAPIError(w, err)
		return
	}

	// Announced on the feed like every other entry write, under the EXISTING entry_added kind: the
	// feed re-reads the node and finds the new entry, nested and ranked as it was stored.
	announced := mutation(mutationEntryAdded, request.Path)
	announced.EntryID = created.ID
	announced.EntryIndex = entryIndex
	server.publish(announced)
	server.logger.Success("Created entry %s on %s for %s", created.ID, request.Path, userID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(newEntryView(created))
}

// handlePatchEntryMetadata merges metadata into one entry and, when they are given, rewrites its
// rank and parent — a reorder or a reparent written as data.
//
// Addressed by ID and ?path=, the way DELETE /entries/{id} is: the id names the entry and the path
// says which node to look on. The merge follows PATCH /nodes/{path}/metadata's rule — a metadata key
// set to null is DELETED — and rank and parent are absent-means-unchanged, so a caller nudging one
// key does not blank the order it did not mention.
func (server *Server) handlePatchEntryMetadata(w http.ResponseWriter, r *http.Request) {
	server.logger.Enter("PatchEntryMetadata")
	defer server.logger.Exit("PatchEntryMetadata")

	userID, ok := userIDFrom(r)
	if !ok {
		http.Error(w, "No user in session", http.StatusUnauthorized)
		return
	}

	path := r.URL.Query().Get("path")
	entryID := mux.Vars(r)["id"]

	// Rank and ParentID are POINTERS so an absent field (nil) is distinguishable from one set to the
	// empty string — the difference between "leave the order alone" and "un-rank this entry".
	var request struct {
		Metadata map[string]interface{} `json:"metadata"`
		Rank     *string                `json:"rank"`
		ParentID *string                `json:"parent_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var updated core.Entry
	err := server.changeNode(path, userID, core.WritePermission, func(node *core.Node) error {
		entry, err := node.PatchEntry(entryID, userID, request.Metadata, request.Rank, request.ParentID)
		if err != nil {
			return asEntryError(err)
		}
		updated = *entry
		return nil
	})
	if err != nil {
		writeAPIError(w, err)
		return
	}

	server.logger.Success("Patched entry %s on %s for %s", entryID, path, userID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(newEntryView(updated))
}
