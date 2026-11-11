// Written by Richard Christopher, Copyright 2026 Richard Christopher
package internal

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/NeoTecDigital/LumberJack/internal/core"
	"github.com/gorilla/mux"
)

// The object routes: raw bytes in, raw bytes out, addressed by their BLAKE3.
//
// PERMISSION is the forest root's. An object belongs to no node — it is bytes that trees and
// commits will later name — so the one node every caller is granted on is the one the check is made
// against: WritePermission on the root to put, ReadPermission on the root to get. A session granted
// only deeper than the root is refused 403 here, as it is on /users.
//
// THE FOREST IS NOT CHANGED. The permission check takes the shared hold for the lookup and lets go
// of it; the store is written outside it, and `.dat` is not rewritten. Nothing is published to
// /stream either: the feed announces mutations of the graph, and this is not one.
//
// THROUGH THE IN-PROCESS `call` PATH the body is the `body` field of the JSON envelope, which Go
// encodes as standard base64 — so a binary object travels as base64 in and base64 out, and
// ApplicationCall's 64 MiB cap (applicationLimit) applies to the DECODED bytes in both directions.
// Through HTTP the body is the bytes themselves. The per-object cap is the configured
// `max_object_bytes`, or DefaultMaxObjectBytes; the effective cap through `call` is the smaller of
// that and applicationLimit.

// maxObjectBytes is the per-object cap this install runs under.
func (server *Server) maxObjectBytes() int64 {
	if server.config.Process.MaxObjectBytes > 0 {
		return server.config.Process.MaxObjectBytes
	}
	return DefaultMaxObjectBytes
}

// objects opens the object store on first use and hands the same one back after. A failed open is
// NOT remembered: the usual reason is the key wrapper being unreachable, and the next request is
// allowed to try again rather than being told forever about a KMS outage that has ended.
func (server *Server) objects() (*objectStore, error) {
	server.objectsMu.Lock()
	defer server.objectsMu.Unlock()
	if server.objectStore != nil {
		return server.objectStore, nil
	}
	storage, err := server.storageCodec()
	if err != nil {
		return nil, err
	}
	store, err := openObjectStore(ObjectsPath(server.config), server.maxObjectBytes(), storage)
	if err != nil {
		return nil, err
	}
	for _, repair := range store.repairs {
		server.logger.Warn("Object store: %s", repair)
	}
	store.repairs = nil
	server.objectStore = store
	return store, nil
}

// closeObjects releases the store at shutdown, if it was ever opened.
func (server *Server) closeObjects() {
	server.objectsMu.Lock()
	defer server.objectsMu.Unlock()
	if server.objectStore != nil {
		server.objectStore.close()
		server.objectStore = nil
	}
}

// rootPermission confirms the caller holds permission on the root of the forest, under the shared
// hold, and answers the refusal the same way every node route does.
func (server *Server) rootPermission(r *http.Request, permission core.Permission) (string, error) {
	userID, ok := userIDFrom(r)
	if !ok {
		return "", apiErrorf(http.StatusUnauthorized, "No user in session")
	}
	return userID, server.readNode("", userID, permission, func(*core.Node) error { return nil })
}

// handlePutObject is POST /objects: the raw body is the object.
func (server *Server) handlePutObject(w http.ResponseWriter, r *http.Request) {
	if _, err := server.rootPermission(r, core.WritePermission); err != nil {
		writeAPIError(w, err)
		return
	}
	store, err := server.objects()
	if err != nil {
		writeAPIError(w, apiErrorf(http.StatusInternalServerError, "Object store unavailable: %v", err))
		return
	}

	// The cap is on the body before anything is held: MaxBytesReader cuts the read at the limit, so an
	// oversized upload is refused rather than buffered and then measured.
	r.Body = http.MaxBytesReader(w, r.Body, store.maxBytes)
	data, err := io.ReadAll(r.Body)
	if err != nil {
		var oversized *http.MaxBytesError
		if errors.As(err, &oversized) {
			writeAPIError(w, objectTooLarge(store.maxBytes))
			return
		}
		writeAPIError(w, apiErrorf(http.StatusBadRequest, "Could not read the object"))
		return
	}

	receipt, err := store.put(data)
	if err != nil {
		if errors.Is(err, ErrObjectTooLarge) {
			writeAPIError(w, objectTooLarge(store.maxBytes))
			return
		}
		server.logger.Failure("Object put failed: %v", err)
		writeAPIError(w, apiErrorf(http.StatusInternalServerError, "Failed to store object"))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(receipt)
}

// objectTooLarge names the cap, as the attachment refusal does.
func objectTooLarge(limit int64) error {
	return apiErrorf(http.StatusRequestEntityTooLarge, "Object too large: the limit is %d bytes", limit)
}

// handleGetObject is GET and HEAD /objects/{id}. GET answers the verified bytes; HEAD answers the
// size without reading them.
func (server *Server) handleGetObject(w http.ResponseWriter, r *http.Request) {
	if _, err := server.rootPermission(r, core.ReadPermission); err != nil {
		writeAPIError(w, err)
		return
	}
	id, err := parseObjectID(mux.Vars(r)["id"])
	if err != nil {
		writeAPIError(w, apiErrorf(http.StatusBadRequest, "%v", err))
		return
	}
	store, err := server.objects()
	if err != nil {
		writeAPIError(w, apiErrorf(http.StatusInternalServerError, "Object store unavailable: %v", err))
		return
	}

	if r.Method == http.MethodHead {
		size, err := store.stat(id)
		if err != nil {
			writeAPIError(w, objectReadError(err))
			return
		}
		writeObjectHeaders(w, size)
		w.WriteHeader(http.StatusOK)
		return
	}

	data, err := store.get(id)
	if err != nil {
		writeAPIError(w, objectReadError(err))
		return
	}
	writeObjectHeaders(w, int64(len(data)))
	w.Write(data)
}

func writeObjectHeaders(w http.ResponseWriter, size int64) {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	w.Header().Set("X-Content-Type-Options", "nosniff")
}

// objectReadError turns a store failure into the status it deserves: an id that is not there is 404,
// and a record that no longer hashes to its id is a 500 that SAYS corrupt — a client is not told
// "not found" about bytes the engine once acknowledged.
func objectReadError(err error) error {
	switch {
	case errors.Is(err, ErrObjectNotFound):
		return apiErrorf(http.StatusNotFound, "Object not found")
	case errors.Is(err, ErrObjectCorrupt):
		return apiErrorf(http.StatusInternalServerError, "%v", err)
	default:
		return apiErrorf(http.StatusInternalServerError, "Failed to read object")
	}
}
