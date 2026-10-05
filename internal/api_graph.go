// Written by Richard Christopher, Copyright 2026 Richard Christopher

package internal

import (
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/NeoTecDigital/LumberJack/internal/core"
	"github.com/NeoTecDigital/LumberJack/internal/graph"
	"github.com/gorilla/mux"
)

// The graph routes: the command engine's HTTP surface, on the main router and behind the session
// middleware like every other protected route. The engine's state lives in the forest under the
// `graph` root — see internal/graph — so a 200 from POST /graph/commands means the forest's state
// file holds the change, exactly as it does for every other write.
//
// Permission is checked on the graph root: Write to command, Read to look. Before the first
// command has created that root it is checked on the forest root, and the principal whose command
// creates it becomes its only member — the graph root does NOT inherit the forest root's users.
//
// THESE ROUTES ARE THE ONLY WRITERS BENEATH THAT ROOT. Every generic write route refuses a target
// there (refuseGraphWrite, in forest_lock.go), which is what lets the engine keep the graph decoded
// between commands and what keeps a record's kind, revision and receipts the engine's to change.
//
// A 5xx FROM POST /graph/commands MEANS THE OUTCOME IS UNKNOWN. The command may be in memory and
// not on the disk, so the caller retries THE SAME command id: a command that was applied is
// replayed and flushed again, and one that was not is applied. While the forest is ahead of its
// file every command first tries to flush it; the engine refuses every other command with 503 only
// while that flush still fails.

// graphCommandLimit bounds a command body. A batch of a few thousand entities is a few megabytes.
const graphCommandLimit = 16 << 20

func (s *Server) registerGraphRoutes(router *mux.Router) {
	router.HandleFunc("/graph", s.authMiddleware(s.handleGraphSnapshot)).Methods("GET")
	router.HandleFunc("/graph/events", s.authMiddleware(s.handleGraphEvents)).Methods("GET")
	router.HandleFunc("/graph/commands", s.authMiddleware(s.handleGraphCommand)).Methods("POST")
	router.HandleFunc("/graph/commands/{id}", s.authMiddleware(s.handleGraphReceipt)).Methods("GET")
}

// graphPermittedLocked answers whether the caller holds permission on the graph root, or on the
// forest root while there is no graph root yet. The caller holds the forest.
func (s *Server) graphPermittedLocked(userID string, permission core.Permission) bool {
	node := graph.Root(s.forest)
	if node == nil {
		node = s.forest
	}
	return node.CheckPermission(userID, permission)
}

// readGraph runs read under the shared hold once the caller is known and may read the graph, and
// answers whatever it produced.
func (s *Server) readGraph(w http.ResponseWriter, r *http.Request, read func() (interface{}, error)) {
	userID, ok := userIDFrom(r)
	if !ok {
		writeGraphError(w, http.StatusUnauthorized, "unauthorized", "Sign in required", nil)
		return
	}
	// A READ SHOWS NOTHING THE DISK DOES NOT HOLD. A receipt, the graph or the journal read out of
	// memory while a failed write is outstanding would let a caller act on a command that a kill
	// still loses — the daemon replays from GET /graph/commands/{id}. The read first retries the
	// write, and answers 503 while the store is still behind. See flushOutstandingForest.
	s.flushOutstandingForest()
	if s.persistBehind() {
		s.writeGraphFailure(w, graph.ErrUnavailable)
		return
	}
	var body interface{}
	var err error
	s.readForest(func() {
		if !s.graphPermittedLocked(userID, core.ReadPermission) {
			err = apiErrorf(http.StatusForbidden, "Insufficient permissions")
			return
		}
		body, err = read()
	})
	if err != nil {
		s.writeGraphFailure(w, err)
		return
	}
	writeGraphJSON(w, http.StatusOK, body)
}

func (s *Server) handleGraphSnapshot(w http.ResponseWriter, r *http.Request) {
	s.readGraph(w, r, func() (interface{}, error) { return s.graph.Snapshot(s.forest) })
}

func (s *Server) handleGraphEvents(w http.ResponseWriter, r *http.Request) {
	since, sinceErr := graphQueryUint(r, "since")
	limit, limitErr := graphQueryUint(r, "limit")
	if sinceErr != nil || limitErr != nil || limit > math.MaxInt32 {
		writeGraphError(w, http.StatusBadRequest, "invalid_query", "since and limit must be unsigned integers", nil)
		return
	}
	s.readGraph(w, r, func() (interface{}, error) { return graph.Events(s.forest, since, int(limit)) })
}

func graphQueryUint(r *http.Request, key string) (uint64, error) {
	text := r.URL.Query().Get(key)
	if text == "" {
		return 0, nil
	}
	return strconv.ParseUint(text, 10, 64)
}

func (s *Server) handleGraphReceipt(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	s.readGraph(w, r, func() (interface{}, error) {
		receipt, found, err := graph.ReceiptFor(s.forest, id)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, apiErrorf(http.StatusNotFound, "command receipt not found")
		}
		return receipt, nil
	})
}

// handleGraphCommand commits one batch. Permission, validation and the write all happen under the
// one exclusive hold, and the answer waits for the state file.
func (s *Server) handleGraphCommand(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFrom(r)
	if !ok {
		writeGraphError(w, http.StatusUnauthorized, "unauthorized", "Sign in required", nil)
		return
	}
	cmd, err := decodeGraphCommand(w, r)
	if err != nil {
		writeGraphError(w, http.StatusBadRequest, "invalid_command", err.Error(), nil)
		return
	}
	s.flushOutstandingForest()
	var result graph.Result
	// TRACKED: the engine says which nodes it wrote, so persistence logs the change and the hub
	// is told from the same set, and neither walks the forest.
	err = s.changeForestTracked(func() (*graph.Touched, error) {
		if !s.graphPermittedLocked(userID, core.WritePermission) {
			return nil, apiErrorf(http.StatusForbidden, "Insufficient permissions")
		}
		var touched *graph.Touched
		var commitErr error
		result, touched, commitErr = s.graph.CommitTracked(s.forest, cmd, userID, time.Now().UTC())
		return touched, commitErr
	})
	if err != nil {
		s.writeGraphFailure(w, err)
		return
	}
	if !result.Replayed {
		s.publish(mutation(mutationMetadataSet, s.canonicalPath(graph.RootName)))
	}
	writeGraphJSON(w, http.StatusOK, result)
}

// flushOutstandingForest writes the forest as it stands when a failed flush left it ahead of its
// file, so that a disk which has recovered is found out by ANY command and not only by a retry of
// the one that failed — a caller that restarted no longer knows that id.
//
// It decides nothing itself. A flush that succeeds ends the doubt and the engine takes the command;
// one that fails has been logged by changeForest and leaves the forest ahead, which the engine
// answers as before: 503 for a new command, and a replay for an id it has seen.
//
// A REPLAY GOES THROUGH THE SAME DURABLE COMMIT AS AN ORIGINAL. The engine answers a stored
// result for an id it has seen, but changeForest does not return until the store is durable to
// the configured policy — the whole forest in snapshot mode, every staged record in tiered mode —
// so a replay of a command whose write failed is answered 5xx until that write lands, never 200
// on the strength of a receipt the disk does not yet hold. TestAReplayIsNotAcknowledgedUntilTheCommandIsDurable
// pins this in both modes.
func (s *Server) flushOutstandingForest() {
	if !s.persistBehind() {
		return
	}
	if s.tier != nil {
		// The records are already staged; only the append, or the sync behind it, is owed. A
		// change of nothing would stage a further record of the same nodes on every retry.
		if err := s.tier.log.Commit(0); err != nil {
			s.logger.Failure("Failed to append to the log: %v", err)
			return
		}
		if err := s.tier.log.Sync(); err != nil {
			s.logger.Failure("Failed to sync the log: %v", err)
		}
		return
	}
	_ = s.changeForest(func() error { return nil })
}

func decodeGraphCommand(w http.ResponseWriter, r *http.Request) (graph.Command, error) {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, graphCommandLimit))
	decoder.DisallowUnknownFields()
	var cmd graph.Command
	if err := decoder.Decode(&cmd); err != nil {
		return cmd, err
	}
	if decoder.More() {
		return cmd, errors.New("command body must contain one JSON value")
	}
	return cmd, nil
}

// writeGraphFailure maps an engine error to its status: a conflict is 409 and names what it
// disagreed with, an invalid command is 400, a command refused while a failed write is still
// outstanding is 503, a refusal carries its own status, and anything else is the server's fault
// and is logged rather than disclosed.
func (s *Server) writeGraphFailure(w http.ResponseWriter, err error) {
	var conflict *graph.Conflict
	var carried *apiError
	switch {
	case errors.As(err, &conflict):
		writeGraphError(w, http.StatusConflict, "conflict", conflict.Error(), conflictDetails(conflict))
	case errors.Is(err, graph.ErrInvalid):
		writeGraphError(w, http.StatusBadRequest, "invalid_command", err.Error(), nil)
	case errors.Is(err, graph.ErrUnavailable):
		writeGraphError(w, http.StatusServiceUnavailable, "unavailable",
			"A previous write has not reached the disk. Retry the command that was answered 5xx, with the same id.", nil)
	case errors.As(err, &carried):
		writeGraphError(w, carried.status, graphErrorCode(carried.status), carried.message, nil)
	default:
		s.logger.Failure("Graph request failed: %v", err)
		writeGraphError(w, http.StatusInternalServerError, "internal", "Graph request failed", nil)
	}
}

func graphErrorCode(status int) string {
	switch status {
	case http.StatusUnauthorized:
		return "unauthorized"
	case http.StatusForbidden:
		return "forbidden"
	case http.StatusNotFound:
		return "not_found"
	case http.StatusInternalServerError:
		return "internal"
	}
	return "error"
}

func conflictDetails(conflict *graph.Conflict) map[string]interface{} {
	details := map[string]interface{}{"collection": conflict.Collection, "id": conflict.ID}
	if conflict.Stale {
		details["expected"] = conflict.Expected
		details["actual"] = conflict.Actual
	}
	return details
}

func writeGraphError(w http.ResponseWriter, status int, code, message string, details map[string]interface{}) {
	body := map[string]interface{}{"code": code, "message": message}
	for key, value := range details {
		body[key] = value
	}
	writeGraphJSON(w, status, map[string]interface{}{"error": body})
}

func writeGraphJSON(w http.ResponseWriter, status int, value interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
