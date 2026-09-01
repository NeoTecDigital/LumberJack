package internal

import (
	"encoding/json"
	"net/http"
)

// handleHealth answers whether the engine is up, WITHOUT authentication.
//
// It exists so that a health check is a health check. The only liveness signal before this was
// POSTing the admin's credentials to /login on a five-second poll, which sent a password across the
// wire hundreds of times an hour and read a 401 — a REFUSAL — as healthy.
//
// The version is READ FROM version.go and not restated here. A constant in this file is how the
// engine came to answer 0.2.0-alpha while 0.3.0-alpha was being tagged: the one thing an operator
// can ask a running service to identify itself with was a copy of a fact owned somewhere else.
//
// The body is written FIELD BY FIELD and not serialized from a struct. A struct grows fields, and a
// route that anyone may call without credentials is the last place a later field should be able to
// appear by itself. Nothing here names a user, a node, a path or a configuration value.
func (server *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	status := map[string]string{
		"status":  "ok",
		"version": Version,
	}

	code := http.StatusOK
	if server.forest == nil {
		// Up enough to answer, not up enough to serve. Saying so is the point of the route.
		status["status"] = "degraded"
		code = http.StatusServiceUnavailable
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(status)
}
