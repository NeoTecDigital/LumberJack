// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"encoding/json"
	"net/http"
	"time"
)

func timeFromActivationExpiry(expires float64) time.Time { return time.Unix(0, int64(expires*1e9)) }

func activationProjection(actor activationActor) map[string]any {
	return map[string]any{"principalId": actor.PrincipalID, "kind": actor.Kind, "scope": actor.Scope,
		"grantRevision": actor.GrantRevision, "resourceRevision": actor.ResourceRevision}
}

func (s *Server) handleAuthenticatedPrincipal(w http.ResponseWriter, r *http.Request) {
	actor, ok := r.Context().Value(activationContextKey{}).(activationActor)
	if !ok {
		s.handleApplicationPrincipal(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	result := activationProjection(actor)
	result["id"] = actor.PrincipalID
	_ = json.NewEncoder(w).Encode(result)
}

func (s *Server) handleActivationProbe(w http.ResponseWriter, r *http.Request) {
	actor, ok := r.Context().Value(activationContextKey{}).(activationActor)
	if !ok {
		activationWriteFailure(w, activationFailure{"access_denied", 403})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(activationProjection(actor))
}
