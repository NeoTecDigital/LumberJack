// Written by Richard Christopher, Copyright 2026 Mindfull
package internal

import (
	"context"
	"net/http"
)

// Only the verified business-admission dispatcher can install this value. A
// browser body/header or legacy native user ID is never an account identity.
type businessScopeKey struct{}
type authenticatedBusinessScope struct {
	AccountID   string
	WorkspaceID string
}

func AuthenticatedContentScope(r *http.Request) (string, string, error) {
	scope, ok := r.Context().Value(businessScopeKey{}).(authenticatedBusinessScope)
	if !ok || scope.AccountID == "" {
		return "", "", apiErrorf(http.StatusServiceUnavailable, "handoff_unavailable")
	}
	return scope.AccountID, scope.WorkspaceID, nil
}

// Private installation point: do not export a browser-callable scope setter.
// Integration must call this only after signed admission, current barrier and
// native ACL checks; absent integration leaves encrypted operations closed.
func withAuthenticatedBusinessScope(r *http.Request, scope authenticatedBusinessScope) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), businessScopeKey{}, scope))
}
