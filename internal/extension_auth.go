// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"

	"github.com/NeoTecDigital/LumberJack/extension"
)

// Request authentication and configuration parts through the extension seams
// (docs/extension-api.md §4.4, §4.7).

// ErrUndeclaredPart refuses an application_configure part no extension declared.
var ErrUndeclaredPart = errors.New("lumberjack: an application configuration part no extension declared")

func (server *Server) authenticators() []extension.RequestAuthenticator {
	if server.extensions == nil {
		return nil
	}
	return server.extensions.authenticators
}

// serveExtensionAuth asks each authenticator, in registration order, whether the request is its
// own. It answers true when one decided: an accepted request has run next with its principal, and a
// refused one has been answered 401 without falling through to any other credential type.
func (server *Server) serveExtensionAuth(next http.HandlerFunc, w http.ResponseWriter, r *http.Request) bool {
	for _, authenticator := range server.authenticators() {
		principal, claim := authenticator.AuthenticateRequest(r)
		switch claim {
		case extension.NotMine:
			continue
		case extension.Accepted:
			if principal.UserID != "" {
				ctx := context.WithValue(r.Context(), "user_id", principal.UserID)
				next.ServeHTTP(w, r.WithContext(extension.WithPrincipal(ctx, principal)))
				return true
			}
		}
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return true
	}
	return false
}

// malformedHeaders reports whether any authenticator refuses the headers of an application call.
func (server *Server) malformedHeaders(headers map[string]string) bool {
	for _, authenticator := range server.authenticators() {
		if authenticator.MalformedHeaders(headers) {
			return true
		}
	}
	return false
}

// handlePrincipal answers GET /principal: the projection an authenticator gave its principal, or the
// engine's own {id, username, admin} for an account in the forest.
func (server *Server) handlePrincipal(w http.ResponseWriter, r *http.Request) {
	principal, ok := extension.PrincipalFrom(r.Context())
	if !ok || principal.Projection == nil {
		server.handleApplicationPrincipal(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(principal.Projection)
}

// ConfigureParts hands each part of application_configure to the extension that declared it, in
// name order, before the application opens. A part nobody declared is refused, never ignored — a
// null value included, which is how the cut build answered a null part.
func (server *Server) ConfigureParts(parts map[string]json.RawMessage) error {
	names := make([]string, 0, len(parts))
	for name, raw := range parts {
		if len(raw) != 0 {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		owner := server.configurableFor(name)
		if owner == nil {
			return fmt.Errorf("%w: %q", ErrUndeclaredPart, name)
		}
		if err := owner.Configure(name, parts[name]); err != nil {
			return fmt.Errorf("configuration part %q: %w", name, err)
		}
	}
	return nil
}

func (server *Server) configurableFor(part string) extension.Configurable {
	if server.extensions == nil {
		return nil
	}
	return server.extensions.configurables[part]
}
