// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package extension

import (
	"context"
	"encoding/json"
	"net/http"
)

// RequestAuthenticator claims requests carrying its own credential type, BEFORE the engine's bearer
// check. Authenticators are asked in registration order; the first claim that is not NotMine decides.
type RequestAuthenticator interface {
	AuthenticateRequest(r *http.Request) (Principal, Claim)
	MalformedHeaders(headers map[string]string) bool // the application transport refuses these 401
}

// Claim is an authenticator's answer about one request.
type Claim uint8

const (
	NotMine  Claim = iota // the engine continues with the next authenticator, then its own bearer check
	Accepted              // Principal is authenticated
	Refused               // the credential is this authenticator's and invalid: 401, no fall-through
)

// Principal is who an accepted request acts as.
type Principal struct {
	UserID     string         // what handlers see as the caller
	Projection map[string]any // what GET /principal answers; nil = the engine's {id, username, admin}
}

type principalKey struct{}

// WithPrincipal is the context a request carries once an authenticator accepted it.
func WithPrincipal(ctx context.Context, principal Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, principal)
}

// PrincipalFrom answers the principal an authenticator accepted for this request, if one did.
func PrincipalFrom(ctx context.Context) (Principal, bool) {
	principal, ok := ctx.Value(principalKey{}).(Principal)
	return principal, ok
}

// Configurable receives its named parts of application_configure before the application opens. A
// part no extension declared is refused, never ignored.
type Configurable interface {
	Configure(part string, raw json.RawMessage) error
}
