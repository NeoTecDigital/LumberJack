// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package extension

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/NeoTecDigital/LumberJack/core"
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

// SecondFactor runs after the engine has verified the password and counted the attempt. At most one
// is registered. Without one, the engine refuses the password login of an account enrolled in a
// second factor (users[].mfa_enabled, or an id under the root's preserved account_security).
type SecondFactor interface {
	Required(tx ReadTx, user core.User) bool
	AfterPassword(ctx context.Context, user core.User, login Login) (*Challenge, error)
}

// Login is what a password exchange carried besides its credential.
type Login struct {
	Transport string                     // "bearer" (/login) or "browser" (POST /session)
	Extras    map[string]json.RawMessage // body fields the engine does not read, e.g. phone_last4
}

// Challenge is answered verbatim, with Cache-Control: no-store, in place of a session. A nil
// Challenge from AfterPassword means issue the session now.
type Challenge struct{ Body any }

// ErrInvalidCredentials is the answer to a credential that does not verify; the engine counts it.
var ErrInvalidCredentials = &Error{Status: 401, Message: "Invalid credentials"}

// Sessions is how an authenticator or a second factor finishes a login. It is the engine's session
// registry, credential epochs and lockout, unchanged. RecordLoginFailure and ClearLoginFailures write
// through the engine's write path and must be called with no hold.
type Sessions interface {
	Issue(tx Tx, userID string, o SessionOptions) (TokenPair, error)
	RecordLoginFailure(userID string)
	ClearLoginFailures(userID string)
	RetireCredentials(tx Tx, userID string) // the credential-epoch bump
}

// SessionOptions says which credential a login answers with.
type SessionOptions struct {
	Transport string // "bearer": a session and refresh JWT pair, as /login; "browser": an ms_ token, as POST /session
}

// TokenPair is an issued session. A bearer issue fills SessionToken and RefreshToken; a browser
// issue fills SessionToken (the ms_ token) and ExpiresAt.
type TokenPair struct {
	SessionToken string `json:"session_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresAt    int64  `json:"expires_at,omitempty"`
}
