// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package admission

import (
	"crypto/sha256"
	"encoding/hex"
)

// The one command whose subject cannot be expected in advance: who is being admitted is what the
// admission says. Verify compares claims against a trusted command; this binds the claims to one
// another, to the fixed session operation and to the profile that travels beside them.
const (
	SessionOperation = "personal.session.admit"
	SessionProduct   = "momentum"
	// MaxSessionLifetime holds however long a verifier was configured to allow.
	MaxSessionLifetime int64 = 60
)

// VerifySession answers the claims of a signed personal-session admission, or ErrDenied. `profile`
// is the exact bytes the admission carried beside its envelope; the signature covers their digest,
// so a profile changed in the browser, by even a byte of whitespace, is refused here.
//
// A commandId is single use, and that is NOT checked here: spending it belongs in the same
// exclusive hold that mints the session, so a replay and the mint it would race cannot interleave.
func (v *Verifier) VerifySession(raw, profile []byte, now int64) (Claims, error) {
	claims, err := v.authentic(raw)
	if err != nil {
		return Claims{}, err
	}
	if !v.current(claims, now, min(v.lifetime, MaxSessionLifetime)) {
		return Claims{}, ErrDenied
	}
	if claims.Operation != SessionOperation || claims.Scope.Product != SessionProduct || claims.Scope.WorkspaceID != "" {
		return Claims{}, ErrDenied
	}
	digest := sha256.Sum256(profile)
	if claims.ResourceID != claims.PrincipalID || hex.EncodeToString(digest[:]) != claims.BodySHA256 {
		return Claims{}, ErrDenied
	}
	return claims, nil
}
