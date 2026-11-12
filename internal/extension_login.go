// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/NeoTecDigital/LumberJack/core"
	"github.com/NeoTecDigital/LumberJack/extension"
	"github.com/NeoTecDigital/LumberJack/internal/slots"
)

// What a verified password earns, and the engine's session registry as an extension sees it
// (docs/extension-api.md §4.4).
//
// THE DEFAULT POSTURE (owner decision Q1(a)). Without a registered SecondFactor a password login
// issues a session. An account already enrolled in a second factor — users[].mfa_enabled, or an id
// under the root's preserved account_security — is REFUSED instead, 401 "second factor required",
// and the refusal is not counted: the password was right, and what is missing is the factor's owner.

func errSecondFactorRequired() error {
	return apiErrorf(http.StatusUnauthorized, "second factor required")
}

func (server *Server) secondFactor() extension.SecondFactor {
	if server.extensions == nil {
		return nil
	}
	return server.extensions.secondFactor
}

// secondFactorEnrolledLocked reports whether an account was enrolled in a second factor by the
// build that carried one: users[].mfa_enabled, or its id is a key of the root's preserved
// "account_security" slot. A slot that does not read as an object closes the door for everyone.
// The caller holds the forest.
func (server *Server) secondFactorEnrolledLocked(user core.User) bool {
	if user.MFAEnabled {
		return true
	}
	held, present := server.forest.Slots(slots.Token{}).Get("account_security")
	if !present {
		return false
	}
	var accounts map[string]json.RawMessage
	if json.Unmarshal(held.Raw, &accounts) != nil {
		return true
	}
	_, enrolled := accounts[user.ID]
	return enrolled
}

// passwordVerified decides what a verified password earns: a challenge to answer instead of a
// session, a session (nil, nil), or the fail-closed refusal. The attempt was already counted by
// authenticateCredential; a login that needs nothing more clears the account's failure budget.
func (server *Server) passwordVerified(ctx context.Context, user *core.User, login extension.Login) (*extension.Challenge, error) {
	factor := server.secondFactor()
	required, enrolled := false, false
	server.readForest(func() {
		if factor != nil {
			required = factor.Required(forestTx{server: server, owner: server.extensions.factorOwner}, *user)
			return
		}
		enrolled = server.secondFactorEnrolledLocked(*user)
	})
	if enrolled {
		return nil, errSecondFactorRequired()
	}
	if !required {
		server.clearLoginFailures(user.ID)
		return nil, nil
	}
	challenge, err := factor.AfterPassword(ctx, *user, login)
	if err != nil {
		return nil, extensionError(err)
	}
	if challenge == nil {
		server.clearLoginFailures(user.ID)
	}
	return challenge, nil
}

// decodeLogin reads a password exchange: the credential the engine checks, and every other body
// field as the login's extras.
func decodeLogin(r *http.Request, transport string) (username, password string, login extension.Login, err error) {
	var fields map[string]json.RawMessage
	if err = json.NewDecoder(r.Body).Decode(&fields); err != nil {
		return "", "", extension.Login{}, err
	}
	for name, target := range map[string]*string{"username": &username, "password": &password} {
		if raw, present := fields[name]; present {
			if err = json.Unmarshal(raw, target); err != nil {
				return "", "", extension.Login{}, err
			}
		}
		delete(fields, name)
	}
	return username, password, extension.Login{Transport: transport, Extras: fields}, nil
}

// writeChallenge answers a second factor's challenge verbatim, uncached.
func writeChallenge(w http.ResponseWriter, challenge *extension.Challenge) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(challenge.Body)
}

// extensionSessions is the engine's session registry, epochs and lockout, for an extension.
type extensionSessions struct{ server *Server }

var errNotThisForest = errors.New("lumberjack: a Tx from another runtime")

func (sessions extensionSessions) locked(tx extension.Tx) error {
	held, ok := tx.(forestTx)
	if !ok || held.server != sessions.server {
		return errNotThisForest
	}
	return nil
}

// Issue registers a session for the account under the hold of tx's change, so the session and the
// change that earned it are one durable snapshot.
func (sessions extensionSessions) Issue(tx extension.Tx, userID string, o extension.SessionOptions) (extension.TokenPair, error) {
	if err := sessions.locked(tx); err != nil {
		return extension.TokenPair{}, err
	}
	server := sessions.server
	token, err := newSessionToken()
	if err != nil {
		return extension.TokenPair{}, err
	}
	session, err := server.registerSessionLocked(userID, nil, token)
	if err != nil {
		return extension.TokenPair{}, err
	}
	if o.Transport == "browser" {
		return extension.TokenPair{SessionToken: token, ExpiresAt: min(session.ExpiresAt, time.Now().Unix()+applicationSessionIdleTTL)}, nil
	}
	profile, err := server.forest.GetUserProfile(userID)
	if err != nil {
		return extension.TokenPair{}, apiErrorf(http.StatusUnauthorized, "Account unavailable")
	}
	pair, err := server.signSessionPair(profile, server.sessionHash(token), session)
	if err != nil {
		return extension.TokenPair{}, err
	}
	return extension.TokenPair{SessionToken: pair.SessionToken, RefreshToken: pair.RefreshToken}, nil
}

func (sessions extensionSessions) RecordLoginFailure(userID string) {
	sessions.server.recordLoginFailure(userID)
}

func (sessions extensionSessions) ClearLoginFailures(userID string) {
	sessions.server.clearLoginFailures(userID)
}

// RetireCredentials moves the account to a new credential epoch inside tx's change.
func (sessions extensionSessions) RetireCredentials(tx extension.Tx, userID string) {
	if sessions.locked(tx) != nil {
		return
	}
	users := sessions.server.forest.Users
	for index := range users {
		if users[index].ID == userID {
			retireCredentialsLocked(&users[index])
		}
	}
}
