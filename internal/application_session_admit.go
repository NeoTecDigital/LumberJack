// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/NeoTecDigital/LumberJack/core"
	"github.com/NeoTecDigital/LumberJack/internal/admission"
)

// A SESSION A SIGNATURE ASKED FOR. The account authority (Activity, over GoTrue) proves who is
// signed in, at what assurance and under which grant, and signs a one-minute admission saying so.
// This engine verifies the signature, spends the admission's command once, makes sure the account
// exists under the name the authority gave it, and mints an ms_ session. It checks no password and
// no factor of its own, and trusts no browser flag: the assurance was decided before the signature
// existed.
//
// The lease is short because that is what stands in for a revocation channel: the client renews it
// with a fresh admission on every auth refresh, so an out-of-band revocation lags at most this long.
const delegatedSessionTTL = 10 * 60

const (
	admissionRefusal = "Admission refused"
	// usernameTakenRefusal is the one refusal somebody can act on. It is only ever said to a caller
	// holding a verified admission, so it tells a stranger nothing.
	usernameTakenRefusal = "That username belongs to another account"
	usernameTaken        = sessionAdmissionRefusal("username_taken")
	admissionMaxBytes    = 16 << 10
	profileMaxBytes      = 4 << 10
	// A username's limit is the one the conversation and sign-in routes already hold it to, and an
	// email's is what auth.users.email can carry.
	usernameMaxBytes = 128
	emailMaxBytes    = 1020
	// engineUserNamespace is the prefix core.GenerateUserID gives every account this engine made for
	// itself. Such an id is only ever found, never created: a migrated person sent to the wrong
	// forest fails here instead of quietly getting an empty workspace.
	engineUserNamespace = "user-"
)

// A principal becomes the account id and part of its home's node name (personal-<id>), and a node
// path is split on "/". The admission's atom alphabet allows a slash; an account id cannot hold one.
var delegatablePrincipal = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@-]{0,255}$`)

// sessionProfile is what the account authority says this person is called. The admission's signature
// binds it by digest, so it is as trustworthy as the principal beside it.
type sessionProfile struct {
	Username string `json:"username"`
	Email    string `json:"email"`
}

func printable(text string) bool {
	return strings.IndexFunc(text, unicode.IsControl) < 0
}

// validSessionUsername is the engine's rule for a name: what the sharing and conversation routes can
// find again by exact match, so nothing they trim away, and nothing they would refuse.
func validSessionUsername(name string) bool {
	return name != "" && name == strings.TrimSpace(name) && len(name) <= usernameMaxBytes && printable(name)
}

func validSessionEmail(email string) bool {
	if email == "" {
		return true // A phone-only identity has none; it is the username that must exist.
	}
	return len(email) <= emailMaxBytes && printable(email) && strings.Contains(email, "@") && !strings.ContainsFunc(email, unicode.IsSpace)
}

// valid refuses the id as a name: it would reach every screen that says who somebody is.
func (p sessionProfile) valid(principal string) bool {
	return validSessionUsername(p.Username) && validSessionEmail(p.Email) && !strings.EqualFold(p.Username, principal)
}

// strictSessionJSON reads one JSON value: declared fields only, no duplicate, no null, nothing after.
func strictSessionJSON(body []byte, target any) error {
	if err := checkActivationJSON(body); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}

// openSessionAdmission reads the opaque string the browser carried: the signed envelope and the
// profile it binds. The profile is hashed as the bytes that arrived, which are the canonical bytes
// the authority signed or the signature does not hold.
func openSessionAdmission(verifier *admission.Verifier, raw []byte, now int64) (admission.Claims, sessionProfile, error) {
	var wire struct {
		Envelope json.RawMessage `json:"envelope"`
		Profile  json.RawMessage `json:"profile"`
	}
	var profile sessionProfile
	if strictSessionJSON(raw, &wire) != nil || len(wire.Envelope) == 0 || len(wire.Profile) == 0 || len(wire.Profile) > profileMaxBytes {
		return admission.Claims{}, profile, admission.ErrDenied
	}
	claims, err := verifier.VerifySession(wire.Envelope, wire.Profile, now)
	if err != nil {
		return admission.Claims{}, profile, err
	}
	if strictSessionJSON(wire.Profile, &profile) != nil || !profile.valid(claims.PrincipalID) {
		return admission.Claims{}, profile, admission.ErrDenied
	}
	return claims, profile, nil
}

// SessionAdmissionConfig is the public half of the account authority's signing key.
type SessionAdmissionConfig struct {
	KeyID     string `json:"keyId"`
	PublicKey string `json:"publicKey"`
	Issuer    string `json:"issuer"`
	Audience  string `json:"audience"`
}

// DecodeSessionAdmissionConfig reads a configuration strictly: every field, no other, no duplicate.
func DecodeSessionAdmissionConfig(body []byte) (SessionAdmissionConfig, error) {
	var config SessionAdmissionConfig
	if err := strictSessionJSON(body, &config); err != nil {
		return config, fmt.Errorf("invalid session admission configuration")
	}
	_, err := newSessionAdmissionVerifier(config)
	return config, err
}

func newSessionAdmissionVerifier(config SessionAdmissionConfig) (*admission.Verifier, error) {
	key, err := base64.RawURLEncoding.Strict().DecodeString(config.PublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("session admission requires an Ed25519 public key")
	}
	verifier, err := admission.New(map[string]ed25519.PublicKey{config.KeyID: key}, config.Issuer, config.Audience, admission.MaxSessionLifetime)
	if err != nil {
		return nil, fmt.Errorf("session admission requires a key id, an issuer and an audience")
	}
	return verifier, nil
}

// ConfigureSessionAdmission is explicit and one-shot. Without it every admission is refused.
func (s *Server) ConfigureSessionAdmission(config SessionAdmissionConfig) error {
	verifier, err := newSessionAdmissionVerifier(config)
	if err != nil {
		return err
	}
	if !s.sessionAdmission.CompareAndSwap(nil, verifier) {
		return fmt.Errorf("session admission already configured")
	}
	return nil
}

func sessionAdmissionInput(r *http.Request) (string, bool) {
	var input struct {
		Admission string `json:"admission"`
	}
	decoder := json.NewDecoder(io.LimitReader(r.Body, admissionMaxBytes))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || input.Admission == "" {
		return "", false
	}
	return input.Admission, true
}

// handleSessionAdmit is POST /session/admit, public for the reason /session is: the admission is
// the credential. EVERY REFUSAL OF AN ADMISSION IS THE SAME 401, so nothing tells a caller which
// check it failed; the log says which, by a closed reason, and never carries the admission or a
// name. A verified admission whose username belongs to somebody else is a conflict, and says so.
func (s *Server) handleSessionAdmit(w http.ResponseWriter, r *http.Request) {
	verifier := s.sessionAdmission.Load()
	raw, ok := sessionAdmissionInput(r)
	if verifier == nil || !ok {
		s.refuseSessionAdmission(w, "unconfigured_or_malformed")
		return
	}
	claims, profile, err := openSessionAdmission(verifier, []byte(raw), time.Now().Unix())
	if err != nil {
		s.refuseSessionAdmission(w, "not_verified")
		return
	}
	token, user, expiresAt, err := s.mintDelegatedSession(claims, profile)
	if refusal, refused := err.(sessionAdmissionRefusal); refused {
		s.refuseSessionAdmission(w, string(refusal))
		return
	}
	if err != nil {
		writeAPIError(w, err)
		return
	}
	securityJSON(w, map[string]interface{}{"id": user.ID, "username": user.Username, "token": token, "expires_at": expiresAt, "absolute_expires_at": expiresAt})
}

func (s *Server) refuseSessionAdmission(w http.ResponseWriter, reason string) {
	s.logger.Warn("Session admission refused: %s", reason)
	if reason == string(usernameTaken) {
		http.Error(w, usernameTakenRefusal, http.StatusConflict)
		return
	}
	http.Error(w, admissionRefusal, http.StatusUnauthorized)
}

// sessionAdmissionRefusal is a verified admission this engine will not honour, by a closed reason.
type sessionAdmissionRefusal string

func (r sessionAdmissionRefusal) Error() string { return string(r) }

// mintDelegatedSession spends the command, ensures the account and stores the session under ONE
// exclusive hold, so the record of a spent command and the session it paid for are one durable
// snapshot: a crash between them is not possible, and neither is a replay that races the mint.
// A refusal mutates nothing, which matters because changeForest does not roll a change back.
func (s *Server) mintDelegatedSession(claims admission.Claims, named sessionProfile) (string, core.User, int64, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", core.User{}, 0, apiErrorf(http.StatusInternalServerError, "Session unavailable")
	}
	token := "ms_" + hex.EncodeToString(raw)
	var user core.User
	var expiresAt int64
	err := s.changeForest(func() error {
		now := time.Now().Unix()
		if held, spent := s.forest.AdmittedCommands[claims.CommandID]; spent && held > now {
			return sessionAdmissionRefusal("command_spent")
		}
		profile, err := s.delegatedAccountLocked(claims.PrincipalID, named, now)
		if err != nil {
			return err
		}
		user = *profile
		s.spendAdmittedCommandLocked(claims, now)
		s.sweepApplicationSessionsLocked(user.ID, now)
		expiresAt = now + delegatedSessionTTL
		s.forest.ApplicationSessions[s.sessionHash(token)] = core.ApplicationSession{UserID: user.ID, CreatedAt: now, LastActiveAt: now,
			ExpiresAt: expiresAt, CredentialEpoch: user.CredentialEpoch, Delegated: true, SourceSession: claims.SessionID}
		return nil
	})
	return token, user, expiresAt, err
}

// delegatedAccountLocked finds the principal's account, creating it when that is allowed: id =
// principal, no password, root read as /users/create gives, named as the profile says. An account a
// signature can reach is never an operator's, whatever the signature says. A name that belongs to
// another principal is refused, never merged, whichever account is asking for it.
func (s *Server) delegatedAccountLocked(principal string, named sessionProfile, now int64) (*core.User, error) {
	if !delegatablePrincipal.MatchString(principal) || principal == SystemUserID {
		return nil, sessionAdmissionRefusal("principal_refused")
	}
	var existing *core.User
	for index := range s.forest.Users {
		user := &s.forest.Users[index]
		if user.ID == principal {
			existing = user
		} else if strings.EqualFold(user.Username, named.Username) {
			return nil, usernameTaken
		}
	}
	if existing != nil {
		return s.renamedAccountLocked(existing, named, now)
	}
	if strings.HasPrefix(principal, engineUserNamespace) {
		return nil, sessionAdmissionRefusal("foreign_engine_account")
	}
	account := core.User{ID: principal, Username: named.Username, Email: named.Email}
	if err := s.forest.AssignUser(account, core.ReadPermission); err != nil {
		return nil, apiErrorf(http.StatusInternalServerError, "%v", err)
	}
	return s.forest.GetUserProfile(principal)
}

// renamedAccountLocked brings a known account's name and email to what the authority says now, and
// nothing else about it. Access and membership are held by id, so a new name moves none of them.
func (s *Server) renamedAccountLocked(account *core.User, named sessionProfile, now int64) (*core.User, error) {
	if s.forest.CheckPermission(account.ID, core.AdminPermission) {
		return nil, sessionAdmissionRefusal("operator_refused")
	}
	if account.LockedUntil > now {
		return nil, sessionAdmissionRefusal("account_locked")
	}
	account.Username, account.Email = named.Username, named.Email
	return account, nil
}

// spendAdmittedCommandLocked records the command until its admission could no longer verify, and
// forgets those past that point. The ledger can only hold what the signing key issued in the last
// minute, so it stays small without a separate bound.
func (s *Server) spendAdmittedCommandLocked(claims admission.Claims, now int64) {
	if s.forest.AdmittedCommands == nil {
		s.forest.AdmittedCommands = map[string]int64{}
	}
	for command, expiresAt := range s.forest.AdmittedCommands {
		if expiresAt <= now {
			delete(s.forest.AdmittedCommands, command)
		}
	}
	s.forest.AdmittedCommands[claims.CommandID] = claims.ExpiresAt
}

// endApplicationSessionLocked forgets a session. A delegated one takes the rest of its family with
// it: renewal leaves the previous lease running for a stream still using it, so sign-out has to end
// every lease its source session holds or it would end only the newest.
func (s *Server) endApplicationSessionLocked(key string) {
	session, exists := s.forest.ApplicationSessions[key]
	delete(s.forest.ApplicationSessions, key)
	if !exists || !session.Delegated {
		return
	}
	for other, held := range s.forest.ApplicationSessions {
		if held.Delegated && held.UserID == session.UserID && held.SourceSession == session.SourceSession {
			delete(s.forest.ApplicationSessions, other)
		}
	}
}
