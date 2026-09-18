package internal

// The native application's compatibility surface. It binds the existing route
// contracts to one embedded forest without opening an HTTP socket. Workspace
// mutations themselves live in ApplyWorkCommand, shared by both transports.
import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

type ApplicationRequest struct {
	Method  string            `json:"method"`
	Target  string            `json:"target"`
	Headers map[string]string `json:"headers"`
	Body    []byte            `json:"body"`
}
type ApplicationResponse struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers"`
	Body    []byte            `json:"body"`
}

// adminReconcileEnv names the ONE opt-in that lets the environment overwrite a stored credential.
// It is read as an exact "1" rather than as any truthy string, because a variable that a typo can
// switch on is a variable that resets an administrator's password by accident.
const adminReconcileEnv = "CORRESPONDER_ADMIN_RECONCILE"

// ConfigureApplication runs once, before an embedder accepts untrusted requests.
// A populated forest keeps its account identities and password hashes.
//
// AND SAYS SO, which it did not. This returned successfully having done nothing whenever the store
// already held users — the right behaviour, since a bootstrap that reset the administrator's password
// on every start would hand the environment file a permanent key to the installation. But it was
// SILENT about it, so an environment whose password no longer matched the stored hash looked exactly
// like one that did, and the only symptom was a login that would not work. That happened here: a
// datastore's admin stopped matching backend/.env after a reset and nothing in any log said so.
//
// The repair is explicit and opt-in. With CORRESPONDER_ADMIN_RECONCILE=1 the configured admin's
// password hash — that account's, and no other's — is replaced from the environment, and the fact is
// logged. Without it the behaviour is exactly what it was, plus the line.
func (s *Server) ConfigureApplication(username, password, secret string) error {
	if len(secret) < 32 || username == "" || len(password) < 12 {
		return fmt.Errorf("application bootstrap needs a username, a password of at least 12 characters and a session key of at least 32 bytes")
	}
	s.jwtConfig = JWTConfig{SecretKey: []byte(secret), ExpiresIn: 24 * time.Hour}
	reconcile := os.Getenv(adminReconcileEnv) == "1"
	// The report is assembled inside the hold and logged outside it, so nothing writes to a log sink
	// while the forest is held exclusively.
	notice := ""
	err := s.changeForest(func() error {
		notice = ""
		populated := false
		for _, user := range s.forest.Users {
			if user.ID != SystemUserID {
				populated = true
				break
			}
		}
		if !populated {
			user := core.User{ID: core.GenerateUserID(), Username: username}
			if err := user.SetPassword(password); err != nil {
				return err
			}
			return s.forest.AssignUser(user, core.AdminPermission)
		}

		if !reconcile {
			notice = fmt.Sprintf("BOOTSTRAP: the configured admin %q was NOT created or updated — this datastore already holds accounts, "+
				"and its stored password is whatever it already was. If a sign-in with the configured password is failing, that is why. "+
				"Set %s=1 to reset THAT ACCOUNT'S password from the environment on the next start.", username, adminReconcileEnv)
			return nil
		}

		// The repair, scoped to one account by name. It updates a password hash and NOTHING else — not
		// permissions, not the id, not any other user — because the failure it answers is exactly one
		// credential having diverged, and widening it would make an environment variable a way to
		// rewrite the account table.
		for i := range s.forest.Users {
			if s.forest.Users[i].Username != username {
				continue
			}
			if err := s.forest.Users[i].SetPassword(password); err != nil {
				return err
			}
			// A repaired credential also clears the lockout counter: an account whose password was
			// wrong has almost certainly been failed into, and leaving it shut would fix the hash and
			// keep the symptom.
			s.forest.Users[i].FailedLogins, s.forest.Users[i].LockedUntil = 0, 0
			notice = fmt.Sprintf("BOOTSTRAP: %s=1 — reset the password of the existing admin account %q from the environment. "+
				"No other account was touched.", adminReconcileEnv, username)
			return nil
		}
		notice = fmt.Sprintf("BOOTSTRAP: %s=1 but this datastore holds no account named %q, so nothing was changed. "+
			"The repair updates one existing account; it does not create one.", adminReconcileEnv, username)
		return nil
	})
	if notice != "" {
		s.logger.Warn("%s", notice)
	}
	if err == nil {
		s.applicationHubEnabled.Store(true)
	}
	return err
}

const applicationLimit = 64 << 20

type applicationWriter struct {
	header   http.Header
	status   int
	body     bytes.Buffer
	overflow bool
}

func (w *applicationWriter) Header() http.Header { return w.header }
func (w *applicationWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}
func (w *applicationWriter) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	if w.body.Len()+len(body) > applicationLimit {
		w.overflow = true
		return 0, fmt.Errorf("response exceeds application limit")
	}
	return w.body.Write(body)
}

// ApplicationCall authenticates using the credential on this request. The
// principal on an embedded service handle is never used for application data.
func (s *Server) ApplicationCall(input ApplicationRequest) ApplicationResponse {
	if len(input.Body) > applicationLimit {
		return applicationError(413, "Request too large")
	}
	target, err := url.ParseRequestURI(input.Target)
	if err != nil || !strings.HasPrefix(input.Target, "/") || target.Host != "" || target.Scheme != "" {
		return applicationError(400, "Invalid target")
	}
	if target.Path == "/stream" {
		return applicationError(400, "Use the Corresponder change dispatcher")
	}
	// /session/mfa joins the credential exchange in this exemption for the same reason /session is in
	// it: a change-delivery backlog must not be able to strand a caller halfway through a login it has
	// already started, holding a challenge that expires in five minutes.
	if input.Method != "GET" && input.Method != "HEAD" && target.Path != "/session" && target.Path != "/session/mfa" && target.Path != "/login" && target.Path != "/refresh" && target.Path != "/changes" {
		full := false
		s.readForest(func() { full = s.forest.Correspondence != nil && len(s.forest.Correspondence.Pending) >= 4096 })
		if full {
			return applicationError(503, "Change delivery is behind. Try again shortly.")
		}
	}
	req, err := http.NewRequest(input.Method, "http://embedded"+input.Target, bytes.NewReader(input.Body))
	if err != nil {
		return applicationError(400, "Invalid request")
	}
	for key, value := range input.Headers {
		req.Header.Set(key, value)
	}
	out := &applicationWriter{header: make(http.Header)}
	if target.Path == "/session" && input.Method == "POST" {
		s.handleApplicationSession(out, req)
	} else if target.Path == "/session/mfa" && input.Method == "POST" {
		// PUBLIC, and deliberately so: the caller holds an "mfa_pending" challenge, not a session, so
		// wrapping this in authMiddleware would make the step that OBTAINS a session require one. The
		// handler validates the challenge bearer itself — see handleApplicationSessionMFA.
		s.handleApplicationSessionMFA(out, req)
	} else if target.Path == "/session" && (input.Method == "GET" || input.Method == "DELETE") {
		s.authMiddleware(s.handleApplicationSession)(out, req)
	} else if target.Path == "/principal" && input.Method == "GET" {
		s.authMiddleware(s.handleApplicationPrincipal)(out, req)
	} else if target.Path == "/notifications" && (input.Method == "GET" || input.Method == "POST") {
		s.authMiddleware(s.handleApplicationNotifications)(out, req)
	} else if target.Path == "/changes" && input.Method == "POST" {
		s.authMiddleware(s.handleApplicationChanges)(out, req)
	} else {
		s.routes().ServeHTTP(out, req)
	}
	if out.overflow {
		return applicationError(413, "Response exceeds application limit")
	}
	if out.status == 0 {
		out.status = 200
	}
	headers := map[string]string{}
	for key, value := range out.header {
		headers[key] = strings.Join(value, ", ")
	}
	return ApplicationResponse{Status: out.status, Headers: headers, Body: out.body.Bytes()}
}
func applicationError(status int, message string) ApplicationResponse {
	return ApplicationResponse{Status: status, Headers: map[string]string{"Content-Type": "text/plain"}, Body: []byte(message)}
}

// Each Corresponder subscriber owns its prior visible path set. Polling is
// nonblocking; the hub schedules it, filters delivery and owns the socket.
func (s *Server) handleApplicationChanges(w http.ResponseWriter, r *http.Request) {
	userID, _ := userIDFrom(r)
	var query struct {
		After   uint64   `json:"after"`
		Epoch   string   `json:"epoch"`
		Visible []string `json:"visible"`
	}
	if err := json.NewDecoder(r.Body).Decode(&query); err != nil {
		http.Error(w, "Invalid cursor", 400)
		return
	}
	visible := map[string]bool{}
	valid := false
	// Permission resolution, cursor polling and projection share one read hold.
	// Revocation cannot interleave between collecting access and filtering paths.
	s.forestMutex.RLock()
	defer s.forestMutex.RUnlock()
	func() {
		_, err := s.forest.GetUserProfile(userID)
		valid = err == nil
		if valid {
			_ = s.walkScope("", nil, func(at visit) {
				if at.node.CheckPermission(userID, core.ReadPermission) {
					visible[at.path] = true
				}
			})
		}
	}()
	if !valid {
		http.Error(w, "Account unavailable", 401)
		return
	}
	events, caughtUp, _ := s.mutations.pollSince(query.After)
	s.mutations.mutex.Lock()
	sequence, epoch := s.mutations.sequence, s.mutations.epoch
	s.mutations.mutex.Unlock()
	// Poll's own last record is the delivered cursor. Reading a later global
	// sequence would skip a mutation published between these two reads.
	after := query.After
	if len(events) > 0 {
		after = events[len(events)-1].Sequence
	}
	if query.Epoch != epoch || query.After > sequence || !caughtUp {
		caughtUp = false
		after = sequence
		events = nil
	}
	delivered := []mutationEvent{}
	for _, event := range events {
		if visible[event.NodePath] {
			delivered = append(delivered, event)
		}
	}
	resync := !caughtUp
	for _, path := range query.Visible {
		if !visible[path] {
			resync = true
			break
		}
	}
	paths := make([]string, 0, len(visible))
	for path := range visible {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"events": delivered, "epoch": epoch, "after": after, "caught_up": caughtUp, "resync": resync, "visible": paths})
}
