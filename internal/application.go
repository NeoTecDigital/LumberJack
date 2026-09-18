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

// ConfigureApplication runs once, before an embedder accepts untrusted requests.
// A populated forest keeps its account identities and password hashes.
func (s *Server) ConfigureApplication(username, password, secret string) error {
	if len(secret) < 32 || username == "" || len(password) < 12 {
		return fmt.Errorf("application bootstrap needs a username, a password of at least 12 characters and a session key of at least 32 bytes")
	}
	s.jwtConfig = JWTConfig{SecretKey: []byte(secret), ExpiresIn: 24 * time.Hour}
	err := s.changeForest(func() error {
		for _, user := range s.forest.Users {
			if user.ID != SystemUserID {
				return nil
			}
		}
		user := core.User{ID: core.GenerateUserID(), Username: username}
		if err := user.SetPassword(password); err != nil {
			return err
		}
		if err := s.forest.AssignUser(user, core.AdminPermission); err != nil {
			return err
		}
		return nil
	})
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
	if input.Method != "GET" && input.Method != "HEAD" && target.Path != "/session" && target.Path != "/login" && target.Path != "/refresh" && target.Path != "/changes" {
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
