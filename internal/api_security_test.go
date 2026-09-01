package internal

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/vaziolabs/lumberjack/internal/core"
	"github.com/vaziolabs/lumberjack/types"
)

// bcryptPrefixes are what a bcrypt hash starts with. Finding one in a response body means the
// password field of a core.User reached a client.
var bcryptPrefixes = []string{"$2a$", "$2b$", "$2y$"}

// No route hands a client a password hash.
//
// core.User tags its Password field for JSON and a core.Node carries its users, so GET /forest,
// GET /users and GET /forest/tree each used to serialize the admin's bcrypt hash to anyone holding
// a session.
func TestNoRouteSerializesAPasswordHash(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)

	// A hash exists to leak: the admin was created with a password, and a second user is added
	// through the route a client uses, so both storage paths are covered.
	if len(server.forest.Users) == 0 || !strings.HasPrefix(server.forest.Users[0].Password, "$2") {
		t.Fatalf("The admin has no bcrypt hash to leak, so this test proves nothing")
	}
	if code := post(t, server.handleCreateUser, userID, map[string]interface{}{
		"username": "second", "email": "second@example.com", "password": "another-password",
	}).Code; code != http.StatusOK {
		t.Fatalf("Create user: got %d, want %d", code, http.StatusOK)
	}

	// A node below the root, so the projection is proven to recurse rather than only cover the top.
	if code := post(t, server.handleCreateNode, userID, map[string]interface{}{"path": "work/leaf"}).Code; code != http.StatusOK {
		t.Fatalf("Create node: got %d, want %d", code, http.StatusOK)
	}

	routes := []struct {
		name    string
		handler http.HandlerFunc
		target  string
	}{
		{"GET /forest", server.handleGetForest, "/forest"},
		{"GET /users", server.handleGetUsers, "/users"},
		{"GET /forest/tree", server.handleGetTree, "/forest/tree?path=work"},
		{"GET /users/profile", server.handleGetUserProfile, "/users/profile"},
	}

	for _, route := range routes {
		recorder := get(t, route.handler, userID, route.target)
		if recorder.Code != http.StatusOK {
			t.Errorf("%s: got %d, want %d: %s", route.name, recorder.Code, http.StatusOK, recorder.Body.String())
			continue
		}

		body := recorder.Body.String()
		for _, prefix := range bcryptPrefixes {
			if strings.Contains(body, prefix) {
				t.Errorf("%s: the response body contains a bcrypt hash", route.name)
			}
		}
		if strings.Contains(body, `"password"`) {
			t.Errorf("%s: the response body carries a password field", route.name)
		}
	}
}

// The projection is a separate type, so producing it does NOT empty the field on the live forest.
// Blanking the field on the running struct would have logged every caller out of their own data.
func TestProjectionDoesNotMutateTheForest(t *testing.T) {
	server, _ := newStockServer(t)
	before := server.forest.Users[0].Password

	newNodeView(server.forest, adminID(t, server))

	if after := server.forest.Users[0].Password; after != before {
		t.Errorf("Projecting the forest changed the stored password from %q to %q", before, after)
	}
	if !server.forest.Users[0].VerifyPassword("admin") {
		t.Error("The stored credential no longer verifies after projection")
	}
}

// The server refuses to start without a signing key rather than inventing one. It used to sign with
// the literal "your-secret-key", which anyone reading the source could forge a session with.
func TestServerRefusesToStartWithoutASigningKey(t *testing.T) {
	t.Setenv(jwtSecretEnv, "")

	config := types.ServerConfig{
		Process: types.ProcessInfo{
			Name:         "unsigned",
			DatabasePath: t.TempDir(),
			LogPath:      t.TempDir(),
			ServerPort:   "8080",
		},
	}

	if _, err := NewServer(config, core.User{Username: "admin", Password: "admin"}); err == nil {
		t.Error("NewServer started with no signing key configured")
	}
	if _, err := LoadServer(config); err == nil {
		t.Error("LoadServer started with no signing key configured")
	}
}

// The key that is used is the one the environment gives, and only that one.
func TestSigningKeyComesFromTheEnvironment(t *testing.T) {
	t.Setenv(jwtSecretEnv, "a-configured-key")

	config, err := newJWTConfig()
	if err != nil {
		t.Fatalf("Failed to read the signing key: %v", err)
	}
	if string(config.SecretKey) != "a-configured-key" {
		t.Errorf("Got signing key %q, want the configured one", string(config.SecretKey))
	}
	if os.Getenv(jwtSecretEnv) == "" {
		t.Fatal("The test did not configure a key")
	}
}

// GET /health answers without credentials, and says nothing about anyone.
//
// The only liveness signal before this route was a POST of the admin's password to /login every
// five seconds, whose 401 was read as healthy.
func TestHealthNeedsNoCredentialsAndLeaksNothing(t *testing.T) {
	server, _ := newStockServer(t)

	// No Authorization header, no context user: the request an unauthenticated prober makes.
	request := httptest.NewRequest("GET", "/health", nil)
	recorder := httptest.NewRecorder()
	server.handleHealth(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("GET /health: got %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	if request.Header.Get("Authorization") != "" {
		t.Fatal("The probe sent an Authorization header, so this test proves nothing")
	}

	var body map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("Failed to decode %q: %v", recorder.Body.String(), err)
	}
	if body["status"] != "ok" {
		t.Errorf("Got status %q, want ok", body["status"])
	}
	if body["version"] == "" {
		t.Error("The health body reports no version")
	}

	// Exactly the two fields, so a field added to the response later has to be added here too.
	if len(body) != 2 {
		t.Errorf("The health body carries %d fields: %s", len(body), recorder.Body.String())
	}

	raw := recorder.Body.String()
	if strings.Contains(raw, "password") {
		t.Error("The health body carries a password field")
	}
	for _, prefix := range bcryptPrefixes {
		if strings.Contains(raw, prefix) {
			t.Error("The health body contains a bcrypt hash")
		}
	}
	for _, leaked := range []string{server.forest.Users[0].Username, server.forest.Users[0].ID, server.config.Process.DatabasePath} {
		if leaked != "" && strings.Contains(raw, leaked) {
			t.Errorf("The health body names %q", leaked)
		}
	}
}

// A server whose forest never loaded says so rather than reporting itself up.
func TestHealthReportsDegradedWithoutAForest(t *testing.T) {
	server, _ := newStockServer(t)
	server.forest = nil

	recorder := httptest.NewRecorder()
	server.handleHealth(recorder, httptest.NewRequest("GET", "/health", nil))

	if recorder.Code != http.StatusServiceUnavailable {
		t.Errorf("GET /health with no forest: got %d, want %d", recorder.Code, http.StatusServiceUnavailable)
	}
	if !strings.Contains(recorder.Body.String(), "degraded") {
		t.Errorf("GET /health with no forest reported %q", recorder.Body.String())
	}
}
