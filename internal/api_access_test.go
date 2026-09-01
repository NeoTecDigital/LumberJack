package internal

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vaziolabs/lumberjack/internal/core"
)

// The tests here go through the ROUTER rather than calling a handler directly, because what is
// under test is which routes require a session — a fact that lives in the routing table and not in
// any handler.

// serve sends a request through the server's real routing table.
func serve(t *testing.T, server *Server, request *http.Request) *httptest.ResponseRecorder {
	t.Helper()

	recorder := httptest.NewRecorder()
	server.routes().ServeHTTP(recorder, request)
	return recorder
}

// jsonRequest builds a request carrying a JSON body, with no credential of any kind.
func jsonRequest(t *testing.T, method, target string, body map[string]interface{}) *http.Request {
	t.Helper()

	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("Failed to encode request: %v", err)
	}

	request := httptest.NewRequest(method, target, bytes.NewBuffer(encoded))
	request.Header.Set("Content-Type", "application/json")
	return request
}

// sessionFor mints the session token the login route would hand this user.
func sessionFor(t *testing.T, server *Server, userID, username string) string {
	t.Helper()

	pair, err := server.generateTokenPair(&core.User{ID: userID, Username: username})
	if err != nil {
		t.Fatalf("Failed to generate a session token: %v", err)
	}
	return pair.SessionToken
}

// addReadUser puts a user holding nothing but ReadPermission on the root, which is exactly what
// self-registration used to grant.
func addReadUser(t *testing.T, server *Server, username string) string {
	t.Helper()

	user := core.User{ID: core.GenerateUserID(), Username: username}
	if err := server.forest.AssignUser(user, core.ReadPermission); err != nil {
		t.Fatalf("Failed to add a reader: %v", err)
	}
	return user.ID
}

// An anonymous caller cannot register itself, and therefore cannot read the forest.
//
// POST /users/create was a PUBLIC route. Registration granted ReadPermission on the root, and the
// read routes ask only for a valid session — so anyone who could reach the port could mint an
// account, log in with it, and read the whole tree and the entire user list.
func TestAnonymousRegistrationIsRefused(t *testing.T) {
	server, _ := newStockServer(t)
	usersBefore := len(server.forest.Users)

	credentials := map[string]interface{}{
		"username": "qapwn",
		"email":    "qapwn@example.com",
		"password": "qapwn-password",
	}

	registered := serve(t, server, jsonRequest(t, "POST", "/users/create", credentials))
	if registered.Code != http.StatusUnauthorized {
		t.Errorf("Anonymous POST /users/create: got %d, want %d: %s",
			registered.Code, http.StatusUnauthorized, registered.Body.String())
	}

	if after := len(server.forest.Users); after != usersBefore {
		t.Fatalf("Anonymous registration added %d user(s) to the forest", after-usersBefore)
	}

	// The account does not exist to log in as, so the read that followed it cannot happen either.
	loggedIn := serve(t, server, jsonRequest(t, "POST", "/login", map[string]interface{}{
		"username": "qapwn", "password": "qapwn-password",
	}))
	if loggedIn.Code != http.StatusUnauthorized {
		t.Errorf("Login as the unregistered user: got %d, want %d", loggedIn.Code, http.StatusUnauthorized)
	}

	// And an anonymous read is refused on its own account, not only for want of an account.
	for _, target := range []string{"/forest", "/users"} {
		read := serve(t, server, httptest.NewRequest("GET", target, nil))
		if read.Code != http.StatusUnauthorized {
			t.Errorf("Anonymous GET %s: got %d, want %d: %s",
				target, read.Code, http.StatusUnauthorized, read.Body.String())
		}
	}
}

// A session that is not administrative cannot create a user either. Registration is refused for
// want of AUTHORITY, not merely for want of a token.
func TestNonAdminCannotCreateAUser(t *testing.T) {
	server, _ := newStockServer(t)
	readerID := addReadUser(t, server, "reader")
	usersBefore := len(server.forest.Users)

	request := jsonRequest(t, "POST", "/users/create", map[string]interface{}{
		"username": "invited", "email": "invited@example.com", "password": "invited-password",
	})
	request.Header.Set("Authorization", "Bearer "+sessionFor(t, server, readerID, "reader"))

	if recorder := serve(t, server, request); recorder.Code != http.StatusForbidden {
		t.Errorf("Reader POST /users/create: got %d, want %d: %s",
			recorder.Code, http.StatusForbidden, recorder.Body.String())
	}
	if after := len(server.forest.Users); after != usersBefore {
		t.Errorf("A non-administrative session added %d user(s)", after-usersBefore)
	}
}

// An administrator still can, which is what the route is for.
func TestAdminCanCreateAUser(t *testing.T) {
	server, _ := newStockServer(t)
	adminUserID := adminID(t, server)

	request := jsonRequest(t, "POST", "/users/create", map[string]interface{}{
		"username": "invited", "email": "invited@example.com", "password": "invited-password",
	})
	request.Header.Set("Authorization", "Bearer "+sessionFor(t, server, adminUserID, "admin"))

	if recorder := serve(t, server, request); recorder.Code != http.StatusOK {
		t.Fatalf("Admin POST /users/create: got %d, want %d: %s",
			recorder.Code, http.StatusOK, recorder.Body.String())
	}

	loggedIn := serve(t, server, jsonRequest(t, "POST", "/login", map[string]interface{}{
		"username": "invited", "password": "invited-password",
	}))
	if loggedIn.Code != http.StatusOK {
		t.Errorf("Login as the created user: got %d, want %d: %s",
			loggedIn.Code, http.StatusOK, loggedIn.Body.String())
	}
}

// A user with no name or no password is refused, rather than stored as an account nobody can be.
func TestUserCreationRequiresANameAndAPassword(t *testing.T) {
	server, _ := newStockServer(t)
	adminUserID := adminID(t, server)

	for _, body := range []map[string]interface{}{
		{"username": "  ", "password": "a-password"},
		{"username": "named", "password": ""},
	} {
		request := jsonRequest(t, "POST", "/users/create", body)
		request.Header.Set("Authorization", "Bearer "+sessionFor(t, server, adminUserID, "admin"))

		if recorder := serve(t, server, request); recorder.Code != http.StatusBadRequest {
			t.Errorf("POST /users/create %v: got %d, want %d", body, recorder.Code, http.StatusBadRequest)
		}
	}
}

// wantFileMode and wantDirMode are what a state file, a log file and the directories holding them
// are REQUIRED to be. They are written out here as literals on purpose.
//
// These tests used to compare the mode on disk against the constant that produced it —
// stateFileMode, types.LogFileMode — which is a tautology: changing the constant to 0644 changes
// both sides of the comparison and the suite stays green while every install goes world-readable.
// QA proved exactly that. The requirement is 0600 and 0700, so 0600 and 0700 is what is asserted,
// and flipping a constant now fails here.
const (
	wantFileMode os.FileMode = 0600
	wantDirMode  os.FileMode = 0700
)

// The state file is readable by its owner and by NOBODY ELSE. It holds the whole forest, and the
// forest holds every bcrypt hash; it used to be written 0644 by os.Create.
func TestStateFileIsNotWorldReadable(t *testing.T) {
	server, dir := newStockServer(t)
	statePath := server.statePath()

	info, err := os.Stat(statePath)
	if err != nil {
		t.Fatalf("The state file was not written: %v", err)
	}
	if mode := info.Mode().Perm(); mode != wantFileMode {
		t.Errorf("State file mode is %04o, want %04o", mode, wantFileMode)
	}

	// It really does hold a hash, so this test is about something.
	contents, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("Failed to read the state file: %v", err)
	}
	if len(contents) == 0 {
		t.Fatal("The state file is empty, so this test proves nothing")
	}

	// A second write goes through the temporary-file path again. An atomic rename carries the mode
	// of the temporary file with it, so a 0644 temporary file is a 0644 state file.
	if code := post(t, server.handleCreateNode, adminID(t, server), map[string]interface{}{
		"path": "work/leaf",
	}).Code; code != http.StatusOK {
		t.Fatalf("Create node: got %d, want %d", code, http.StatusOK)
	}

	info, err = os.Stat(statePath)
	if err != nil {
		t.Fatalf("The state file disappeared: %v", err)
	}
	if mode := info.Mode().Perm(); mode != wantFileMode {
		t.Errorf("State file mode after rewrite is %04o, want %04o", mode, wantFileMode)
	}

	// Nothing is left behind at a wider mode under a different name.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("Failed to read the data directory: %v", err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".tmp") {
			t.Errorf("A temporary state file was left behind: %s", entry.Name())
		}
	}
}

// GET /logs answers with logs. It used to answer 500 on EVERY call on every install: it stats a
// file that nothing ever opened.
func TestLogsRouteReturnsLogsRatherThanAFault(t *testing.T) {
	server, _ := newStockServer(t)
	adminUserID := adminID(t, server)

	// The server logged while it was being built, so there is something to page.
	if _, err := os.Stat(server.logFilePath()); err != nil {
		t.Fatalf("No log file was opened at %s: %v", server.logFilePath(), err)
	}

	recorder := get(t, server.handleGetLogs, adminUserID, "/logs")
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET /logs: got %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}

	var response struct {
		Logs    []LogEntry `json:"logs"`
		HasMore bool       `json:"has_more"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to decode %q: %v", recorder.Body.String(), err)
	}
	if len(response.Logs) == 0 {
		t.Error("GET /logs returned no entries from a log file that has content")
	}
}

// The log file, and therefore the log route, carries NO CREDENTIAL MATERIAL. This is the reason the
// %+v dumps of users and nodes came out of the logging calls: this route is what made them reachable.
func TestTheLogFileCarriesNoPasswordHash(t *testing.T) {
	server, _ := newStockServer(t)
	adminUserID := adminID(t, server)

	// Exercise the paths that handle users and nodes, which are the ones that could dump a hash.
	if code := post(t, server.handleCreateUser, adminUserID, map[string]interface{}{
		"username": "logged", "email": "logged@example.com", "password": "a-real-password",
	}).Code; code != http.StatusOK {
		t.Fatalf("Create user: got %d, want %d", code, http.StatusOK)
	}
	if code := post(t, server.handleCreateNode, adminUserID, map[string]interface{}{"path": "work/leaf"}).Code; code != http.StatusOK {
		t.Fatalf("Create node: got %d, want %d", code, http.StatusOK)
	}
	serve(t, server, jsonRequest(t, "POST", "/login", map[string]interface{}{
		"username": "logged", "password": "a-real-password",
	}))

	// A load reads the forest back, which is the other place a dump could happen.
	if _, err := LoadServer(server.config); err != nil {
		t.Fatalf("Failed to reload the server: %v", err)
	}

	contents, err := os.ReadFile(server.logFilePath())
	if err != nil {
		t.Fatalf("Failed to read the log file: %v", err)
	}
	if len(contents) == 0 {
		t.Fatal("The log file is empty, so this test proves nothing")
	}

	log := string(contents)
	for _, prefix := range bcryptPrefixes {
		if strings.Contains(log, prefix) {
			t.Errorf("The log file contains a bcrypt hash (%s)", prefix)
		}
	}
	if strings.Contains(log, "a-real-password") {
		t.Error("The log file contains a plaintext password")
	}

	// And what the log file holds is what the route hands out.
	body := get(t, server.handleGetLogs, adminUserID, "/logs").Body.String()
	for _, prefix := range bcryptPrefixes {
		if strings.Contains(body, prefix) {
			t.Errorf("GET /logs returned a bcrypt hash (%s)", prefix)
		}
	}
}

// The log file is readable by its owner and nobody else: it names users, paths and failures.
func TestLogFileIsNotWorldReadable(t *testing.T) {
	server, _ := newStockServer(t)

	info, err := os.Stat(server.logFilePath())
	if err != nil {
		t.Fatalf("No log file was opened: %v", err)
	}
	if mode := info.Mode().Perm(); mode != wantFileMode {
		t.Errorf("Log file mode is %04o, want %04o", mode, wantFileMode)
	}
}

// A server with nowhere to log says so with a 404 rather than reporting a configuration choice as a
// server fault.
func TestLogsRouteIsHonestWithoutALogFile(t *testing.T) {
	server, _ := newStockServer(t)
	adminUserID := adminID(t, server)
	server.config.Process.LogPath = ""

	if recorder := get(t, server.handleGetLogs, adminUserID, "/logs"); recorder.Code != http.StatusNotFound {
		t.Errorf("GET /logs with no log path: got %d, want %d: %s",
			recorder.Code, http.StatusNotFound, recorder.Body.String())
	}
}

// The log is operator data, so reading it takes an administrator.
func TestLogsRouteRequiresAdmin(t *testing.T) {
	server, _ := newStockServer(t)
	readerID := addReadUser(t, server, "reader")

	if recorder := get(t, server.handleGetLogs, readerID, "/logs"); recorder.Code != http.StatusForbidden {
		t.Errorf("Reader GET /logs: got %d, want %d: %s",
			recorder.Code, http.StatusForbidden, recorder.Body.String())
	}
	if recorder := serve(t, server, httptest.NewRequest("GET", "/logs", nil)); recorder.Code != http.StatusUnauthorized {
		t.Errorf("Anonymous GET /logs: got %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
}

// The directory the state file sits in is enterable by its owner and NOBODY ELSE.
//
// This is the hole the file modes alone did not close. Every entrypoint pre-created this directory
// at 0755 before any code with an opinion about the mode ran, and os.MkdirAll applies its mode only
// to directories it actually creates — so the 0700 in the state writer was an unreachable no-op and
// a `stat` of a running install measured 755 no matter what the source said.
func TestStateDirectoryIsNotWorldEnterable(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	logDir := filepath.Join(root, "logs")

	// Planted at 0755 FIRST, which is what the entrypoints used to leave behind. A test that lets
	// the server create the directory itself proves nothing: t.TempDir is already 0700, and so is
	// anything MkdirAll makes fresh.
	plantWideDir(t, dataDir)
	plantWideDir(t, logDir)

	server := newServerInDirs(t, dataDir, logDir)

	// A second write goes through the whole persist path again, after the directory exists.
	if code := post(t, server.handleCreateNode, adminID(t, server), map[string]interface{}{
		"path": "work/leaf",
	}).Code; code != http.StatusOK {
		t.Fatalf("Create node: got %d, want %d", code, http.StatusOK)
	}

	// The state file really is in there, so this is measuring the directory that holds the hashes.
	if _, err := os.Stat(server.statePath()); err != nil {
		t.Fatalf("No state file was written into %s: %v", dataDir, err)
	}

	assertDirMode(t, dataDir)
}

// The directory the log file sits in, likewise. It holds the file GET /logs serves.
func TestLogDirectoryIsNotWorldEnterable(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	logDir := filepath.Join(root, "logs")

	plantWideDir(t, dataDir)
	plantWideDir(t, logDir)

	server := newServerInDirs(t, dataDir, logDir)

	if _, err := os.Stat(server.logFilePath()); err != nil {
		t.Fatalf("No log file was written into %s: %v", logDir, err)
	}

	assertDirMode(t, logDir)
}

// plantWideDir creates dir at 0755 — the mode every entrypoint used to leave it at — and confirms
// it landed that way, so a test built on it is starting from the state it means to.
func plantWideDir(t *testing.T, dir string) {
	t.Helper()

	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("Failed to create %s: %v", dir, err)
	}
	// MkdirAll is subject to the umask, so the mode is forced rather than requested.
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatalf("Failed to widen %s: %v", dir, err)
	}
	if mode := statMode(t, dir); mode != 0755 {
		t.Fatalf("%s is %04o, not the 0755 this test needs to start from", dir, mode)
	}
}

// assertDirMode measures a directory against the literal 0700, for the reason wantDirMode gives.
func assertDirMode(t *testing.T, dir string) {
	t.Helper()

	if mode := statMode(t, dir); mode != wantDirMode {
		t.Errorf("%s is %04o, want %04o", dir, mode, wantDirMode)
	}
}

func statMode(t *testing.T, path string) os.FileMode {
	t.Helper()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Failed to stat %s: %v", path, err)
	}
	return info.Mode().Perm()
}

// readerOn grants a user ReadPermission on ONE node and nothing above it.
//
// addReadUser grants on the ROOT, which every route then sees on every node by inheritance. That
// hides the whole question a permission filter exists to answer.
func readerOn(t *testing.T, server *Server, username, path string) string {
	t.Helper()

	node, err := server.getNodeFromPath(path)
	if err != nil {
		t.Fatalf("Failed to find %s: %v", path, err)
	}

	user := core.User{ID: core.GenerateUserID(), Username: username}
	if err := node.AssignUser(user, core.ReadPermission); err != nil {
		t.Fatalf("Failed to grant read on %s: %v", path, err)
	}
	return user.ID
}

// partitionedForest is a forest with one branch the caller may read and one it may not, and the id
// of a user granted read on the first of them alone.
func partitionedForest(t *testing.T, server *Server, adminUserID string) string {
	t.Helper()

	leafFor(t, server, adminUserID, "org/secret/closed")
	if code := post(t, server.handleCreateNode, adminUserID, map[string]interface{}{
		"path": "org/public", "type": "branch",
	}).Code; code != http.StatusOK {
		t.Fatalf("Create org/public: got %d, want %d", code, http.StatusOK)
	}

	readerID := readerOn(t, server, "reader", "org/public")
	// Created AFTER the grant, so it inherits the reader the way every child inherits its parent's
	// users. This is the node /query already reports and the listing routes did not.
	leafFor(t, server, adminUserID, "org/public/open")
	return readerID
}

// GET /forest shows a caller what it was granted and nothing else.
//
// handleGetForest never called userIDFrom or CheckPermission. /query filters per node; this route
// answered the WHOLE forest to any valid session, which is a straight read of everybody's data.
func TestForestListingFiltersByReadPermission(t *testing.T) {
	server, _ := newStockServer(t)
	adminUserID := adminID(t, server)
	readerID := partitionedForest(t, server, adminUserID)

	body := get(t, server.handleGetForest, readerID, "/forest").Body.String()
	for _, hidden := range []string{`"secret"`, `"closed"`} {
		if strings.Contains(body, hidden) {
			t.Errorf("GET /forest showed %s to a caller holding no permission on it", hidden)
		}
	}
	// Granted deeper than the root, so the node has to survive being reported through two ancestors
	// the caller may not read. Pruning at the first refusal would hide what was explicitly granted.
	for _, shown := range []string{`"public"`, `"open"`} {
		if !strings.Contains(body, shown) {
			t.Errorf("GET /forest hid %s from the caller it was granted to", shown)
		}
	}
}

// GET /forest/tree refuses a subtree the caller may not read.
//
// It asked for no caller at all: any valid session could name any path and be given the subtree.
func TestTreeRouteRefusesASubtreeTheCallerMayNotRead(t *testing.T) {
	server, _ := newStockServer(t)
	adminUserID := adminID(t, server)
	readerID := partitionedForest(t, server, adminUserID)

	refused := get(t, server.handleGetTree, readerID, "/forest/tree?path=org/secret")
	if refused.Code != http.StatusForbidden {
		t.Errorf("GET /forest/tree on a secret subtree: got %d, want %d: %s",
			refused.Code, http.StatusForbidden, refused.Body.String())
	}

	allowed := get(t, server.handleGetTree, readerID, "/forest/tree?path=org/public")
	if allowed.Code != http.StatusOK {
		t.Errorf("GET /forest/tree on the granted subtree: got %d, want %d: %s",
			allowed.Code, http.StatusOK, allowed.Body.String())
	}
}

// GET /users is administrative. It listed every account in the install to any valid session.
func TestUserListingIsAdministrative(t *testing.T) {
	server, _ := newStockServer(t)
	adminUserID := adminID(t, server)
	readerID := partitionedForest(t, server, adminUserID)

	if code := get(t, server.handleGetUsers, readerID, "/users").Code; code != http.StatusForbidden {
		t.Errorf("GET /users as a non-admin: got %d, want %d", code, http.StatusForbidden)
	}
	if code := get(t, server.handleGetUsers, adminUserID, "/users").Code; code != http.StatusOK {
		t.Errorf("GET /users as the admin: got %d, want %d", code, http.StatusOK)
	}
}
