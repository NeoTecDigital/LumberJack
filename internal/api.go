package internal

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/NeoTecDigital/LumberJack/core"
	"github.com/NeoTecDigital/LumberJack/types"
	"github.com/gorilla/mux"
)

// jwtSecretEnv names the environment variable the session signing key comes from. There is exactly
// ONE source for it. The key used to be the literal "your-secret-key", written out twice, so every
// install signed its sessions with a key published in the source tree and anyone holding the source
// could mint a token for any user.
const jwtSecretEnv = "LUMBERJACK_JWT_SECRET"

// newJWTConfig reads the signing key, and FAILS CLOSED. An unset key is not a reason to invent one:
// a server that invents one accepts tokens it should refuse.
func newJWTConfig() (JWTConfig, error) {
	secret := os.Getenv(jwtSecretEnv)
	if secret == "" {
		return JWTConfig{}, fmt.Errorf("%s is not set: refusing to start without a session signing key", jwtSecretEnv)
	}

	return JWTConfig{
		SecretKey: []byte(secret),
		ExpiresIn: 24 * time.Hour,
	}, nil
}

// LoopbackHost is where the engine listens unless it is told otherwise, IN SO MANY WORDS.
//
// The address used to be built as ":" + port, which is every interface the host has — here that is
// the LAN address, a Tailscale address and a VPN address as well as loopback, with no TLS and no
// CORS anywhere in front of the login route. The relay in front of the engine binds loopback by
// default for exactly this reason (RELAY_HOST in backend/.env.example); the engine now says the
// same thing, so the two agree and neither is the hole.
const LoopbackHost = "127.0.0.1"

// ListenAddr resolves what the HTTP server binds.
//
// An unset BindHost is read as LOOPBACK rather than passed through, because passing it through is
// what net/http turns into every interface. Reaching the engine from another machine is a
// deliberate act: `lumberjack serve --host`, or LUMBERJACK_HOST.
//
// EXPORTED so the entrypoint that resolves the host can be tested against the same function the
// listener is built from. cmd holds the flag and the environment; this holds the rule; and the one
// line that carries the first into the second is testable only if both sides are reachable from
// one test. See TestServeBindHostReachesTheListener.
func ListenAddr(process types.ProcessInfo) string {
	host := strings.TrimSpace(process.BindHost)
	if host == "" {
		host = LoopbackHost
	}
	return net.JoinHostPort(host, process.ServerPort)
}

// newServerCore builds everything a forest needs to be OPERATED but not SERVED: a fresh forest, the
// logger, the config, the state writer, and the runtime a forest needs to answer at all — the read
// cache, the worker pool and the mutation stream. No signing key, no HTTP server.
//
// It exists so an EMBEDDED runtime can be built without a session signing key it has no sessions to
// sign — the JWT config fails closed (newJWTConfig) precisely because an HTTP server that mints
// tokens must, and an in-process caller mints none. The safety property survives by CONSTRUCTION,
// not by a new guard: a core-only server leaves `server` (the *http.Server) nil, and Start already
// refuses a nil server. See the assertion in the tests.
//
// The runtime is brought up HERE, not in the HTTP entrypoints, because an embedded runtime needs
// the queue, cache and mutation stream just as much as an HTTP one does — a core-only server that
// skipped startRuntime had a nil apiQueue, and Shutdown's very first act, close(apiQueue.shutdown),
// nil-panicked before the shutdownOnce guard could matter. startRuntime touches nothing HTTP and
// depends on nothing the forest is later filled with, so this is where it belongs.
func newServerCore(config types.ServerConfig) *Server {
	logger, logCloser := newServerLogger(config)
	server := &Server{
		forest:     core.NewForest("forest"),
		logger:     logger,
		logCloser:  logCloser,
		config:     config,
		grantsHeld: true,
	}
	// The state directory is narrowed to DataDirMode ONCE, here at construction — every entrypoint
	// funnels through this — instead of on every write. Entrypoints pre-create it at 0755 and
	// os.MkdirAll narrows nothing it did not itself make, so without this a running install's
	// directory of password hashes stayed world-enterable (TestStateDirectoryIsNotWorldEnterable).
	// The WRITE path no longer re-asserts it (internal/file.go), so an operator's narrower mode now
	// survives a persist — and so does a WIDER one: a chmod either way holds until the next restart
	// narrows the directory again here. Best effort: a directory whose mode cannot be set does not stop the server
	// coming up, and the state file inside it is 0600 regardless.
	if dir := filepath.Dir(server.statePath()); dir != "" && dir != "." {
		if err := types.EnsureDir(dir, types.DataDirMode); err != nil {
			logger.Warn("Could not secure the state directory mode: %v", err)
		}
	}
	// The writer is the only thing that touches the state file, and it does so with the forest
	// unheld. Every entrypoint goes through here, so every one gets one.
	server.stateWriter = newStateWriter(server.publishSnapshot)
	server.startRuntime()
	return server
}

// newServerShell builds what both HTTP entrypoints start from: the core above, plus the signing key
// and the HTTP server. NewServer and LoadServer differ in what they put IN the forest, not in how
// the shell around it is made, and the block was written out twice.
//
// It fails closed without a signing key, and is the ONLY constructor that reaches for one — so the
// key is required exactly where sessions are, the HTTP path, and nowhere else.
func newServerShell(config types.ServerConfig) (*Server, error) {
	jwtConfig, err := newJWTConfig()
	if err != nil {
		return nil, err
	}

	server := newServerCore(config)
	server.jwtConfig = jwtConfig
	server.server = newHTTPServer(config)
	return server, nil
}

// The bounds a served endpoint runs under. ReadHeaderTimeout is the slowloris cutoff: a client that
// dribbles its request line and headers is cut here, before any handler is reached. ReadTimeout
// bounds the whole request read — generous enough for a MaxAttachmentSize upload over a slow link.
// IdleTimeout bounds an idle keep-alive. MaxHeaderBytes bounds the header block a client can send.
//
// WriteTimeout is deliberately ABSENT. /stream is Server-Sent Events — one response held open for
// the whole life of a subscription — and a server-wide write deadline cancels the request context at
// that interval, which the stream handler selects on (see api_stream.go), severing every live feed.
// ReadHeaderTimeout closes the REQUEST-side slowloris: a client that dribbles its headers. It does
// NOT close the response side — a client that completes its request and then never reads the reply
// still pins a handler goroutine blocked in Write. Closing that needs a per-handler
// http.ResponseController.SetWriteDeadline, a later change, precisely because the one server-wide
// knob that would also close it cannot coexist with SSE.
const (
	httpReadHeaderTimeout = 10 * time.Second
	httpReadTimeout       = 60 * time.Second
	httpIdleTimeout       = 120 * time.Second
	httpMaxHeaderBytes    = 1 << 20
)

// newHTTPServer builds the HTTP server the served entrypoints listen on, with the timeouts above. It
// is separate from newServerShell so those bounds can be asserted without standing up a forest.
func newHTTPServer(config types.ServerConfig) *http.Server {
	return &http.Server{
		Addr:              ListenAddr(config.Process),
		Handler:           mux.NewRouter(),
		ReadHeaderTimeout: httpReadHeaderTimeout,
		ReadTimeout:       httpReadTimeout,
		IdleTimeout:       httpIdleTimeout,
		MaxHeaderBytes:    httpMaxHeaderBytes,
	}
}

// startRuntime brings up what a forest needs in order to be SERVED: the read cache, the worker pool
// the node routes go through, and the mutation stream.
//
// A LOADED database needs every one of them just as a new one does. Without them each node-path
// route nil-panics in getFromCache and Shutdown nil-panics on the queue, which made a restart fatal
// to the whole /events/* surface.
func (server *Server) startRuntime() {
	server.initCache()
	server.initAPIQueue(5) // Start with 5 workers
	server.mutations = newMutationStream()
}

// installAdmin creates the account a fresh install is administered from, and writes the state file
// it lives in.
//
// Nothing is serving yet, so this is the one place the persist is reached without going through
// changeForest: there is no concurrent request to hold the forest against.
func (server *Server) installAdmin(adminUser core.User) error {
	if len(server.forest.Users) > 0 {
		// The store was opened over a log that already holds accounts — a tiered install that
		// crashed before its first state file. Those accounts are the install; a second admin on
		// top of them is not.
		server.logger.Warn("The log already holds %d accounts; the admin account was not created again", len(server.forest.Users))
		return nil
	}
	coreUser := core.User{
		ID:           core.GenerateUserID(),
		Username:     adminUser.Username,
		Email:        adminUser.Email,
		Organization: adminUser.Organization,
		Phone:        adminUser.Phone,
	}

	if err := coreUser.SetPassword(adminUser.Password); err != nil {
		server.logger.Failure("failed to set admin password: %v", err)
		return err
	}
	if err := server.forest.AssignUser(coreUser, core.AdminPermission); err != nil {
		server.logger.Failure("failed to save admin user: %v", err)
		return err
	}
	if err := server.persistState(server.statePath()); err != nil {
		server.logger.Failure("failed to save state after user creation: %v", err)
		return err
	}
	return nil
}

func NewServer(config types.ServerConfig, adminUser core.User) (*Server, error) {
	server, err := newServerShell(config)
	if err != nil {
		return nil, err
	}

	server.logger.Enter("NewServer")

	if err := server.openStore(nil); err != nil {
		server.logger.Exit("NewServer")
		_ = server.Shutdown(context.Background())
		return nil, err
	}
	if err := server.installAdmin(adminUser); err != nil {
		// The span is closed HERE, before Shutdown, not with a deferred Exit. Shutdown closes the log
		// sink, and a deferred Exit runs AFTER the return — so it would write END into a closed file
		// and the durable log would carry BEGIN with no matching END, an unbalanced span in
		// Lumberjack's own log store. See types/logger.go on why the sink's write order saved the
		// line for stderr but not for the file. The full Shutdown then stops the workers AND releases
		// the log file, idempotently through shutdownOnce, so a failed construction in a loop leaks
		// neither goroutines nor descriptors.
		server.logger.Exit("NewServer")
		_ = server.Shutdown(context.Background())
		return nil, err
	}

	server.logger.Exit("NewServer")
	return server, nil
}

func LoadServer(config types.ServerConfig) (*Server, error) {
	server, err := newServerShell(config)
	if err != nil {
		return nil, err
	}

	server.logger.Enter("LoadServer")

	dbPath := server.statePath()
	server.logger.Debug("Loading database from %s", dbPath)
	if err := server.loadFromFile(dbPath); err != nil {
		server.logger.Failure("failed to load database: %v", err)
		// Exit BEFORE Shutdown closes the sink — a deferred Exit would land in a closed log file and
		// leave BEGIN with no END. See NewServer for the same ordering and why it matters here.
		server.logger.Exit("LoadServer")
		_ = server.Shutdown(context.Background())
		return nil, err
	}

	server.logger.Info("Loaded existing database from %s", dbPath)
	server.logger.Exit("LoadServer")
	return server, nil
}

// NewCore opens a core-only server — no HTTP, no signing key — over a config, loading the state file
// if it holds one and starting on a fresh forest if it does not.
//
// It is what the embedded runtime opens. An ABSENT file is a fresh install; an EMPTY one holds no
// forest and is also fresh; a file with content is loaded. Any OTHER stat error — a path that exists
// but cannot be read — is a real fault and is returned, NOT swallowed as "fresh": treating an
// unreadable state as empty would start on a blank forest and clobber it on the first persist. A load
// failure tears the runtime back down rather than leaking it.
func NewCore(config types.ServerConfig) (*Server, error) {
	server := newServerCore(config)

	dbPath := server.statePath()
	info, err := os.Stat(dbPath)
	switch {
	case os.IsNotExist(err) || (err == nil && info.Size() == 0):
		if err := server.openStore(nil); err != nil {
			_ = server.Shutdown(context.Background())
			return nil, err
		}
		return server, nil
	case err != nil:
		_ = server.Shutdown(context.Background())
		return nil, err
	}

	if err := server.loadFromFile(dbPath); err != nil {
		_ = server.Shutdown(context.Background())
		return nil, err
	}
	return server, nil
}

// SystemUserID is the default principal an EMPTY forest is administered by. It is a dev-environment
// default, not a bypass: it is a real user with admin, so CheckPermission runs against it exactly as
// it runs against any user — one enforcement path, and the permissive default cannot drift from it.
const SystemUserID = "system"

// EnsureSystemUser gives an empty forest the default unlocked `system` user, and reports whether it
// did. A forest that already has users is left untouched — real users, auth and RBAC are the real
// path.
//
// The emptiness test and the seed happen inside ONE exclusive hold, so two callers cannot both find
// the forest empty and each seed it — which gave `system` two admin permissions, or left the forest
// holding both `system` and a real user. changeForest persists whether or not it seeded; that one
// write when opening a loaded forest is the price of the invariant being true under concurrency.
func (server *Server) EnsureSystemUser() (bool, error) {
	seeded := false
	err := server.changeForest(func() error {
		if len(server.forest.Users) > 0 {
			return nil
		}
		if err := server.forest.AssignUser(core.User{ID: SystemUserID}, core.AdminPermission); err != nil {
			return err
		}
		seeded = true
		return nil
	})
	return seeded, err
}

func (s *Server) Start() error {
	if s.server == nil {
		return errors.New("server not initialized")
	}

	s.server.Handler = s.routes()
	go func() {
		s.logger.Info("API server starting on http://" + s.server.Addr)
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Failure("API server error: %v", err)
		}
	}()

	return nil
}

// Shutdown stops the workers and the HTTP server, and is IDEMPOTENT.
//
// close(apiQueue.shutdown) panics on a second call — close of a closed channel — and a C caller has
// every reason to be defensive and call this twice, as does the CLI. So the real work runs exactly
// once behind shutdownOnce and every later call replays its result, rather than crashing the
// process on the second attempt.
func (s *Server) Shutdown(ctx context.Context) error {
	s.shutdownOnce.Do(func() {
		s.shutdownErr = s.shutdown(ctx)
	})
	return s.shutdownErr
}

// shutdown is the one real teardown, run once by Shutdown.
func (s *Server) shutdown(ctx context.Context) error {
	// Signal workers to shut down
	close(s.apiQueue.shutdown)

	// Wait for all workers to finish
	s.apiQueue.wg.Wait()
	s.closeObjects()

	var err error
	if s.server != nil {
		s.logger.Info("Shutting down API server")
		err = s.server.Shutdown(ctx)
	}
	// The store closes LAST, with nothing serving: the clean-shutdown snapshot takes the forest
	// hold, and the log is closed only once no handler can append to it.
	if storeErr := s.closeStore(); err == nil {
		err = storeErr
	}
	s.closeLogSink()
	return err
}

// closeLogSink releases the log file, if the logger opened one. Failing to close it is reported and
// not returned: it does not make a shutdown unsuccessful.
func (s *Server) closeLogSink() {
	if s.logCloser == nil {
		return
	}
	if err := s.logCloser.Close(); err != nil {
		s.logger.Warn("Failed to close the log file: %v", err)
	}
	s.logCloser = nil
}
