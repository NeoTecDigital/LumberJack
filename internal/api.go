package internal

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
	"github.com/vaziolabs/lumberjack/internal/core"
	"github.com/vaziolabs/lumberjack/types"
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

// newServerShell builds what BOTH entrypoints start from: a fresh forest, the signing key, the
// logger and the HTTP server. NewServer and LoadServer differ in what they put IN the forest, not
// in how the shell around it is made, and the block was written out twice.
func newServerShell(config types.ServerConfig) (*Server, error) {
	jwtConfig, err := newJWTConfig()
	if err != nil {
		return nil, err
	}

	logger, logCloser := newServerLogger(config)
	return &Server{
		forest:    core.NewForest("forest"),
		jwtConfig: jwtConfig,
		logger:    logger,
		logCloser: logCloser,
		server: &http.Server{
			Addr:    ":" + config.Process.ServerPort,
			Handler: mux.NewRouter(),
		},
		config: config,
	}, nil
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
	if err := server.persistLocked(server.statePath()); err != nil {
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
	defer server.logger.Exit("NewServer")

	if err := server.installAdmin(adminUser); err != nil {
		return nil, err
	}

	server.startRuntime()
	return server, nil
}

func LoadServer(config types.ServerConfig) (*Server, error) {
	server, err := newServerShell(config)
	if err != nil {
		return nil, err
	}

	server.logger.Enter("LoadServer")
	defer server.logger.Exit("LoadServer")

	dbPath := server.statePath()
	server.logger.Debug("Loading database from %s", dbPath)
	if err := server.loadFromFile(dbPath); err != nil {
		server.logger.Failure("failed to load database: %v", err)
		return nil, err
	}

	server.startRuntime()
	server.logger.Info("Loaded existing database from %s", dbPath)
	return server, nil
}

func (s *Server) Start() error {
	if s.server == nil {
		return errors.New("server not initialized")
	}

	s.server.Handler = s.routes()
	go func() {
		s.logger.Info("API server starting on http://localhost" + s.server.Addr)
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Failure("API server error: %v", err)
		}
	}()

	return nil
}

// routes builds the whole HTTP surface, including which parts of it require a session.
//
// It is SEPARATE from Start so that what is public and what is protected can be asserted without
// binding a port. The routing table used to be a local inside Start, which meant no test could tell
// a route registered publicly from one registered behind the middleware — and /users/create was
// registered publicly for exactly that long.
func (s *Server) routes() *mux.Router {
	router := mux.NewRouter()

	// Public routes
	router.HandleFunc("/health", s.handleHealth).Methods("GET")
	router.HandleFunc("/login", s.handleLogin).Methods("POST")
	router.HandleFunc("/refresh", s.handleRefreshToken).Methods("POST")

	s.registerRecordRoutes(router)
	s.registerQueryRoutes(router)
	s.registerAccountRoutes(router)
	return router
}

// registerRecordRoutes registers the routes that WRITE to the forest, and the ones that read one
// thing back by name.
func (s *Server) registerRecordRoutes(router *mux.Router) {
	// Protected routes
	//
	// /users/create IS ONE OF THEM. It was public, which meant anyone who could reach the port could
	// register themselves, receive ReadPermission on the root of the forest, and read the whole tree
	// and the entire user list. Creating a user is an administrative act; the handler checks for
	// AdminPermission and the middleware here is what gives it a caller to check.
	router.HandleFunc("/users/create", s.authMiddleware(s.handleCreateUser)).Methods("POST")
	router.HandleFunc("/time", s.authMiddleware(s.handleGetTimeTracking)).Methods("GET")
	router.HandleFunc("/time/start", s.authMiddleware(s.handleStartTimeTracking)).Methods("POST")
	router.HandleFunc("/time/stop", s.authMiddleware(s.handleStopTimeTracking)).Methods("POST")
	router.HandleFunc("/events", s.authMiddleware(s.handleGetEventEntries)).Methods("POST")
	router.HandleFunc("/events/plan", s.authMiddleware(s.handlePlanEvent)).Methods("POST")
	router.HandleFunc("/events/start", s.authMiddleware(s.handleStartEvent)).Methods("POST")
	router.HandleFunc("/events/append", s.authMiddleware(s.handleAppendToEvent)).Methods("POST")
	router.HandleFunc("/events/end", s.authMiddleware(s.handleEndEvent)).Methods("POST")
	router.HandleFunc("/nodes", s.authMiddleware(s.handleCreateNode)).Methods("POST")
	router.HandleFunc("/forest", s.authMiddleware(s.handleGetForest)).Methods("GET")
	router.HandleFunc("/forest/tree", s.authMiddleware(s.handleGetTree)).Methods("GET")
	router.HandleFunc("/attachments/upload", s.authMiddleware(s.handleUploadAttachment)).Methods("POST")
	router.HandleFunc("/attachments/{id}", s.authMiddleware(s.handleGetAttachment)).Methods("GET")
	router.HandleFunc("/attachments/{id}", s.authMiddleware(s.handleDeleteAttachment)).Methods("DELETE")
	router.HandleFunc("/events/{eventId}/entries/{entryIndex}/attachments", s.authMiddleware(s.handleAddEntryAttachment)).Methods("POST")
	router.HandleFunc("/logs", s.authMiddleware(s.handleGetLogs)).Methods("GET")
}

// registerQueryRoutes registers the query layer, the listings built on it, the canvas routes and
// the live feed.
func (s *Server) registerQueryRoutes(router *mux.Router) {
	// The query layer. One predicate grammar, two entry points, and the discovery routes that are
	// thin wrappers over the first of them rather than a second implementation.
	router.HandleFunc("/query", s.authMiddleware(s.handleQuery)).Methods("POST")
	router.HandleFunc("/aggregate", s.authMiddleware(s.handleAggregate)).Methods("POST")
	// GET /events is the DISCOVERY primitive: POST /events needs an event_id the caller must
	// already possess, so until now there was no way to find out what events exist at all.
	router.HandleFunc("/events", s.authMiddleware(s.handleListEvents)).Methods("GET")
	router.HandleFunc("/entries", s.authMiddleware(s.handleListEntries)).Methods("GET")
	// The canvas routes. Registered BEFORE the {path} catch-all: gorilla matches in registration
	// order, and a catch-all registered first would swallow /nodes/link.
	router.HandleFunc("/nodes/link", s.authMiddleware(s.handleLinkNode)).Methods("POST")
	router.HandleFunc("/nodes/link", s.authMiddleware(s.handleUnlinkNode)).Methods("DELETE")
	router.HandleFunc("/nodes/{path:.*}/metadata", s.authMiddleware(s.handlePatchNodeMetadata)).Methods("PATCH")
	router.HandleFunc("/nodes/{path:.*}", s.authMiddleware(s.handleGetNode)).Methods("GET")
	// The live feed. Registered last of these because it never returns while a client is connected.
	router.HandleFunc("/stream", s.authMiddleware(s.handleStream)).Methods("GET")
}

// registerAccountRoutes registers the user and settings routes.
func (s *Server) registerAccountRoutes(router *mux.Router) {
	router.HandleFunc("/users", s.authMiddleware(s.handleGetUsers)).Methods("GET")
	router.HandleFunc("/users/assign", s.authMiddleware(s.handleAssignUser)).Methods("POST")
	router.HandleFunc("/users/profile", s.authMiddleware(s.handleGetUserProfile)).Methods("GET")
	router.HandleFunc("/settings/", s.authMiddleware(s.handleGetServerSettings)).Methods("GET")
	router.HandleFunc("/settings/update", s.authMiddleware(s.handleUpdateServerSettings)).Methods("POST")
}

func (s *Server) Shutdown(ctx context.Context) error {
	// Signal workers to shut down
	close(s.apiQueue.shutdown)

	// Wait for all workers to finish
	s.apiQueue.wg.Wait()

	if s.server != nil {
		s.logger.Info("Shutting down API server")
		err := s.server.Shutdown(ctx)
		s.closeLogSink()
		return err
	}

	s.closeLogSink()
	return nil
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
