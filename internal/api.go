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

func NewServer(config types.ServerConfig, adminUser core.User) (*Server, error) {
	router := mux.NewRouter()

	jwtConfig, err := newJWTConfig()
	if err != nil {
		return nil, err
	}

	logger, logCloser := newServerLogger(config)
	server := &Server{
		forest:    core.NewForest("forest"),
		jwtConfig: jwtConfig,
		logger:    logger,
		logCloser: logCloser,
		server: &http.Server{
			Addr:    ":" + config.Process.ServerPort,
			Handler: router,
		},
		config: config,
	}

	server.logger.Enter("NewServer")
	defer server.logger.Exit("NewServer")

	// Create admin user for new database
	coreUser := core.User{
		ID:           core.GenerateUserID(),
		Username:     adminUser.Username,
		Email:        adminUser.Email,
		Organization: adminUser.Organization,
		Phone:        adminUser.Phone,
	}

	if err := coreUser.SetPassword(adminUser.Password); err != nil {
		server.logger.Failure("failed to set admin password: %v", err)
		return nil, err
	}

	if err := server.forest.AssignUser(coreUser, core.AdminPermission); err != nil {
		server.logger.Failure("failed to save admin user: %v", err)
		return nil, err
	}

	if err := server.writeChangesToFile(server.statePath()); err != nil {
		server.logger.Failure("failed to save state after user creation: %v", err)
		return nil, err
	}

	server.initCache()
	server.initAPIQueue(5) // Start with 5 workers

	return server, nil
}

func LoadServer(config types.ServerConfig) (*Server, error) {
	router := mux.NewRouter()

	jwtConfig, err := newJWTConfig()
	if err != nil {
		return nil, err
	}

	logger, logCloser := newServerLogger(config)
	server := &Server{
		forest:    core.NewForest("forest"),
		jwtConfig: jwtConfig,
		logger:    logger,
		logCloser: logCloser,
		server: &http.Server{
			Addr:    ":" + config.Process.ServerPort,
			Handler: router,
		},
		config: config,
	}

	server.logger.Enter("LoadServer")
	defer server.logger.Exit("LoadServer")

	dbPath := server.statePath()
	server.logger.Debug("Loading database from %s", dbPath)
	if err := server.loadFromFile(dbPath); err != nil {
		server.logger.Failure("failed to load database: %v", err)
		return nil, err
	}

	// A LOADED database needs the same cache and worker pool a NEW one gets. Without them every
	// node-path route nil-panics in getFromCache and Shutdown nil-panics on the queue, which made
	// a restart fatal to the whole /events/* surface.
	server.initCache()
	server.initAPIQueue(5) // Start with 5 workers

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
	router.HandleFunc("/users", s.authMiddleware(s.handleGetUsers)).Methods("GET")
	router.HandleFunc("/users/assign", s.authMiddleware(s.handleAssignUser)).Methods("POST")
	router.HandleFunc("/users/profile", s.authMiddleware(s.handleGetUserProfile)).Methods("GET")
	router.HandleFunc("/settings/", s.authMiddleware(s.handleGetServerSettings)).Methods("GET")
	router.HandleFunc("/settings/update", s.authMiddleware(s.handleUpdateServerSettings)).Methods("POST")
	router.HandleFunc("/attachments/upload", s.authMiddleware(s.handleUploadAttachment)).Methods("POST")
	router.HandleFunc("/attachments/{id}", s.authMiddleware(s.handleGetAttachment)).Methods("GET")
	router.HandleFunc("/attachments/{id}", s.authMiddleware(s.handleDeleteAttachment)).Methods("DELETE")
	router.HandleFunc("/events/{eventId}/entries/{entryIndex}/attachments", s.authMiddleware(s.handleAddEntryAttachment)).Methods("POST")
	router.HandleFunc("/logs", s.authMiddleware(s.handleGetLogs)).Methods("GET")

	return router
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
