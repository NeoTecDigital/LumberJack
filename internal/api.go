package internal

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/gorilla/mux"
	"github.com/vaziolabs/lumberjack/internal/core"
	"github.com/vaziolabs/lumberjack/types"
)

func NewServer(config types.ServerConfig, adminUser core.User) (*Server, error) {
	router := mux.NewRouter()

	// Load JWT secret from environment variable
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		return nil, errors.New("JWT_SECRET environment variable not set")
	}

	server := &Server{
		forest: core.NewForest("forest"),
		jwtConfig: JWTConfig{
			SecretKey: []byte(jwtSecret),
			ExpiresIn: 24 * time.Hour,
		},
		logger: types.NewLogger(),
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
		ID:           core.GenerateID(),
		Name:         adminUser.Name,
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

	dbPath := filepath.Join(config.Process.DatabasePath, config.Process.Name+".dat")
	if err := server.writeChangesToFile(server.forest, dbPath); err != nil {
		server.logger.Failure("failed to save state after user creation: %v", err)
		return nil, err
	}

	server.initCache()
	server.initAPIQueue(5) // Start with 5 workers

	return server, nil
}

func LoadServer(config types.ServerConfig) (*Server, error) {
	router := mux.NewRouter()

	// Load JWT secret from environment variable
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		return nil, errors.New("JWT_SECRET environment variable not set")
	}

	server := &Server{
		forest: core.NewForest("forest"),
		jwtConfig: JWTConfig{
			SecretKey: []byte(jwtSecret),
			ExpiresIn: 24 * time.Hour,
		},
		logger: types.NewLogger(),
		server: &http.Server{
			Addr:    ":" + config.Process.ServerPort,
			Handler: router,
		},
		config: config,
	}

	server.logger.Enter("LoadServer")
	defer server.logger.Exit("LoadServer")

	dbPath := filepath.Join(config.Process.DatabasePath, config.Process.Name+".dat")
	server.logger.Debug("Loading database from %s", dbPath)
	if err := server.loadFromFile(dbPath); err != nil {
		server.logger.Failure("failed to load database: %v", err)
		return nil, err
	}

	server.initCache()
	server.initAPIQueue(5) // Start with 5 workers

	server.logger.Info("Loaded existing database from %s", dbPath)
	return server, nil
}

func (s *Server) Start() error {
	if s.server == nil {
		return errors.New("server not initialized")
	}

	router := mux.NewRouter()

	// Public routes
	router.HandleFunc("/login", s.handleLogin).Methods("POST")
	router.HandleFunc("/refresh", s.handleRefreshToken).Methods("POST")
	router.HandleFunc("/users/create", s.handleCreateUser).Methods("POST")
	// Protected routes
	router.HandleFunc("/time", s.authMiddleware(s.handleGetTimeTracking)).Methods("GET")
	router.HandleFunc("/time/start", s.authMiddleware(s.handleStartTimeTracking)).Methods("POST")
	router.HandleFunc("/time/stop", s.authMiddleware(s.handleStopTimeTracking)).Methods("POST")
	router.HandleFunc("/events", s.authMiddleware(s.handleGetEventEntries)).Methods("POST")
	router.HandleFunc("/events/plan", s.authMiddleware(s.handlePlanEvent)).Methods("POST")
	router.HandleFunc("/events/start", s.authMiddleware(s.handleStartEvent)).Methods("POST")
	router.HandleFunc("/events/append", s.authMiddleware(s.handleAppendToEvent)).Methods("POST")
	router.HandleFunc("/events/end", s.authMiddleware(s.handleEndEvent)).Methods("POST")
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
	// Node management routes
	router.HandleFunc("/nodes/create", s.authMiddleware(s.handleCreateNode)).Methods("POST")
	router.HandleFunc("/nodes/metadata", s.authMiddleware(s.handleUpdateNodeMetadata)).Methods("PUT")
	router.HandleFunc("/nodes/get", s.authMiddleware(s.handleGetNodeByPath)).Methods("GET")

	s.server.Handler = router
	go func() {
		s.logger.Info("API server starting on http://localhost" + s.server.Addr)
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Failure("API server error: %v", err)
		}
	}()

	return nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	// Signal workers to shut down
	close(s.apiQueue.shutdown)

	// Wait for all workers to finish
	s.apiQueue.wg.Wait()

	if s.server != nil {
		s.logger.Info("Shutting down API server")
		return s.server.Shutdown(ctx)
	}
	return nil
}
