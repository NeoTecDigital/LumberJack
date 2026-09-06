package dashboard

import (
	"context"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/NeoTecDigital/LumberJack/types"
)

const (
	ReadPermission Permission = iota
	WritePermission
	AdminPermission
)

func NewDashboard(apiEndpoint string, port string) *DashboardServer {
	router := mux.NewRouter()

	dashboardServer := &DashboardServer{
		apiEndpoint: apiEndpoint,
		server: &http.Server{
			Handler:      router,
			Addr:         ":" + port,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
		},
		logger: types.NewLogger(),
	}

	// Serve static files
	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("dashboard/static"))))

	// Auth routes
	router.HandleFunc("/login", dashboardServer.handleLogin).Methods("POST")
	router.HandleFunc("/api/refresh", dashboardServer.handleRefreshToken).Methods("POST")

	// Protected API routes
	protected := router.PathPrefix("/api").Subrouter()
	protected.Use(dashboardServer.authMiddleware)
	protected.HandleFunc("/forest", dashboardServer.handleGetTree).Methods("GET")
	protected.HandleFunc("/events", dashboardServer.handleGetEvents).Methods("GET")
	protected.HandleFunc("/logs", dashboardServer.handleGetLogs).Methods("GET")
	protected.HandleFunc("/users", dashboardServer.handleGetUsers).Methods("GET")
	protected.HandleFunc("/users", dashboardServer.handleCreateUser).Methods("POST")
	protected.HandleFunc("/user/profile", dashboardServer.handleGetUserProfile).Methods("GET")
	protected.HandleFunc("/logout", dashboardServer.handleLogout).Methods("POST")
	protected.HandleFunc("/settings", dashboardServer.handleUpdateSettings).Methods("POST")

	// Main dashboard routes
	router.HandleFunc("/", dashboardServer.handleLoginPage).Methods("GET")
	router.Handle("/dashboard", dashboardServer.authMiddleware(http.HandlerFunc(dashboardServer.handleDashboard))).Methods("GET")

	return dashboardServer
}

func (s *DashboardServer) Start() error {
	go func() {
		s.logger.Info("Dashboard server starting on http://localhost:" + s.server.Addr)
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Failure("Dashboard server error: %v", err)
		}
	}()
	return nil
}

func (s *DashboardServer) Shutdown(ctx context.Context) error {
	if s.server != nil {
		s.logger.Info("Shutting down dashboard server")
		return s.server.Shutdown(ctx)
	}
	return nil
}
