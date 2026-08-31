package internal

import (
	"encoding/json"
	"net/http"

	"github.com/golang-jwt/jwt"
	"github.com/vaziolabs/lumberjack/internal/core"
)

// The routes that make a user and turn a credential into a session, and the claims they carry.

// HTTP handler for creating a user
func (server *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	server.logger.Enter("CreateUser")
	defer server.logger.Exit("CreateUser")

	var request struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		server.logger.Failure("Failed to decode request: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Create new user
	user := core.User{
		ID:       core.GenerateUserID(),
		Username: request.Username,
		Email:    request.Email,
	}

	if err := user.SetPassword(request.Password); err != nil {
		server.logger.Failure("Failed to set password: %v", err)
		http.Error(w, "Failed to set password", http.StatusInternalServerError)
		return
	}

	// Add user to the root node
	if err := server.forest.AssignUser(user, core.ReadPermission); err != nil {
		server.logger.Failure("Failed to assign user: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Save state
	if err := server.writeChangesToFile(server.statePath()); err != nil {
		server.logger.Failure("Failed to save state: %v", err)
		http.Error(w, "Failed to save state", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	server.logger.Success("User created successfully")
}

// Add new handlers
func (server *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	server.logger.Enter("handleLogin")
	defer server.logger.Exit("handleLogin")

	var credentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
		server.logger.Failure("Invalid request: %v", err)
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	server.logger.Info("Attempting login for user: %s", credentials.Username)
	server.logger.Info("Number of users in system: %d", len(server.forest.Users))

	// Get pointer to user to avoid copying
	var foundUser *core.User
	for i := range server.forest.Users {
		if server.forest.Users[i].Username == credentials.Username {
			foundUser = &server.forest.Users[i]
			break
		}
	}

	if foundUser == nil {
		server.logger.Failure("User not found: %s", credentials.Username)
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	if !foundUser.VerifyPassword(credentials.Password) {
		server.logger.Failure("Invalid password for user: %s", credentials.Username)
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Generate token pair
	tokenPair, err := server.generateTokenPair(foundUser)
	if err != nil {
		server.logger.Failure("Failed to generate tokens: %v", err)
		http.Error(w, "Failed to generate tokens", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"session_token": tokenPair.SessionToken,
		"refresh_token": tokenPair.RefreshToken,
	})
	server.logger.Success("Login successful for user %s", foundUser.Username)
}

// Add new handler for token refresh
func (server *Server) handleRefreshToken(w http.ResponseWriter, r *http.Request) {
	var request struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	token, err := jwt.ParseWithClaims(request.RefreshToken, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return server.jwtConfig.SecretKey, nil
	})

	if err != nil || !token.Valid {
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	claims, ok := token.Claims.(*TokenClaims)
	if !ok || claims.TokenType != "refresh" {
		http.Error(w, "Invalid token type", http.StatusUnauthorized)
		return
	}

	// Generate new session token
	user := &core.User{ID: claims.UserID, Username: claims.Username}
	tokenPair, err := server.generateTokenPair(user)
	if err != nil {
		http.Error(w, "Failed to generate tokens", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"session_token": tokenPair.SessionToken,
	})
}

func (server *Server) handleGetUserProfile(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFrom(r)
	if !ok {
		http.Error(w, "No user in session", http.StatusUnauthorized)
		return
	}

	user, err := server.forest.GetUserProfile(userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"username":     user.Username,
		"email":        user.Email,
		"organization": user.Organization,
		"phone":        user.Phone,
		"permissions":  user.Permissions,
	})
}

// Add these structures for token management
type TokenPair struct {
	SessionToken string `json:"session_token"`
	RefreshToken string `json:"refresh_token"`
}

type TokenClaims struct {
	UserID    string `json:"user_id"`
	Username  string `json:"username"`
	TokenType string `json:"token_type"` // "session" or "refresh"
	jwt.StandardClaims
}
