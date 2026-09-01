package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/vaziolabs/lumberjack/internal/core"
)

// The routes that make a user and turn a credential into a session, and the claims they carry.

// handleCreateUser creates a user, and is an ADMINISTRATIVE route.
//
// It used to be registered as a PUBLIC route. Self-registration granted ReadPermission on the root
// of the forest, and the read routes ask for nothing beyond a valid session — so anyone who could
// reach the port could mint an account, log in, and read the entire forest and the whole user list.
// There is no evidence self-registration was intended: the dashboard's own create-user route sits
// behind the dashboard's authenticated subrouter, which is the only caller in the tree.
//
// The check matches handleAssignUser: only a user holding AdminPermission may widen the set of
// people who can see the data.
func (server *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	server.logger.Enter("CreateUser")
	defer server.logger.Exit("CreateUser")

	if _, ok := server.requireAdmin(w, r); !ok {
		return
	}

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

	// A user with no name cannot be logged in as and cannot be told apart from the next one, and a
	// user with no password is an account whose credential is the empty string.
	if strings.TrimSpace(request.Username) == "" {
		http.Error(w, "username is required", http.StatusBadRequest)
		return
	}
	if request.Password == "" {
		http.Error(w, "password is required", http.StatusBadRequest)
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

	// Add user to the root node, under the same exclusive hold that persists it.
	if err := server.changeForest(func() error {
		if err := server.forest.AssignUser(user, core.ReadPermission); err != nil {
			return apiErrorf(http.StatusInternalServerError, "%v", err)
		}
		return nil
	}); err != nil {
		server.logger.Failure("Failed to create user: %v", err)
		writeAPIError(w, err)
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

	foundUser := server.findUserByName(credentials.Username)
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

// findUserByName looks a credential up, WITH THE FOREST HELD FOR READING.
//
// The login route used to range server.forest.Users with no hold at all, while AssignUser appends
// to that same slice under the exclusive one — an unsynchronized slice read against a concurrent
// append, which is the defect forest_lock.go exists to close, on the one route every session starts
// with.
//
// It returns a COPY. A pointer into the slice outlives the hold, and the next append can move the
// backing array out from under it.
func (server *Server) findUserByName(username string) *core.User {
	var found *core.User
	server.readForest(func() {
		server.logger.Info("Number of users in system: %d", len(server.forest.Users))
		for index := range server.forest.Users {
			if server.forest.Users[index].Username != username {
				continue
			}
			copied := server.forest.Users[index]
			copied.Permissions = append([]core.Permission(nil), copied.Permissions...)
			found = &copied
			return
		}
	})
	return found
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

	// PROJECTED INSIDE THE HOLD. GetUserProfile hands back a copy of the User struct, but its
	// Permissions field is still the forest's own slice — encoding it after the hold was released
	// was a read of a slice AssignUser appends to.
	var profile userView
	var err error
	server.readForest(func() {
		var user *core.User
		user, err = server.forest.GetUserProfile(userID)
		if err != nil {
			return
		}
		profile = newUserView(*user)
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"username":     profile.Username,
		"email":        profile.Email,
		"organization": profile.Organization,
		"phone":        profile.Phone,
		"permissions":  profile.Permissions,
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

// The session guard the routes are wrapped in, and the pair of tokens a login hands out. They live
// beside the routes that issue and consume them rather than in a helpers bucket.

// Update the auth middleware to handle user_id from token claims
func (server *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if tokenString == "" {
			http.Error(w, "No token provided", http.StatusUnauthorized)
			return
		}

		token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return server.jwtConfig.SecretKey, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		claims, ok := token.Claims.(*TokenClaims)
		if !ok || claims.TokenType != "session" {
			http.Error(w, "Invalid session token", http.StatusUnauthorized)
			return
		}

		// Add user info to context
		ctx := context.WithValue(r.Context(), "user_id", claims.UserID)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// userIDFrom reads the caller that authMiddleware put in the request context.
//
// The unchecked `r.Context().Value("user_id").(string)` this replaces PANICKED on a nil interface
// conversion whenever a handler was reached without one, which takes the whole process down instead
// of answering 401.
func userIDFrom(r *http.Request) (string, bool) {
	userID, ok := r.Context().Value("user_id").(string)
	return userID, ok && userID != ""
}

// requireAdmin reads the caller and confirms it administers the forest.
//
// It ANSWERS THE REQUEST on refusal and reports false, so a handler guards itself in three lines
// instead of repeating the same eight. The refusals are told apart: no session is 401, a session
// without the authority is 403.
func (server *Server) requireAdmin(w http.ResponseWriter, r *http.Request) (string, bool) {
	userID, ok := userIDFrom(r)
	if !ok {
		http.Error(w, "No user in session", http.StatusUnauthorized)
		return "", false
	}

	// Under the read hold: CheckPermission ranges the root's Users, which AssignUser appends to
	// under the exclusive one.
	administers := false
	server.readForest(func() {
		administers = server.forest.CheckPermission(userID, core.AdminPermission)
	})
	if !administers {
		http.Error(w, "Insufficient permissions", http.StatusForbidden)
		return "", false
	}

	return userID, true
}

func (server *Server) generateTokenPair(user *core.User) (*TokenPair, error) {
	// Generate session token (short-lived)
	sessionClaims := TokenClaims{
		UserID:    user.ID,
		Username:  user.Username,
		TokenType: "session",
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
			IssuedAt:  time.Now().Unix(),
		},
	}

	sessionToken := jwt.NewWithClaims(jwt.SigningMethodHS256, sessionClaims)
	sessionTokenString, err := sessionToken.SignedString(server.jwtConfig.SecretKey)
	if err != nil {
		return nil, err
	}

	// Generate refresh token (long-lived)
	refreshClaims := TokenClaims{
		UserID:    user.ID,
		Username:  user.Username,
		TokenType: "refresh",
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(7 * 24 * time.Hour).Unix(),
			IssuedAt:  time.Now().Unix(),
		},
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString(server.jwtConfig.SecretKey)
	if err != nil {
		return nil, err
	}

	return &TokenPair{
		SessionToken: sessionTokenString,
		RefreshToken: refreshTokenString,
	}, nil
}
