package dashboard

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func (s *DashboardServer) handleDashboard(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("dashboard/templates/index.html"))
	tmpl.Execute(w, nil)
}

func (s *DashboardServer) handleGetTree(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		http.Error(w, "No authentication token found", http.StatusUnauthorized)
		return
	}

	req, _ := http.NewRequest("GET", s.apiEndpoint+"/forest", nil)
	req.Header.Set("Authorization", "Bearer "+cookie.Value)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Error connecting to API server: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	io.Copy(w, resp.Body)
}

func (s *DashboardServer) handleGetEvents(w http.ResponseWriter, r *http.Request) {
	// Forward request to API server
	req, _ := http.NewRequest("POST", s.apiEndpoint+"/events", r.Body)
	req.Header.Set("Authorization", r.Header.Get("Authorization"))
	req.Header.Set("X-User-ID", r.Header.Get("X-User-ID"))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	io.Copy(w, resp.Body)
}

func (s *DashboardServer) handleGetLogs(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"logs":[],"has_more":false}`))
		return
	}

	// Create new request to API server
	req, _ := http.NewRequest("GET", s.apiEndpoint+"/logs", nil)
	req.Header.Set("Authorization", "Bearer "+cookie.Value)
	req.Header.Set("Content-Type", "application/json")

	// Forward all query parameters including last_event_id
	req.URL.RawQuery = r.URL.RawQuery

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"logs":[],"has_more":false}`))
		return
	}
	defer resp.Body.Close()

	// Read and validate the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil || !json.Valid(body) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"logs":[],"has_more":false}`))
		return
	}

	// Forward the response
	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}

func (s *DashboardServer) handleGetUsers(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		http.Error(w, "No authentication token found", http.StatusUnauthorized)
		return
	}

	req, _ := http.NewRequest("GET", s.apiEndpoint+"/users", nil)
	req.Header.Set("Authorization", "Bearer "+cookie.Value)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Error connecting to API server: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	io.Copy(w, resp.Body)
}

func (s *DashboardServer) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var user UserData
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := json.Unmarshal(body, &user); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// The Authorization header the dashboard's own middleware put on this request is FORWARDED.
	// /users/create is no longer a public route on the API — creating a user is an administrative
	// act — and a bare http.Post carries no credential, so this proxy would answer 401 forever.
	req, err := http.NewRequest("POST", s.apiEndpoint+"/users/create", bytes.NewBuffer(body))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", r.Header.Get("Authorization"))

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (s *DashboardServer) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("dashboard/templates/login.html"))
	tmpl.Execute(w, nil)
}

func (s *DashboardServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	s.logger.Enter("Login")
	defer s.logger.Exit("Login")

	// Read the request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.logger.Error("Error reading request body: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Forward login request to API
	resp, err := http.Post(s.apiEndpoint+"/login", "application/json", bytes.NewBuffer(body))
	if err != nil {
		s.logger.Error("Error connecting to API: %v", err)
		http.Error(w, "Failed to connect to API", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Read the API response
	apiResponse, err := io.ReadAll(resp.Body)
	if err != nil {
		s.logger.Error("Error reading API response: %v", err)
		http.Error(w, "Failed to read API response", http.StatusInternalServerError)
		return
	}

	// Parse the API response
	var loginResponse struct {
		SessionToken string `json:"session_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(apiResponse, &loginResponse); err != nil {
		s.logger.Error("Error parsing API response: %v", err)
		http.Error(w, "Invalid API response", http.StatusInternalServerError)
		return
	}

	// Set cookies if we have valid tokens
	if loginResponse.SessionToken != "" {
		isSecure := !strings.HasPrefix(s.apiEndpoint, "http://localhost")

		// Parse the JWT to get expiry time
		parts := strings.Split(loginResponse.SessionToken, ".")
		if len(parts) == 3 {
			var claims struct {
				Exp int64 `json:"exp"`
			}
			if payload, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
				if err := json.Unmarshal(payload, &claims); err == nil {
					http.SetCookie(w, &http.Cookie{
						Name:     "session_expiry",
						Value:    strconv.FormatInt(claims.Exp*1000, 10), // Convert to milliseconds
						Path:     "/",
						HttpOnly: false,
						Secure:   isSecure,
						SameSite: http.SameSiteStrictMode,
						MaxAge:   3600,
					})
				}
			}
		}

		// Set session token cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "session_token",
			Value:    loginResponse.SessionToken,
			Path:     "/",
			HttpOnly: false,
			Secure:   isSecure,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   3600,
		})

		// Set refresh token cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "refresh_token",
			Value:    loginResponse.RefreshToken,
			Path:     "/",
			HttpOnly: true,
			Secure:   isSecure,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   604800,
		})
	}

	// Forward the API response to the client
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	w.Write(apiResponse)
}

func (s *DashboardServer) handleRefreshToken(w http.ResponseWriter, r *http.Request) {
	// Get refresh token from cookie
	refreshCookie, err := r.Cookie("refresh_token")
	if err != nil {
		http.Error(w, "No refresh token found", http.StatusUnauthorized)
		return
	}

	// Forward refresh request to API
	req, _ := http.NewRequest("POST", s.apiEndpoint+"/refresh", nil)
	req.Header.Set("Authorization", "Bearer "+refreshCookie.Value)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Error connecting to API server", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Parse the API response
	var newTokens struct {
		SessionToken string `json:"session_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&newTokens); err != nil {
		http.Error(w, "Invalid API response", http.StatusInternalServerError)
		return
	}

	// Set new cookies if we have valid tokens
	if newTokens.SessionToken != "" {
		isSecure := !strings.HasPrefix(s.apiEndpoint, "http://localhost")

		// Parse the JWT to get expiry time
		parts := strings.Split(newTokens.SessionToken, ".")
		if len(parts) == 3 {
			var claims struct {
				Exp int64 `json:"exp"`
			}
			if payload, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
				if err := json.Unmarshal(payload, &claims); err == nil {
					http.SetCookie(w, &http.Cookie{
						Name:     "session_expiry",
						Value:    strconv.FormatInt(claims.Exp*1000, 10), // Convert to milliseconds
						Path:     "/",
						HttpOnly: false,
						Secure:   isSecure,
						SameSite: http.SameSiteStrictMode,
					})
				}
			}
		}

		// Set new session token
		http.SetCookie(w, &http.Cookie{
			Name:     "session_token",
			Value:    newTokens.SessionToken,
			Path:     "/",
			HttpOnly: false,
			Secure:   isSecure,
			SameSite: http.SameSiteStrictMode,
		})

		// Set new refresh token
		http.SetCookie(w, &http.Cookie{
			Name:     "refresh_token",
			Value:    newTokens.RefreshToken,
			Path:     "/",
			HttpOnly: true,
			Secure:   isSecure,
			SameSite: http.SameSiteStrictMode,
		})
	}

	w.WriteHeader(http.StatusOK)
}

func (s *DashboardServer) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_token")
		if err != nil {
			s.logger.Error("No session token found")
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		r.Header.Set("Authorization", "Bearer "+cookie.Value)
		next.ServeHTTP(w, r)
	})
}

func (s *DashboardServer) handleGetUserProfile(w http.ResponseWriter, r *http.Request) {
	// Forward request to API server
	req, _ := http.NewRequest("GET", s.apiEndpoint+"/users/profile", nil)
	req.Header.Set("Authorization", r.Header.Get("Authorization"))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Error connecting to API server: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	io.Copy(w, resp.Body)
}

func (s *DashboardServer) handleLogout(w http.ResponseWriter, r *http.Request) {
	// Clear cookies with same attributes
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Path:     "/",
		Expires:  time.Now().Add(-24 * time.Hour),
		HttpOnly: false,
		Secure:   !strings.HasPrefix(s.apiEndpoint, "http://localhost"),
		SameSite: http.SameSiteStrictMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Path:     "/",
		Expires:  time.Now().Add(-24 * time.Hour),
		HttpOnly: true,
		Secure:   !strings.HasPrefix(s.apiEndpoint, "http://localhost"),
		SameSite: http.SameSiteStrictMode,
	})
	w.WriteHeader(http.StatusOK)
}

func (s *DashboardServer) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	req, _ := http.NewRequest("POST", s.apiEndpoint+"/settings/update", r.Body)
	req.Header.Set("Authorization", r.Header.Get("Authorization"))
	req.Header.Set("X-User-ID", r.Header.Get("X-User-ID"))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Error connecting to API server: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}
