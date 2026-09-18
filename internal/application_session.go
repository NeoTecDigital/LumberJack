package internal

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/NeoTecDigital/LumberJack/internal/core"
	"net/http"
	"strings"
	"time"
)

func (s *Server) sessionHash(token string) string {
	h := hmac.New(sha256.New, s.jwtConfig.SecretKey)
	h.Write([]byte(token))
	return hex.EncodeToString(h.Sum(nil))
}

func (s *Server) applicationSession(token string) (core.ApplicationSession, bool) {
	var session core.ApplicationSession
	valid := false
	s.readForest(func() {
		session, valid = s.forest.ApplicationSessions[s.sessionHash(token)]
		if valid {
			_, err := s.forest.GetUserProfile(session.UserID)
			valid = err == nil && session.ExpiresAt > time.Now().Unix()
		}
	})
	return session, valid
}

func (s *Server) serveApplicationSession(next http.HandlerFunc, w http.ResponseWriter, r *http.Request, token string) {
	session, ok := s.applicationSession(token)
	if !ok {
		http.Error(w, "Session expired or signed out", 401)
		return
	}
	ctx := context.WithValue(r.Context(), "user_id", session.UserID)
	ctx, cancel := context.WithDeadline(ctx, time.Unix(session.ExpiresAt, 0))
	defer cancel()
	next(w, r.WithContext(ctx))
}

func (s *Server) handleApplicationSession(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if r.Method == "POST" {
		var input struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if json.NewDecoder(r.Body).Decode(&input) != nil {
			http.Error(w, "Invalid credentials", 400)
			return
		}
		user := s.findUserByName(input.Username)
		if user == nil || !user.VerifyPassword(input.Password) {
			http.Error(w, "Invalid credentials", 401)
			return
		}
		bytes := make([]byte, 32)
		if _, err := rand.Read(bytes); err != nil {
			http.Error(w, "Session unavailable", 500)
			return
		}
		token = "ms_" + hex.EncodeToString(bytes)
		err := s.changeForest(func() error {
			if _, err := s.forest.GetUserProfile(user.ID); err != nil {
				return apiErrorf(401, "Account unavailable")
			}
			if s.forest.ApplicationSessions == nil {
				s.forest.ApplicationSessions = map[string]core.ApplicationSession{}
			}
			now := time.Now().Unix()
			count := 0
			oldestKey := ""
			var oldest int64
			for key, item := range s.forest.ApplicationSessions {
				if item.ExpiresAt <= now {
					delete(s.forest.ApplicationSessions, key)
					continue
				}
				if item.UserID == user.ID {
					count++
					if oldestKey == "" || item.CreatedAt < oldest {
						oldestKey, oldest = key, item.CreatedAt
					}
				}
			}
			if count >= 20 {
				delete(s.forest.ApplicationSessions, oldestKey)
			}
			s.forest.ApplicationSessions[s.sessionHash(token)] = core.ApplicationSession{UserID: user.ID, CreatedAt: now, ExpiresAt: now + 30*24*3600}
			return nil
		})
		if err != nil {
			writeAPIError(w, err)
			return
		}
	}
	if r.Method == "DELETE" {
		if err := s.changeForest(func() error { delete(s.forest.ApplicationSessions, s.sessionHash(token)); return nil }); err != nil {
			writeAPIError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"signed_out":true}`))
		return
	}
	session, ok := s.applicationSession(token)
	if !ok {
		http.Error(w, "Session expired or signed out", 401)
		return
	}
	s.readForest(func() {
		profile, err := s.forest.GetUserProfile(session.UserID)
		if err != nil {
			http.Error(w, "Account unavailable", 401)
			return
		}
		result := map[string]interface{}{"id": profile.ID, "username": profile.Username, "expires_at": session.ExpiresAt}
		if r.Method == "POST" {
			result["token"] = token
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	})
}
