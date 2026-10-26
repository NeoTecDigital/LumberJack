// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
)

// Extracted without changing native ms_/HMAC/MFA/epoch/registry semantics.
func (server *Server) serveLegacyAuth(next http.HandlerFunc, w http.ResponseWriter, r *http.Request) {
	tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if strings.HasPrefix(tokenString, "ms_") {
		server.serveApplicationSession(next, w, r, tokenString)
		return
	}
	if tokenString == "" {
		http.Error(w, "No token provided", http.StatusUnauthorized)
		return
	}
	claims, refusal := server.legacySessionClaims(tokenString)
	if refusal != "" {
		http.Error(w, refusal, http.StatusUnauthorized)
		return
	}
	ctx := context.WithValue(r.Context(), "user_id", claims.UserID)
	if claims.ExpiresAt > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, time.Unix(claims.ExpiresAt, 0))
		defer cancel()
	}
	next.ServeHTTP(w, r.WithContext(ctx))
}

func (server *Server) legacySessionClaims(tokenString string) (*TokenClaims, string) {
	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return server.jwtConfig.SecretKey, nil
	})
	if err != nil || !token.Valid {
		return nil, "Invalid token"
	}
	claims, ok := token.Claims.(*TokenClaims)
	if !ok || claims.TokenType != "session" {
		return nil, "Invalid session token"
	}
	// Epoch remains the sole forest read; session liveness remains registry-bound.
	if !server.credentialIsCurrent(claims.UserID, claims.CredentialEpoch) {
		return nil, "Invalid session token"
	}
	held, live := server.registeredSession(claims.SessionID)
	if !live || held.UserID != claims.UserID {
		return nil, "Session expired or signed out"
	}
	claims.ExpiresAt = min(claims.ExpiresAt, applicationSessionDeadline(held))
	return claims, ""
}
