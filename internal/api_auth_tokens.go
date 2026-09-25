// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"fmt"
	"strings"
	"time"

	"github.com/NeoTecDigital/LumberJack/internal/core"
	"github.com/golang-jwt/jwt"
)

func (s *Server) sessionKeyFromBearer(token string) string {
	if strings.HasPrefix(token, "ms_") {
		return s.sessionHash(token)
	}
	parsed, err := jwt.ParseWithClaims(token, &TokenClaims{}, func(parsed *jwt.Token) (any, error) {
		if parsed.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return s.jwtConfig.SecretKey, nil
	})
	if err != nil || !parsed.Valid {
		return ""
	}
	claims, ok := parsed.Claims.(*TokenClaims)
	if !ok || claims.TokenType != "session" {
		return ""
	}
	return claims.SessionID
}

func (s *Server) generateTokenPair(user *core.User) (*TokenPair, error) {
	token, _, err := s.mintApplicationSessionAtEpoch(user.ID, &user.CredentialEpoch)
	if err != nil {
		return nil, err
	}
	return s.signedSessionPair(user, s.sessionHash(token))
}

// Refresh never creates a new session family or counts as foreground activity.
// Both credentials stop at the registry's idle deadline and original maximum.
func (s *Server) signedSessionPair(user *core.User, key string) (*TokenPair, error) {
	session, valid := s.registeredSession(key)
	if !valid || session.UserID != user.ID {
		return nil, apiErrorf(401, "Session expired or signed out")
	}
	issue := func(kind string, expiry int64) (string, error) {
		claims := TokenClaims{UserID: user.ID, Username: user.Username, TokenType: kind, SessionID: key, CredentialEpoch: session.CredentialEpoch, StandardClaims: jwt.StandardClaims{IssuedAt: time.Now().Unix(), ExpiresAt: expiry}}
		return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.jwtConfig.SecretKey)
	}
	access, err := issue("session", applicationSessionDeadline(session))
	if err != nil {
		return nil, err
	}
	refresh, err := issue("refresh", min(session.ExpiresAt, session.CreatedAt+applicationSessionTTL))
	if err != nil {
		return nil, err
	}
	return &TokenPair{SessionToken: access, RefreshToken: refresh}, nil
}
