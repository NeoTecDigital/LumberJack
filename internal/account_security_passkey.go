// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/NeoTecDigital/LumberJack/internal/core"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

type passkeyUser struct {
	id, name    string
	credentials []webauthn.Credential
}

func (u passkeyUser) WebAuthnID() []byte                         { return []byte(u.id) }
func (u passkeyUser) WebAuthnName() string                       { return u.name }
func (u passkeyUser) WebAuthnDisplayName() string                { return u.name }
func (u passkeyUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

func accountPasskeyUser(user *core.User, account core.AccountSecurity) passkeyUser {
	answer := passkeyUser{id: user.ID, name: user.Username}
	for _, stored := range account.Passkeys {
		var credential webauthn.Credential
		if json.Unmarshal(stored.Credential, &credential) == nil {
			answer.credentials = append(answer.credentials, credential)
		}
	}
	return answer
}

func accountWebAuthn() (*webauthn.WebAuthn, error) {
	id := os.Getenv("MOMENTUM_WEBAUTHN_RP_ID")
	origins := os.Getenv("MOMENTUM_WEBAUTHN_ORIGINS")
	if id == "" || origins == "" {
		return nil, apiErrorf(503, "Passkeys are not configured for this deployment")
	}
	return webauthn.New(&webauthn.Config{RPID: id, RPDisplayName: "Momentum", RPOrigins: strings.Split(origins, ","), AuthenticatorSelection: protocol.AuthenticatorSelection{UserVerification: protocol.VerificationRequired}})
}

func (s *Server) beginPasskey(user *core.User, enroll bool) (any, []byte, error) {
	service, err := accountWebAuthn()
	if err != nil {
		return nil, nil, err
	}
	var identity passkeyUser
	s.readForest(func() { identity = accountPasskeyUser(user, s.forest.AccountSecurity[user.ID]) })
	var options any
	var session *webauthn.SessionData
	if enroll {
		options, session, err = service.BeginRegistration(identity)
	} else {
		options, session, err = service.BeginLogin(identity, webauthn.WithUserVerification(protocol.VerificationRequired))
	}
	if err != nil {
		return nil, nil, apiErrorf(400, "Passkey ceremony unavailable")
	}
	encoded, err := json.Marshal(session)
	return options, encoded, err
}

func (s *Server) finishPasskeyLogin(challenge string, credential json.RawMessage) (any, error) {
	user, err := s.verifyPasskey(challenge, "", "", credential)
	if err != nil {
		return nil, err
	}
	return s.accountSessionAnswer(user)
}

func (s *Server) finishPasskeyEnrollment(userID, key, challenge, name string, credential json.RawMessage) (any, error) {
	if len(strings.TrimSpace(name)) > 100 {
		return nil, apiErrorf(400, "Passkey name must be at most 100 characters")
	}
	user, err := s.verifyPasskey(challenge, key, name, credential)
	if err != nil {
		return nil, err
	}
	if user.ID != userID {
		return nil, apiErrorf(401, "Wrong account")
	}
	return map[string]any{"verified": true}, nil
}

func (s *Server) verifyPasskey(challengeToken, key, name string, response json.RawMessage) (*core.User, error) {
	claims, err := s.parseMFAChallengeToken(challengeToken)
	if err != nil {
		return nil, err
	}
	service, err := accountWebAuthn()
	if err != nil {
		return nil, err
	}
	var user *core.User
	var outcome error
	err = s.changeForest(func() error {
		pending, ok := s.forest.MFAChallenges[claims.ChallengeID]
		if !ok || pending.UserID != claims.UserID || pending.ExpiresAt <= time.Now().Unix() || pending.Attempts >= mfaMaxAttempts || pending.SessionKey != key {
			outcome = apiErrorf(401, "Invalid or expired challenge")
			return nil
		}
		if pending.Method != "webauthn" && pending.Method != "webauthn_enroll" {
			outcome = apiErrorf(401, "Wrong factor")
			return nil
		}
		if pending.Method == "webauthn_enroll" && key == "" {
			outcome = apiErrorf(401, "Authenticated enrollment required")
			return nil
		}
		profile, err := s.forest.GetUserProfile(claims.UserID)
		if err != nil || profile.LockedUntil > time.Now().Unix() || !epochIsCurrent(claims.CredentialEpoch, profile.CredentialEpoch) {
			outcome = apiErrorf(401, "Invalid or expired challenge")
			return nil
		}
		account := s.forest.AccountSecurity[profile.ID]
		identity := accountPasskeyUser(profile, account)
		var session webauthn.SessionData
		if json.Unmarshal(pending.Ceremony, &session) != nil {
			return apiErrorf(500, "Invalid stored ceremony")
		}
		request, _ := http.NewRequest("POST", "https://webauthn.invalid", bytes.NewReader(response))
		var verified *webauthn.Credential
		if pending.Method == "webauthn_enroll" {
			verified, err = service.FinishRegistration(identity, session, request)
		} else {
			verified, err = service.FinishLogin(identity, session, request)
		}
		if err != nil || verified == nil || verified.Authenticator.CloneWarning {
			pending.Attempts++
			for index := range s.forest.Users {
				if s.forest.Users[index].ID == claims.UserID {
					s.forest.Users[index].FailedLogins++
					if s.forest.Users[index].FailedLogins >= loginFailureLimit {
						s.forest.Users[index].LockedUntil = time.Now().Unix() + int64(loginLockout.Seconds())
					}
				}
			}
			if pending.Attempts >= mfaMaxAttempts {
				delete(s.forest.MFAChallenges, claims.ChallengeID)
			} else {
				s.forest.MFAChallenges[claims.ChallengeID] = pending
			}
			outcome = apiErrorf(401, "Passkey verification failed")
			return nil
		}
		encoded, err := json.Marshal(verified)
		if err != nil {
			return err
		}
		id := base64.RawURLEncoding.EncodeToString(verified.ID)
		if pending.Method == "webauthn_enroll" {
			if len(account.Passkeys) >= 20 {
				return apiErrorf(409, "Remove an old passkey before adding another")
			}
			for _, stored := range account.Passkeys {
				if stored.ID == id {
					return apiErrorf(409, "Passkey already enrolled")
				}
			}
			if strings.TrimSpace(name) == "" {
				name = "Passkey"
			}
			account.Passkeys = append(account.Passkeys, core.AccountPasskey{ID: id, Label: strings.TrimSpace(name), CreatedAt: time.Now().Unix(), Credential: encoded})
		} else {
			for i := range account.Passkeys {
				if account.Passkeys[i].ID == id {
					account.Passkeys[i].Credential = encoded
				}
			}
		}
		if s.forest.AccountSecurity == nil {
			s.forest.AccountSecurity = map[string]core.AccountSecurity{}
		}
		s.forest.AccountSecurity[profile.ID] = account
		if key != "" {
			held, ok := s.forest.ApplicationSessions[key]
			if !ok || applicationSessionDeadline(held) <= time.Now().Unix() {
				return apiErrorf(401, "Session expired")
			}
			held.MFAAt = time.Now().Unix()
			s.forest.ApplicationSessions[key] = held
		}
		delete(s.forest.MFAChallenges, claims.ChallengeID)
		for index := range s.forest.Users {
			if s.forest.Users[index].ID == claims.UserID {
				s.forest.Users[index].FailedLogins = 0
				s.forest.Users[index].LockedUntil = 0
			}
		}
		user = &core.User{ID: profile.ID, Username: profile.Username, CredentialEpoch: profile.CredentialEpoch}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return user, outcome
}

func (s *Server) accountSessionAnswer(user *core.User) (map[string]any, error) {
	token, expiry, err := s.mintApplicationSessionAtEpoch(user.ID, &user.CredentialEpoch)
	if err != nil {
		return nil, err
	}
	return map[string]any{"id": user.ID, "username": user.Username, "token": token, "expires_at": expiry, "absolute_expires_at": time.Now().Unix() + applicationSessionTTL}, nil
}
