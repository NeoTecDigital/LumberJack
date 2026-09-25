// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"encoding/json"
	"net/http"
	"net/mail"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

type accountSecurityRequest struct {
	Operation  string          `json:"operation"`
	Method     string          `json:"method"`
	Challenge  string          `json:"challenge"`
	Code       string          `json:"code"`
	Target     string          `json:"target"`
	SessionID  string          `json:"session_id"`
	Name       string          `json:"name"`
	Contacts   []string        `json:"contacts"`
	Credential json.RawMessage `json:"credential"`
	PhoneLast4 string          `json:"phone_last4"`
}

func securityInput(w http.ResponseWriter, r *http.Request) (accountSecurityRequest, bool) {
	var input accountSecurityRequest
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 128*1024))
	d.DisallowUnknownFields()
	if d.Decode(&input) != nil {
		http.Error(w, "Invalid security request", 400)
		return input, false
	}
	return input, true
}

func (s *Server) handleAccountAuthentication(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}
	input, ok := securityInput(w, r)
	if !ok {
		return
	}
	var answer any
	var err error
	switch r.URL.Path {
	case "/auth/factor":
		answer, err = s.selectAccountFactor(input.Challenge, input.Method, input.PhoneLast4)
	case "/auth/webauthn/finish":
		answer, err = s.finishPasskeyLogin(input.Challenge, input.Credential)
	case "/auth/qr":
		answer, err = s.beginQRLogin(input.Challenge)
	case "/auth/qr/poll":
		answer, err = s.pollQRLogin(input.Challenge)
	default:
		err = apiErrorf(404, "Unknown authentication operation")
	}
	if err != nil {
		writeAPIError(w, err)
		return
	}
	securityJSON(w, answer)
}

func (s *Server) handleAccountSecurity(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFrom(r)
	if !ok {
		http.Error(w, "No session", 401)
		return
	}
	key := s.sessionKeyFromBearer(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	session, live := s.registeredSession(key)
	if !live || session.UserID != userID {
		http.Error(w, "Session expired", 401)
		return
	}
	if r.Method == "GET" && r.URL.Path == "/account/security" {
		s.accountSecurityView(w, userID, key)
		return
	}
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}
	input, ok := securityInput(w, r)
	if !ok {
		return
	}
	// Exceptions are route-specific. An operation label must not bypass the
	// guard on QR approval or passkey enrollment endpoints.
	if time.Now().Unix()-session.MFAAt > 300 && !s.isSecurityReauthentication(r.URL.Path, userID, key, input) {
		http.Error(w, "Verify a second factor again before changing security settings", 403)
		return
	}
	var answer any
	var err error
	switch r.URL.Path {
	case "/account/webauthn/begin":
		answer, err = s.beginSecurityFactor(userID, key, "webauthn_enroll", "")
	case "/account/webauthn/finish":
		answer, err = s.finishPasskeyEnrollment(userID, key, input.Challenge, input.Name, input.Credential)
	case "/account/qr/approve":
		answer, err = s.approveQRLogin(userID, input.Challenge, input.Code)
	case "/account/security":
		answer, err = s.accountSecurityCommand(userID, key, input)
	default:
		err = apiErrorf(404, "Unknown account operation")
	}
	if err != nil {
		writeAPIError(w, err)
		return
	}
	securityJSON(w, answer)
}

func (s *Server) accountSecurityView(w http.ResponseWriter, userID, key string) {
	s.readForest(func() {
		profile, err := s.forest.GetUserProfile(userID)
		if err != nil {
			http.Error(w, "Account unavailable", 401)
			return
		}
		account := s.forest.AccountSecurity[userID]
		devices := []map[string]any{}
		passkeys := []map[string]any{}
		for id, held := range s.forest.ApplicationSessions {
			if held.UserID == userID && applicationSessionDeadline(held) > time.Now().Unix() {
				devices = append(devices, map[string]any{"id": id, "name": held.DeviceName, "created_at": held.CreatedAt, "last_active_at": held.LastActiveAt, "expires_at": applicationSessionDeadline(held), "absolute_expires_at": min(held.ExpiresAt, held.CreatedAt+applicationSessionTTL), "current": id == key})
			}
		}
		sort.Slice(devices, func(i, j int) bool { return devices[i]["created_at"].(int64) > devices[j]["created_at"].(int64) })
		for _, passkey := range account.Passkeys {
			passkeys = append(passkeys, map[string]any{"id": passkey.ID, "name": passkey.Label, "created_at": passkey.CreatedAt})
		}
		securityJSON(w, map[string]any{"mfa_required": requireAccountMFA(), "methods": securityMethods(account, profile), "sessions": devices, "passkeys": passkeys, "recovery_codes_remaining": len(account.RecoveryHashes), "recovery_contacts": account.RecoveryContacts, "email": account.VerifiedEmail})
	})
}

func (s *Server) beginSecurityFactor(userID, key, method, target string) (map[string]any, error) {
	var user *core.User
	s.readForest(func() {
		p, e := s.forest.GetUserProfile(userID)
		if e == nil {
			copy := *p
			user = &copy
		}
	})
	if user == nil {
		return nil, apiErrorf(401, "Account unavailable")
	}
	switch method {
	case "totp_enroll", "webauthn_enroll":
	case "email_enroll":
		if os.Getenv("MOMENTUM_EMAIL_ENABLED") != "true" {
			return nil, apiErrorf(503, "Email verification is not configured")
		}
		address, err := mail.ParseAddress(target)
		if err != nil || address.Address != target || len(target) > 254 {
			return nil, apiErrorf(400, "Enter a valid email address")
		}
	case "sms_enroll":
		digits := digitsOnly(target)
		if len(digits) < 8 || len(digits) > 15 || !strings.HasPrefix(target, "+") {
			return nil, apiErrorf(400, "Enter a phone number with country code")
		}
		target = "+" + digits
	default:
		return nil, apiErrorf(400, "Unknown enrollment method")
	}
	return s.newAccountChallenge(user, method, target, key)
}

func (s *Server) accountSecurityCommand(userID, key string, input accountSecurityRequest) (any, error) {
	if input.Operation == "begin_factor" {
		return s.beginSecurityFactor(userID, key, input.Method, input.Target)
	}
	if input.Operation == "reauthenticate" {
		var user *core.User
		var target string
		allowed := false
		s.readForest(func() {
			p, e := s.forest.GetUserProfile(userID)
			if e != nil {
				return
			}
			copy := *p
			user = &copy
			account := s.forest.AccountSecurity[userID]
			for _, m := range securityMethods(account, p) {
				if m == input.Method {
					allowed = true
				}
			}
			if input.Method == "email" {
				target = account.VerifiedEmail
			}
			if input.Method == "sms" {
				target = p.Phone
			}
		})
		if !allowed {
			return nil, apiErrorf(400, "Factor is not enrolled")
		}
		return s.newAccountChallenge(user, input.Method, target, key)
	}
	if input.Operation == "verify_factor" {
		user, err := s.consumeAccountChallenge(input.Challenge, input.Code, key)
		if err != nil {
			return nil, err
		}
		if user.ID != userID {
			return nil, apiErrorf(401, "Wrong account")
		}
		return map[string]any{"verified": true}, nil
	}
	answer := map[string]any{"updated": true}
	err := s.changeForest(func() error {
		if s.forest.AccountSecurity == nil {
			s.forest.AccountSecurity = map[string]core.AccountSecurity{}
		}
		account := s.forest.AccountSecurity[userID]
		switch input.Operation {
		case "revoke_session":
			held, ok := s.forest.ApplicationSessions[input.SessionID]
			if !ok || held.UserID != userID {
				return apiErrorf(404, "Session unavailable")
			}
			delete(s.forest.ApplicationSessions, input.SessionID)
		case "rename_session":
			held, ok := s.forest.ApplicationSessions[input.SessionID]
			if !ok || held.UserID != userID {
				return apiErrorf(404, "Session unavailable")
			}
			name := strings.TrimSpace(input.Name)
			if len(name) < 1 || len(name) > 100 {
				return apiErrorf(400, "Device name must be 1–100 characters")
			}
			held.DeviceName = name
			s.forest.ApplicationSessions[input.SessionID] = held
		case "recovery_codes":
			codes := []string{}
			account.RecoveryHashes = nil
			for i := 0; i < 10; i++ {
				raw, err := newChallengeID()
				if err != nil {
					return err
				}
				code := strings.ToUpper(raw[:24])
				codes = append(codes, code)
				account.RecoveryHashes = append(account.RecoveryHashes, s.mfaCodeHash(code))
			}
			answer["recovery_codes"] = codes
		case "recovery_contacts":
			if len(input.Contacts) > 5 {
				return apiErrorf(400, "At most five recovery contacts")
			}
			for _, contact := range input.Contacts {
				address, err := mail.ParseAddress(contact)
				if err != nil || address.Address != contact || len(contact) > 254 {
					return apiErrorf(400, "Enter valid recovery email addresses")
				}
			}
			account.RecoveryContacts = input.Contacts
		case "remove_factor":
			switch input.Method {
			case "totp":
				account.TOTPSecret = ""
			case "email":
				account.VerifiedEmail = ""
			case "webauthn":
				kept := []core.AccountPasskey{}
				for _, p := range account.Passkeys {
					if p.ID != input.Target {
						kept = append(kept, p)
					}
				}
				account.Passkeys = kept
			case "sms":
			default:
				return apiErrorf(400, "Unknown factor")
			}
			profile, err := s.forest.GetUserProfile(userID)
			if err != nil {
				return err
			}
			copy := *profile
			if input.Method == "sms" {
				copy.MFAEnabled = false
			}
			methods := securityMethods(account, &copy)
			strong := 0
			for _, m := range methods {
				if m != "recovery" {
					strong++
				}
			}
			if strong == 0 {
				return apiErrorf(409, "Enroll another factor before removing this one")
			}
			if input.Method == "sms" {
				for i := range s.forest.Users {
					if s.forest.Users[i].ID == userID {
						s.forest.Users[i].MFAEnabled = false
					}
				}
			}
			// Removing a factor retires all other devices and challenges.
			for i := range s.forest.Users {
				if s.forest.Users[i].ID == userID {
					s.forest.Users[i].CredentialEpoch++
					held := s.forest.ApplicationSessions[key]
					held.CredentialEpoch = s.forest.Users[i].CredentialEpoch
					s.forest.ApplicationSessions[key] = held
				}
			}
		default:
			return apiErrorf(400, "Unknown security operation")
		}
		s.forest.AccountSecurity[userID] = account
		return nil
	})
	return answer, err
}
