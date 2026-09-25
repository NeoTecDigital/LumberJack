// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"testing"
	"time"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

// A channel barrier separates the real registry read from the real renewal
// operation used by the handler. No scheduler delay or production test hook is
// needed: the invalidation transaction completes before renewal can acquire its
// write lock.
// Before the shared predicate fix, the first five cases failed with:
// "invalidated activity returned <nil>; expected 401",
// "invalidated activity returned a session descriptor", and
// "invalidated activity advanced LastActiveAt" (FAIL, 0.534s).
func TestActivityRechecksAccountInsideRenewalTransaction(t *testing.T) {
	t.Setenv("MOMENTUM_REQUIRE_MFA", "true")
	cases := []string{"account locked", "administrator MFA epoch changed", "last factor removed", "account deleted", "MFA stamp removed", "idle expired", "absolute expired"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			s, _ := newStockServer(t)
			user := addPasswordUser(t, s, "active-account", "fixture-password")
			if err := s.changeForest(func() error {
				s.forest.AccountSecurity = map[string]core.AccountSecurity{user.ID: {TOTPSecret: "JBSWY3DPEHPK3PXP"}}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			token, _, err := s.mintApplicationSession(user.ID)
			if err != nil {
				t.Fatal(err)
			}
			key := s.sessionHash(token)
			if err := s.changeForest(func() error {
				held := s.forest.ApplicationSessions[key]
				held.LastActiveAt = time.Now().Unix() - 300
				s.forest.ApplicationSessions[key] = held
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			validated := make(chan bool, 1)
			resume := make(chan struct{})
			type result struct {
				session core.ApplicationSession
				err     error
			}
			answer := make(chan result, 1)
			go func() {
				_, valid := s.applicationSession(token)
				validated <- valid
				<-resume
				session, err := s.renewApplicationSession(key)
				answer <- result{session, err}
			}()
			if !<-validated {
				close(resume)
				t.Fatal("fixture session was invalid before the barrier")
			}
			if err := s.changeForest(func() error {
				for index := range s.forest.Users {
					if s.forest.Users[index].ID == user.ID {
						switch name {
						case "account locked":
							s.forest.Users[index].LockedUntil = time.Now().Add(time.Hour).Unix()
						case "administrator MFA epoch changed":
							s.forest.Users[index].CredentialEpoch++
						case "account deleted":
							s.forest.Users = append(s.forest.Users[:index], s.forest.Users[index+1:]...)
						}
						break
					}
				}
				if name == "last factor removed" {
					delete(s.forest.AccountSecurity, user.ID)
				}
				held := s.forest.ApplicationSessions[key]
				switch name {
				case "MFA stamp removed":
					held.MFAAt = 0
				case "idle expired":
					held.LastActiveAt = time.Now().Unix() - applicationSessionIdleTTL - 1
				case "absolute expired":
					held.CreatedAt = time.Now().Unix() - applicationSessionTTL - 1
				}
				s.forest.ApplicationSessions[key] = held
				return nil
			}); err != nil {
				close(resume)
				t.Fatal(err)
			}
			var before int64
			s.readForest(func() { before = s.forest.ApplicationSessions[key].LastActiveAt })
			close(resume)
			got := <-answer
			var refusal *apiError
			if !asAPIError(got.err, &refusal) || refusal.status != 401 {
				t.Errorf("invalidated activity returned %v; expected 401", got.err)
			}
			if got.session != (core.ApplicationSession{}) {
				t.Error("invalidated activity returned a session descriptor")
			}
			s.readForest(func() {
				if s.forest.ApplicationSessions[key].LastActiveAt != before {
					t.Error("invalidated activity advanced LastActiveAt")
				}
			})
		})
	}
}
