package internal

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"sync"
	"time"

	"github.com/NeoTecDigital/LumberJack/internal/core"
	"golang.org/x/crypto/bcrypt"
)

// ONE credential check, behind BOTH doors.
//
// /login and /session each read a username and a password, and each used to decide for itself what
// that meant. Two implementations of one security decision is two places the weaker one is the real
// one: whatever /login counted, /session did not, and an attacker picks the door. So the decision
// lives here, once, and both handlers call it.
//
// What it enforces, in order: the account is not shut; the password verifies; the ownership gate
// passes when the account carries a second factor. Every refusal is the SAME error — a caller learns
// only that the credential did not work, never which half of it failed, whether the account exists,
// whether it is locked, or whether it has a second factor.

// errInvalidCredentials is that single refusal. It is a function rather than a package variable so
// that a caller cannot mutate the shared value out from under every other caller.
func errInvalidCredentials() *apiError {
	return apiErrorf(http.StatusUnauthorized, "Invalid credentials")
}

var (
	dummyCompareOnce sync.Once
	dummyCompareHash []byte
)

// spendAPasswordCompare burns one bcrypt verification against a hash of a value nobody holds.
//
// THE SIDE CHANNEL IT CLOSES. A login for an account that does not exist used to return immediately,
// while a login for one that does spent a bcrypt compare — tens of milliseconds. The bodies were
// identical and the clock was not, so the uniform "Invalid credentials" leaked the entire user list
// to anyone willing to time it. The same applies to a LOCKED account, which would otherwise be the
// fast path and announce itself as locked.
//
// The hash is built once, at first use, from freshly drawn random bytes: there is no literal
// credential in this source and nothing to leak, and the cost is one hash per process.
func spendAPasswordCompare(password string) {
	dummyCompareOnce.Do(func() {
		filler := make([]byte, 32)
		if _, err := rand.Read(filler); err != nil {
			return
		}
		hashed, err := bcrypt.GenerateFromPassword([]byte(hex.EncodeToString(filler)), bcrypt.DefaultCost)
		if err != nil {
			return
		}
		dummyCompareHash = hashed
	})
	if len(dummyCompareHash) == 0 {
		return
	}
	_ = bcrypt.CompareHashAndPassword(dummyCompareHash, []byte(password))
}

// authenticateCredential is the whole check. It returns the account on success and errInvalidCredentials
// on every failure; the caller decides what a verified credential earns — a token pair at /login, an
// application session at /session, or a second-factor challenge at either.
func (server *Server) authenticateCredential(username, password, phoneLast4 string) (*core.User, error) {
	user := server.findUserByName(username)
	if user == nil {
		spendAPasswordCompare(password)
		return nil, errInvalidCredentials()
	}

	now := time.Now().Unix()
	if user.LockedUntil > now {
		// Locked accounts pay the same compare, so the lockout does not announce itself by answering
		// faster than an open account does.
		spendAPasswordCompare(password)
		return nil, errInvalidCredentials()
	}
	if user.LockedUntil != 0 {
		// The window has closed. Clear the spent budget BEFORE this attempt is judged, or the first
		// mistype after a lockout expires re-locks the account instantly — a fifteen-minute penalty
		// that renews forever on a user who is simply bad at typing.
		server.clearLoginFailures(user.ID)
	}

	if !user.VerifyPassword(password) {
		server.recordLoginFailure(user.ID)
		return nil, errInvalidCredentials()
	}

	// The ownership gate counts too. It is a guess against a four-digit space, which is a far smaller
	// space than the password — so leaving it uncounted would make it the cheapest thing to attack on
	// the account, and the one that triggers an SMS on success.
	if user.MFAEnabled && !phoneLast4Matches(user.Phone, phoneLast4) {
		server.recordLoginFailure(user.ID)
		return nil, errInvalidCredentials()
	}

	server.clearLoginFailures(user.ID)
	return user, nil
}

// recordLoginFailure counts one miss on the account and shuts it at the limit.
//
// The write is durable because the counter is only worth anything if a restart does not clear it.
// A failure to persist is logged and NOT answered to the caller: the refusal stands either way, and
// telling a guesser that its miss was not recorded is exactly the wrong thing to say.
func (server *Server) recordLoginFailure(userID string) {
	if err := server.changeForest(func() error {
		for i := range server.forest.Users {
			if server.forest.Users[i].ID != userID {
				continue
			}
			server.forest.Users[i].FailedLogins++
			if server.forest.Users[i].FailedLogins >= loginFailureLimit {
				server.forest.Users[i].LockedUntil = time.Now().Add(loginLockout).Unix()
			}
			return nil
		}
		return nil
	}); err != nil {
		server.logger.Failure("Failed to record a credential refusal: %v", err)
	}
}

// clearLoginFailures reopens the account, and is the reason the budget is CONSECUTIVE misses.
//
// It reads first and writes only when something would change. A successful login is the common case,
// and changeForest serializes and flushes the WHOLE forest — so writing an unchanged zero on every
// sign-in would make a login cost a full state persist for nothing.
func (server *Server) clearLoginFailures(userID string) {
	stale := false
	server.readForest(func() {
		for i := range server.forest.Users {
			if server.forest.Users[i].ID == userID {
				stale = server.forest.Users[i].FailedLogins != 0 || server.forest.Users[i].LockedUntil != 0
				return
			}
		}
	})
	if !stale {
		return
	}
	if err := server.changeForest(func() error {
		for i := range server.forest.Users {
			if server.forest.Users[i].ID != userID {
				continue
			}
			server.forest.Users[i].FailedLogins = 0
			server.forest.Users[i].LockedUntil = 0
			return nil
		}
		return nil
	}); err != nil {
		server.logger.Failure("Failed to clear a credential counter: %v", err)
	}
}

// principalIsUsable reports whether an account still exists and is not shut. It is what a bearer that
// was issued EARLIER has to be re-checked against, because a signature proves only who signed it and
// when — not that the account it names is still one the server will act for.
func (server *Server) principalIsUsable(userID string) bool {
	usable := false
	server.readForest(func() {
		profile, err := server.forest.GetUserProfile(userID)
		usable = err == nil && profile.LockedUntil <= time.Now().Unix()
	})
	return usable
}
