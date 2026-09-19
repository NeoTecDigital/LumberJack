// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"github.com/NeoTecDigital/LumberJack/internal/core"
)

// WHEN THE RULES FOR AN ACCOUNT CHANGE, WHAT WAS ISSUED UNDER THE OLD ONES HAS TO STOP.
//
// Turning a second factor on was not retroactive. The front door was shut correctly — a password
// alone answers a challenge at /login and a challenge at /session, and cannot get a fresh credential
// for an enrolled account — but everything minted BEFORE the enrolment kept working: the browser's
// ms_ cookie, the hour-long JWT session, and the seven-day refresh token, which went on minting
// brand new sessions for nothing but its own signature. An administrator who enrolled an account
// BECAUSE its password had been spent had shut a door the attacker was no longer using.
//
// The same is true of re-pointing the number, which is what an administrator does when the handset
// is gone: a code already in flight to the old handset still completed the login for the rest of its
// five minutes.
//
// ONE RULE, NOT A LIST OF EVICTIONS. Every credential this engine mints — session, refresh,
// mfa_pending challenge, ms_ application session — carries the epoch its account was on when it was
// minted, and is honoured only while that epoch is still current. Raising the account's epoch
// therefore retires all four at once, including the ones minted by a path nobody remembered to add
// to a sweep, and including the kind that cannot be swept at all: a JWT is not stored anywhere, so
// there is nothing to delete and a comparison is the only mechanism available. Applying the same
// comparison to the two kinds that ARE stored is what keeps one rule instead of two.
//
// WHAT IT COSTS. The stored credentials already read the account's profile on every request, to
// confirm it still exists, so their check is one integer comparison on a value that is already in
// hand. The JWT path did no forest read at all and now takes the read hold once per request; that is
// the price of revoking a bearer that carries its own authority, and the alternative — a token that
// cannot be withdrawn until it expires — is the defect.
//
// WHAT IT DOES NOT DO. It does not make the refusals distinguishable. Every site below answers with
// the sentence it already answered a bad credential with, so nothing on the wire announces that an
// account's rules changed, and no route became an oracle by gaining this check.

// epochIsCurrent reports whether a credential minted under mintedUnder is still honoured by an
// account now on current.
//
// The comparison is >=, NOT ==. A credential minted under a LATER epoch than the account carries can
// only come from a forest restored behind its own credentials, and refusing those would sign out
// everybody a restore was meant to keep; admitting them is the direction that fails safe for the
// people who did nothing wrong. Every credential the engine mints reads the epoch under the same
// hold that mints it, so nothing in normal operation can be ahead.
func epochIsCurrent(mintedUnder, current int64) bool {
	return mintedUnder >= current
}

// credentialEpochLocked reads the epoch an account's credentials must currently carry, and whether
// there is still an account to read it from.
//
// IT TAKES NO HOLD, and it must not: its callers are already inside one. forest_lock.go's rule is
// that only the handlers take the forest — a second RLock underneath a first deadlocks the moment a
// writer is waiting between them — so the hold belongs to the caller and this is the body it runs.
func (server *Server) credentialEpochLocked(userID string) (int64, bool) {
	profile, err := server.forest.GetUserProfile(userID)
	if err != nil {
		return 0, false
	}
	return profile.CredentialEpoch, true
}

// credentialIsCurrent answers, with the forest held for reading, whether a bearer minted under
// mintedUnder is one this server will still act on for userID.
//
// A MISSING ACCOUNT IS NOT CURRENT. An account that is gone has no epoch, so there is nothing for
// the bearer to still match, and admitting it would mean the one credential whose authority is
// entirely in its own signature is also the one nothing can withdraw.
func (server *Server) credentialIsCurrent(userID string, mintedUnder int64) bool {
	current := int64(0)
	known := false
	server.readForest(func() {
		current, known = server.credentialEpochLocked(userID)
	})
	return known && epochIsCurrent(mintedUnder, current)
}

// retireCredentialsLocked moves an account to a new epoch, which retires every credential minted
// under the old one. It is called INSIDE the exclusive hold, on the forest's own copy of the user,
// so the retirement and the change that justified it are one durable snapshot: a crash between them
// cannot leave the account on the new rules with the old rules' sessions still live.
//
// IT IS DELIBERATELY NOT CALLED ON EVERY WRITE to a user. Signing everyone out is the right answer
// to "what it takes to be this account has changed" and the wrong answer to "an administrator opened
// the console and pressed save", so the caller decides what counts as a change, and states why.
func retireCredentialsLocked(user *core.User) {
	user.CredentialEpoch++
}
