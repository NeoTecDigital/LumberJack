package internal

import (
	"encoding/json"
	"net/http"
	"strings"
)

// Enrolment: who carries a second factor, and at which number.
//
// IT IS ADMINISTRATIVE, and that is the whole design decision. There is no self-enrolment route and
// no "change my phone" route, because either one turns a stolen session into a permanent takeover:
// the holder points the codes at their own handset and the real owner is locked out of their own
// account by the mechanism meant to protect it. Setting the number is therefore the same kind of act
// as widening who may read the forest — handleAssignUser's kind — and wears the same guard.

// handleSetUserMfa is POST /users/mfa {user_id | username, phone, mfa_enabled}. It is registered
// BEHIND authMiddleware, and refuses a caller without AdminPermission.
func (server *Server) handleSetUserMfa(w http.ResponseWriter, r *http.Request) {
	server.logger.Enter("handleSetUserMfa")
	defer server.logger.Exit("handleSetUserMfa")

	if _, ok := server.requireAdmin(w, r); !ok {
		return
	}

	var request struct {
		UserID   string `json:"user_id"`
		Username string `json:"username"`
		// Phone is optional on PURPOSE: an absent phone leaves the stored one alone, so turning a
		// second factor off — the path someone reaches for when an account is stuck — does not require
		// retyping a number, and cannot silently blank one.
		Phone      string `json:"phone"`
		MFAEnabled bool   `json:"mfa_enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	if request.UserID == "" && strings.TrimSpace(request.Username) == "" {
		http.Error(w, "Name the account by user_id or username", http.StatusBadRequest)
		return
	}

	var view userView
	if err := server.changeForest(func() error {
		index := -1
		for i := range server.forest.Users {
			if request.UserID != "" {
				if server.forest.Users[i].ID == request.UserID {
					index = i
					break
				}
				continue
			}
			if server.forest.Users[i].Username == request.Username {
				index = i
				break
			}
		}
		if index < 0 {
			// The handler's own 404, not the router's: an administrator reading "page not found" would
			// reasonably conclude the ROUTE is missing rather than the account.
			return apiErrorf(http.StatusNotFound, "No such account")
		}

		// The number is stored as DIGITS, through the same filter the ownership gate reads with. The
		// gate compares digits, so storing the typed string would let two spellings of one line disagree
		// about whether the same four digits match — and a number normalised at enrolment is normalised
		// once, where a number normalised at every comparison is normalised on every code path forever.
		// The DIALLING format is the delivery adapter's business, not the store's.
		phone := server.forest.Users[index].Phone
		if request.Phone != "" {
			phone = digitsOnly(request.Phone)
		}
		// A second factor pointed at a number the gate cannot read is a factor nobody can pass:
		// phoneLast4Matches refuses a phone of fewer than four digits, so enabling against one would
		// lock the account out at its next login. Refuse here, where someone is present to fix it, and
		// BEFORE anything is written — nothing above this point has mutated the forest.
		if request.MFAEnabled && len(phone) < 4 {
			return apiErrorf(http.StatusBadRequest, "Enabling a second factor needs a phone of at least four digits")
		}

		// WHAT WAS ISSUED UNDER THE OLD RULES STOPS HERE, and this is the whole of where that is
		// decided. Turning a second factor ON was not retroactive: the browser cookie, the JWT session
		// and above all the seven-day refresh token all kept working, so enrolling an account because
		// its password had been spent shut a door the attacker had already walked through. Re-pointing
		// the NUMBER has the same shape — a code already travelling to the handset that was just taken
		// away still completed the login — which is why both count, not only the flag.
		//
		// ON A REAL CHANGE ONLY. An administrator who opens the console and saves the account it is
		// already showing has changed nothing and must not sign that user out; the comparison is
		// against the normalised phone, so two spellings of one line are the same line here exactly as
		// they are at the ownership gate.
		changed := server.forest.Users[index].Phone != phone ||
			server.forest.Users[index].MFAEnabled != request.MFAEnabled
		server.forest.Users[index].Phone = phone
		server.forest.Users[index].MFAEnabled = request.MFAEnabled
		if changed {
			retireCredentialsLocked(&server.forest.Users[index])
		}
		view = newUserView(server.forest.Users[index])
		return nil
	}); err != nil {
		writeAPIError(w, err)
		return
	}

	// The PROJECTION, not the stored user: core.User carries the bcrypt hash in a field tagged
	// `json:"password"`, and this is the one route that answers with a user an administrator named.
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(view)
	server.logger.Success("Second-factor enrolment updated")
}

// digitsOnly keeps the decimal digits of s and drops everything else — spaces, dashes, parentheses,
// a leading plus. It is the filter phoneLast4Matches compares with, lifted out so the store and the
// gate cannot disagree about what a number is.
func digitsOnly(s string) string {
	digits := make([]rune, 0, len(s))
	for _, r := range s {
		if r >= '0' && r <= '9' {
			digits = append(digits, r)
		}
	}
	return string(digits)
}
