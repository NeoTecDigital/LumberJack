package internal

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

// ENROLMENT IS ADMINISTRATIVE. Nothing self-serves a second factor here: an account's phone and its
// MFA flag are set by someone already holding AdminPermission, through POST /users/mfa, exactly as
// widening the set of people who can read the forest is. Self-enrolment would let anyone who reached
// a stolen session point the codes at their own phone.
//
// These cases go through the ROUTER, because "behind the session guard" and "refused without
// authority" are facts about the routing table and the guard, not about the handler's body.

// addPlainUser plants an ordinary account with no phone and no second factor — the state an
// enrolment starts from.
func addPlainUser(t *testing.T, server *Server, username string) core.User {
	t.Helper()
	user := core.User{ID: core.GenerateUserID(), Username: username}
	if err := server.changeForest(func() error {
		return server.forest.AssignUser(user, core.ReadPermission)
	}); err != nil {
		t.Fatalf("AssignUser: %v", err)
	}
	return user
}

// storedUser reads an account back out of the forest under the read hold.
func storedUser(t *testing.T, server *Server, userID string) core.User {
	t.Helper()
	var found *core.User
	server.readForest(func() {
		for i := range server.forest.Users {
			if server.forest.Users[i].ID == userID {
				copied := server.forest.Users[i]
				found = &copied
				return
			}
		}
	})
	if found == nil {
		t.Fatalf("the forest no longer carries user %s", userID)
	}
	return *found
}

// TestSetUserMfaIsAdministrative: no session is 401, a session without AdminPermission is 403, and
// neither one changes the account.
//
// OBSERVED RED (before the route existed,
// `go test ./internal -run TestSetUserMfa -count=1`):
//
//	--- FAIL: TestSetUserMfaIsAdministrative (0.04s)
//	    api_user_mfa_test.go:71: anonymous POST /users/mfa: got 404, want 401: 404 page not found
//	    api_user_mfa_test.go:77: reader POST /users/mfa: got 404, want 403: 404 page not found
func TestSetUserMfaIsAdministrative(t *testing.T) {
	server, _ := newStockServer(t)
	target := addPlainUser(t, server, "enrollee")
	readerID := addReadUser(t, server, "reader")

	body := map[string]interface{}{"username": target.Username, "phone": "+1 (555) 867-5309", "mfa_enabled": true}

	anonymous := serve(t, server, jsonRequest(t, "POST", "/users/mfa", body))
	if anonymous.Code != http.StatusUnauthorized {
		t.Errorf("anonymous POST /users/mfa: got %d, want %d: %s", anonymous.Code, http.StatusUnauthorized, anonymous.Body.String())
	}

	asReader := jsonRequest(t, "POST", "/users/mfa", body)
	asReader.Header.Set("Authorization", "Bearer "+sessionFor(t, server, readerID, "reader"))
	if recorder := serve(t, server, asReader); recorder.Code != http.StatusForbidden {
		t.Errorf("reader POST /users/mfa: got %d, want %d: %s", recorder.Code, http.StatusForbidden, recorder.Body.String())
	}

	after := storedUser(t, server, target.ID)
	if after.MFAEnabled || after.Phone != "" {
		t.Errorf("a refused enrolment still wrote to the account: mfa=%v phone=%q", after.MFAEnabled, after.Phone)
	}
}

// TestSetUserMfaEnrolsAndNormalisesThePhone is the enrolment itself. The number is stored DIGITS
// ONLY, so the ownership gate — which compares digits — cannot be defeated or broken by how the
// number happened to be typed, and two enrolments of the same line cannot disagree.
//
// OBSERVED RED (before the route existed, same run):
//
//	--- FAIL: TestSetUserMfaEnrolsAndNormalisesThePhone (0.04s)
//	    api_user_mfa_test.go:106: admin POST /users/mfa: got 404, want 200: 404 page not found
func TestSetUserMfaEnrolsAndNormalisesThePhone(t *testing.T) {
	server, _ := newStockServer(t)
	admin := adminID(t, server)
	target := addPlainUser(t, server, "enrollee")

	request := jsonRequest(t, "POST", "/users/mfa", map[string]interface{}{
		"username": target.Username, "phone": "+1 (555) 867-5309", "mfa_enabled": true,
	})
	request.Header.Set("Authorization", "Bearer "+sessionFor(t, server, admin, "admin"))
	recorder := serve(t, server, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("admin POST /users/mfa: got %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}

	after := storedUser(t, server, target.ID)
	if after.Phone != "15558675309" {
		t.Errorf("the phone was stored as %q, want the digits %q", after.Phone, "15558675309")
	}
	if !after.MFAEnabled {
		t.Errorf("the account was not enrolled")
	}
	if !phoneLast4Matches(after.Phone, "5309") {
		t.Errorf("the stored number does not satisfy the ownership gate it exists for")
	}

	var answer map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &answer); err != nil {
		t.Fatalf("the answer was not JSON: %q", recorder.Body.String())
	}
	if answer["mfa_enabled"] != true || answer["phone"] != "15558675309" || answer["username"] != target.Username {
		t.Errorf("the answer did not carry the updated profile: %v", answer)
	}
	// The projection rule of api_views.go, on the route most likely to break it: an administrative
	// answer about an account must still not carry that account's credential.
	body := recorder.Body.String()
	if strings.Contains(body, `"password"`) || strings.Contains(body, "$2a$") || strings.Contains(body, "$2b$") {
		t.Errorf("POST /users/mfa answered with the account's credential: %s", body)
	}
}

// TestSetUserMfaRefusesEnablingWithoutAUsableNumber. A second factor pointed at a number the gate
// cannot read is a second factor nobody can pass: phoneLast4Matches refuses a phone of fewer than
// four digits, so enabling against one would lock the account out at the next login. Refuse at
// enrolment, where someone is there to fix it, and write NOTHING.
//
// OBSERVED RED (before the route existed, same run):
//
//	--- FAIL: TestSetUserMfaRefusesEnablingWithoutAUsableNumber (0.04s)
//	    api_user_mfa_test.go:156: enabling MFA against "12": got 404, want 400: 404 page not found
//	    api_user_mfa_test.go:156: enabling MFA against "": got 404, want 400: 404 page not found
//	    api_user_mfa_test.go:156: enabling MFA against "no-digits-here": got 404, want 400: 404 page not found
func TestSetUserMfaRefusesEnablingWithoutAUsableNumber(t *testing.T) {
	server, _ := newStockServer(t)
	adminToken := "Bearer " + sessionFor(t, server, adminID(t, server), "admin")
	target := addPlainUser(t, server, "enrollee")

	for _, phone := range []string{"12", "", "no-digits-here"} {
		request := jsonRequest(t, "POST", "/users/mfa", map[string]interface{}{
			"username": target.Username, "phone": phone, "mfa_enabled": true,
		})
		request.Header.Set("Authorization", adminToken)
		if recorder := serve(t, server, request); recorder.Code != http.StatusBadRequest {
			t.Errorf("enabling MFA against %q: got %d, want %d: %s", phone, recorder.Code, http.StatusBadRequest, recorder.Body.String())
		}
		if after := storedUser(t, server, target.ID); after.MFAEnabled || after.Phone != "" {
			t.Errorf("a refused enrolment against %q still wrote: mfa=%v phone=%q", phone, after.MFAEnabled, after.Phone)
		}
	}
}

// TestSetUserMfaTurnsItOffWithoutResendingTheNumber. Disabling is the un-lockout path, and it must
// not require the number to be retyped — a request carrying no phone leaves the stored one alone.
//
// OBSERVED RED (before the route existed, same run):
//
//	--- FAIL: TestSetUserMfaTurnsItOffWithoutResendingTheNumber (0.04s)
//	    api_user_mfa_test.go:182: enrol: got 404, want 200: 404 page not found
func TestSetUserMfaTurnsItOffWithoutResendingTheNumber(t *testing.T) {
	server, _ := newStockServer(t)
	adminToken := "Bearer " + sessionFor(t, server, adminID(t, server), "admin")
	target := addPlainUser(t, server, "enrollee")

	enrol := jsonRequest(t, "POST", "/users/mfa", map[string]interface{}{
		"user_id": target.ID, "phone": "555-867-5309", "mfa_enabled": true,
	})
	enrol.Header.Set("Authorization", adminToken)
	if recorder := serve(t, server, enrol); recorder.Code != http.StatusOK {
		t.Fatalf("enrol: got %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}

	off := jsonRequest(t, "POST", "/users/mfa", map[string]interface{}{"user_id": target.ID, "mfa_enabled": false})
	off.Header.Set("Authorization", adminToken)
	if recorder := serve(t, server, off); recorder.Code != http.StatusOK {
		t.Fatalf("disable: got %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	after := storedUser(t, server, target.ID)
	if after.MFAEnabled {
		t.Errorf("the account is still enrolled")
	}
	if after.Phone != "5558675309" {
		t.Errorf("disabling MFA rewrote the phone to %q", after.Phone)
	}
}

// TestSetUserMfaRefusesAnAccountThatIsNotThere: an id or a name nobody holds is 404, not a silent
// success an administrator would read as "enrolled".
//
// OBSERVED RED (before the route existed, same run):
//
//	--- FAIL: TestSetUserMfaRefusesAnAccountThatIsNotThere (0.04s)
//	    api_user_mfa_test.go:214: POST /users/mfa for an unknown account: got 404 "404 page not found\n" — want the handler's 404, not the router's
func TestSetUserMfaRefusesAnAccountThatIsNotThere(t *testing.T) {
	server, _ := newStockServer(t)

	request := jsonRequest(t, "POST", "/users/mfa", map[string]interface{}{"username": "nobody", "mfa_enabled": false})
	request.Header.Set("Authorization", "Bearer "+sessionFor(t, server, adminID(t, server), "admin"))
	recorder := serve(t, server, request)
	if recorder.Code != http.StatusNotFound || strings.Contains(recorder.Body.String(), "page not found") {
		t.Errorf("POST /users/mfa for an unknown account: got %d %q — want the handler's 404, not the router's",
			recorder.Code, recorder.Body.String())
	}
}

// TestUserProfileCarriesMFAState. The client has to know whether the account it is signed into
// carries a second factor to render its settings, and the flag is not a secret — unlike everything
// else the second factor touches. GET /users/profile carries it.
//
// OBSERVED RED (before the projection carried it, same run):
//
//	--- FAIL: TestUserProfileCarriesMFAState (0.08s)
//	    api_user_mfa_test.go:241: GET /users/profile carries no mfa_enabled: map[email: organization: permissions:[0] phone:+1 (555) 867-5309 username:mfa-user]
func TestUserProfileCarriesMFAState(t *testing.T) {
	server, _ := newStockServer(t)
	user := addMFAUser(t, server)

	recorder := get(t, server.handleGetUserProfile, user.ID, "/users/profile")
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET /users/profile: got %d: %s", recorder.Code, recorder.Body.String())
	}
	var profile map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &profile); err != nil {
		t.Fatalf("the profile was not JSON: %q", recorder.Body.String())
	}
	if profile["mfa_enabled"] != true {
		t.Errorf("GET /users/profile carries no mfa_enabled: %v", profile)
	}
}
