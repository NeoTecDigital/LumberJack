// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/NeoTecDigital/LumberJack/internal/admission"
	"github.com/NeoTecDigital/LumberJack/internal/core"
)

// The profile an admission carries: the digest binds it, and it is what the account is called.

func TestSessionAdmitRefusesAUsernameThatBelongsToAnotherPrincipal(t *testing.T) {
	f := newAdmitFixture(t)
	f.admitAs(admitOwner, ownerProfile)
	before := f.sessionCount()
	for name, profile := range map[string]sessionProfile{
		"the same name":        ownerProfile,
		"the name in capitals": {Username: strings.ToUpper(admitName), Email: "other@example.test"},
		"the operator's name":  {Username: "admin", Email: "other@example.test"},
	} {
		got := f.post(f.signed("bootstrap-journey-other", profile))
		if got.Status != 409 || !strings.Contains(string(got.Body), "belongs to another account") {
			t.Errorf("%s: answered %d %q", name, got.Status, got.Body)
		}
	}
	var created error
	f.server.readForest(func() { _, created = f.server.forest.GetUserProfile("bootstrap-journey-other") })
	if created == nil {
		t.Fatalf("a refused name created an account")
	}
	if f.sessionCount() != before {
		t.Fatalf("a refused name minted a session")
	}
	token, body := f.admitAs("bootstrap-journey-other", sessionProfile{Username: "other@example.test", Email: "other@example.test"})
	if body["username"] != "other@example.test" || f.call("GET", "/principal", token).Status != 200 {
		t.Fatalf("the account could not be admitted under its own name: %v", body)
	}
	if got := f.post(f.signed("bootstrap-journey-other", ownerProfile)); got.Status != 409 {
		t.Fatalf("a later admission took somebody's name: %d %q", got.Status, got.Body)
	}
	var user *core.User
	f.server.readForest(func() { user, _ = f.server.forest.GetUserProfile("bootstrap-journey-other") })
	if user.Username != "other@example.test" || user.Email != "other@example.test" {
		t.Fatalf("a refused name changed the account: %+v", user)
	}
}

func TestSessionAdmitRefusesATamperedProfile(t *testing.T) {
	f := newAdmitFixture(t)
	users := f.userCount()
	claims := f.claims(admitOwner, ownerProfile)
	for name, profile := range map[string]string{
		"another name":  `{"email":"owner@example.test","username":"mallory"}`,
		"another email": `{"email":"mallory@example.test","username":"owner@example.test"}`,
		"whitespace":    `{"email": "owner@example.test","username":"owner@example.test"}`,
		"reordered":     `{"username":"owner@example.test","email":"owner@example.test"}`,
		"extra field":   `{"email":"owner@example.test","username":"owner@example.test","admin":true}`,
	} {
		if got := f.post(f.signedString(claims, []byte(profile), f.key)); got.Status != 401 {
			t.Errorf("%s: answered %d %q", name, got.Status, got.Body)
		}
	}
	envelope := f.signedString(claims, profileBytes(t, ownerProfile), f.key)
	for name, signed := range map[string]string{
		"no profile":      envelope[:strings.Index(envelope, `,"profile"`)] + `}`,
		"a null profile":  envelope[:strings.Index(envelope, `,"profile"`)] + `,"profile":null}`,
		"two profiles":    envelope[:len(envelope)-1] + `,"profile":{"email":"","username":"mallory"}}`,
		"an extra member": envelope[:len(envelope)-1] + `,"principal":"other"}`,
		"a bare envelope": envelope[len(`{"envelope":`):strings.Index(envelope, `,"profile"`)],
	} {
		if got := f.post(signed); got.Status != 401 {
			t.Errorf("%s: answered %d %q", name, got.Status, got.Body)
		}
	}
	if f.userCount() != users || f.sessionCount() != 0 {
		t.Fatalf("a refused profile left state behind")
	}
}

func TestSessionAdmitRefusesAProfileTheEngineCouldNotUse(t *testing.T) {
	f := newAdmitFixture(t)
	users := f.userCount()
	for name, profile := range map[string]sessionProfile{
		"the id as the name":       {Username: admitOwner, Email: admitName},
		"the id in capitals":       {Username: strings.ToUpper(admitOwner), Email: admitName},
		"no name":                  {Username: "", Email: admitName},
		"a padded name":            {Username: " owner", Email: admitName},
		"a name over the limit":    {Username: strings.Repeat("x", usernameMaxBytes+1), Email: admitName},
		"a control character":      {Username: "own\ner", Email: admitName},
		"an email that is not one": {Username: "owner", Email: "not-an-address"},
		"an email with a space":    {Username: "owner", Email: "own er@example.test"},
	} {
		if got := f.post(f.signed(admitOwner, profile)); got.Status != 401 {
			t.Errorf("%s: answered %d %q", name, got.Status, got.Body)
		}
	}
	if f.userCount() != users {
		t.Fatalf("an unusable profile created an account")
	}
	if _, body := f.admitAs(admitOwner, sessionProfile{Username: "no-email-here", Email: ""}); body["username"] != "no-email-here" {
		t.Fatalf("an identity with no email was refused: %v", body)
	}
}

func TestLaterAdmissionsFollowTheProfile(t *testing.T) {
	f := newAdmitFixture(t)
	first, _ := f.admitAs(admitOwner, ownerProfile)
	read := func() core.User {
		var user *core.User
		f.server.readForest(func() { user, _ = f.server.forest.GetUserProfile(admitOwner) })
		return *user
	}
	f.admitAs(admitOwner, sessionProfile{Username: admitName, Email: "moved@example.test"})
	if user := read(); user.Username != admitName || user.Email != "moved@example.test" {
		t.Fatalf("a changed email did not reach the profile: %+v", user)
	}
	_, renamed := f.admitAs(admitOwner, sessionProfile{Username: "moved@example.test", Email: "moved@example.test"})
	if user := read(); user.Username != "moved@example.test" || renamed["username"] != "moved@example.test" {
		t.Fatalf("a changed username did not reach the profile: %+v", user)
	}
	if got := f.call("GET", "/principal", first); got.Status != 200 {
		t.Fatalf("a change of name ended the session: %d", got.Status)
	}
	if got := f.post(f.signed(admitOwner, ownerProfile)); got.Status != 200 {
		t.Fatalf("the name it gave up could not be taken back: %d %q", got.Status, got.Body)
	}
	if user := read(); user.Password != "" || len(user.Permissions) != 1 {
		t.Fatalf("a change of name touched more than the name: %+v", user)
	}
}

// An account made before profiles existed was named after its id; its next admission fixes that.
func TestAnAccountNamedAfterItsIdGetsItsRealName(t *testing.T) {
	f := newAdmitFixture(t)
	if err := f.server.changeForest(func() error {
		return f.server.forest.AssignUser(core.User{ID: admitOwner, Username: admitOwner}, core.ReadPermission)
	}); err != nil {
		t.Fatal(err)
	}
	if _, body := f.admitAs(admitOwner, ownerProfile); body["username"] != admitName {
		t.Fatalf("the id is still the name: %v", body)
	}
}

func TestDelegatedAccountsAreFoundByTheirUsername(t *testing.T) {
	f := newAdmitFixture(t)
	first, _ := f.admitAs(admitOwner, ownerProfile)
	second, _ := f.admitAs("bootstrap-journey-second", sessionProfile{Username: "second@example.test", Email: "second@example.test"})
	send := func(token, target string, body map[string]interface{}) map[string]interface{} {
		t.Helper()
		raw, _ := json.Marshal(body)
		got := f.server.ApplicationCall(ApplicationRequest{Method: "POST", Target: target, Body: raw,
			Headers: map[string]string{"Authorization": "Bearer " + token, "Content-Type": "application/json"}})
		if got.Status != 200 {
			t.Fatalf("%s answered %d %q", target, got.Status, got.Body)
		}
		return decodeApplication(t, got)
	}
	var view struct {
		Nodes []struct {
			Path     string                 `json:"path"`
			Metadata map[string]interface{} `json:"metadata"`
		} `json:"nodes"`
	}
	read := func() {
		t.Helper()
		if err := json.Unmarshal(f.call("GET", "/workspace", first).Body, &view); err != nil || len(view.Nodes) == 0 {
			t.Fatalf("no workspace: %v", err)
		}
	}
	read()
	send(first, "/workspace/commands", map[string]interface{}{"command": "initialize", "path": view.Nodes[0].Path, "client_id": "home"})
	read()
	home := ""
	for _, node := range view.Nodes {
		if node.Metadata["personal_owner"] == admitOwner {
			home = node.Path
		}
	}
	item, _ := send(first, "/workspace/commands", map[string]interface{}{"command": "create", "path": home, "client_id": "item", "title": "Shared", "kind": "goal"})["path"].(string)
	share := map[string]interface{}{"action": "grant", "path": item, "username": "second@example.test", "permission": 0, "scope": "item"}
	preview := send(first, "/access/preview", share)
	people := string(mustJSON(t, preview["recipients"]))
	if !strings.Contains(people, `"username":"second@example.test"`) || strings.Contains(people, `"username":"bootstrap`) {
		t.Fatalf("the preview does not name the recipient: %s", people)
	}
	share["revision"] = preview["revision"]
	send(first, "/access/apply", share)
	if got := f.call("GET", "/nodes/"+item, second); got.Status != 200 {
		t.Fatalf("the recipient cannot read what was shared: %d %q", got.Status, got.Body)
	}
	made := send(first, "/conversations", map[string]interface{}{"kind": "dm", "usernames": []string{"second@example.test"}, "client_id": "chat"})
	if title, _ := made["title"].(string); !strings.Contains(title, admitName) || !strings.Contains(title, "second@example.test") || strings.Contains(title, "bootstrap-") {
		t.Fatalf("the conversation is not named after its people: %v", made)
	}
	if got := f.call("GET", "/conversations", second); !strings.Contains(string(got.Body), "second@example.test") {
		t.Fatalf("the invitation did not reach the second account: %d %q", got.Status, got.Body)
	}
	f.admitAs("bootstrap-journey-second", sessionProfile{Username: "renamed@example.test", Email: "renamed@example.test"})
	listed := string(f.call("GET", "/conversations", first).Body)
	if !strings.Contains(listed, "renamed@example.test") || strings.Contains(listed, "second@example.test") {
		t.Fatalf("a direct message still says the old name: %s", listed)
	}
}

func mustJSON(t *testing.T, value interface{}) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// The same vector the Python signer reproduces, opened the whole way: envelope, digest and profile.
func TestOpenSessionAdmissionReadsTheSharedVector(t *testing.T) {
	raw, err := os.ReadFile("admission/testdata/session_vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		KeyID     string            `json:"keyId"`
		Public    string            `json:"public"`
		Issuer    string            `json:"issuer"`
		Audience  string            `json:"audience"`
		Now       int64             `json:"now"`
		Profile   sessionProfile    `json:"profile"`
		Admission string            `json:"admission"`
		Refused   map[string]string `json:"refusedAdmissions"`
		Usernames struct {
			Accepted []string `json:"accepted"`
			Refused  []string `json:"refused"`
		} `json:"usernames"`
		Claims admission.Claims `json:"claims"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	verifier, err := newSessionAdmissionVerifier(SessionAdmissionConfig{KeyID: vector.KeyID, PublicKey: vector.Public, Issuer: vector.Issuer, Audience: vector.Audience})
	if err != nil {
		t.Fatal(err)
	}
	claims, profile, err := openSessionAdmission(verifier, []byte(vector.Admission), vector.Now)
	if err != nil {
		t.Fatalf("the shared admission was refused: %v", err)
	}
	if profile != vector.Profile || claims != vector.Claims {
		t.Fatalf("the admission opened differently: %+v %+v", profile, claims)
	}
	if len(vector.Refused) < 3 {
		t.Fatalf("the vector carries no refusals: %v", vector.Refused)
	}
	for name, refused := range vector.Refused {
		if _, _, err := openSessionAdmission(verifier, []byte(refused), vector.Now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for _, name := range vector.Usernames.Accepted {
		if !(sessionProfile{Username: name}).valid(vector.Claims.PrincipalID) {
			t.Errorf("the rule refused %q", name)
		}
	}
	for _, name := range vector.Usernames.Refused {
		if (sessionProfile{Username: name}).valid(vector.Claims.PrincipalID) {
			t.Errorf("the rule accepted %q", name)
		}
	}
}
