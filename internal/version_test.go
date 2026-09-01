package internal

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
)

// The version the service reports, and the tag it is released under.
//
// THE DEFECT: three copies of one fact. /health read a constant in api_health.go, the CLI wrote a
// different literal into every config it created, and the release tag was maintained by hand in
// git. The engine answered 0.2.0-alpha while 0.3.0-alpha was being tagged — so the only version an
// operator can ask the running service for was the PREVIOUS release's, and the tag asserted
// something nothing could check.

// tagDisagreement reports why a declared version and the tags on a commit are inconsistent, or "".
//
// It is a pure function so the rule can be tested against tag lists that do not exist yet: the case
// that matters is a tag being cut while the constant still says the last release, and waiting for
// that to happen for real is not a test.
func tagDisagreement(version string, tags []string) string {
	if version == "" {
		return "the build declares no version at all"
	}
	if strings.HasPrefix(version, "v") {
		return "the declared version " + version + " carries a leading v; the tag carries it, the constant does not"
	}
	if len(tags) == 0 {
		return ""
	}
	want := "v" + version
	for _, tag := range tags {
		if tag == want {
			return ""
		}
	}
	return "this commit is tagged " + strings.Join(tags, ", ") + " and the build declares " + version +
		", which would be released as " + want
}

// The rule itself, against tag lists chosen to include the disagreement that prompted it.
func TestTagDisagreementNamesTheMismatch(t *testing.T) {
	cases := []struct {
		name    string
		version string
		tags    []string
		agrees  bool
	}{
		{"untagged commit", "0.3.0-alpha", nil, true},
		{"the tag it is released under", "0.3.0-alpha", []string{"v0.3.0-alpha"}, true},
		{"one of several tags", "0.3.0-alpha", []string{"latest", "v0.3.0-alpha"}, true},
		{"the release being cut while the constant is stale", "0.2.0-alpha", []string{"v0.3.0-alpha"}, false},
		{"a tag behind the constant", "0.3.0-alpha", []string{"v0.2.0-alpha"}, false},
		{"a near miss", "0.3.0-alpha", []string{"v0.3.0"}, false},
		{"no version at all", "", []string{"v0.3.0-alpha"}, false},
		{"the v belongs to the tag", "v0.3.0-alpha", []string{"v0.3.0-alpha"}, false},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			complaint := tagDisagreement(testCase.version, testCase.tags)
			if testCase.agrees && complaint != "" {
				t.Fatalf("Expected agreement, got %q", complaint)
			}
			if !testCase.agrees && complaint == "" {
				t.Fatalf("Expected a disagreement between %q and %v, got none",
					testCase.version, testCase.tags)
			}
		})
	}
}

// The declared version IS the tag, whenever this commit carries one.
//
// This is what makes a release tag falsifiable: cutting v0.3.0-alpha and running the suite that
// gates it fails unless the engine answers 0.3.0-alpha. On an untagged commit there is nothing to
// disagree with, so it passes — the gate is at the tag, which is where the claim is made.
func TestTheDeclaredVersionIsTheTagItIsReleasedUnder(t *testing.T) {
	tags, err := tagsOnHead()
	if err != nil {
		t.Skipf("No git to ask which tags this commit carries: %v", err)
	}
	if complaint := tagDisagreement(Version, tags); complaint != "" {
		t.Fatalf("The tag and the version the engine reports disagree: %s", complaint)
	}
}

// tagsOnHead is what git says this commit is released as.
func tagsOnHead() ([]string, error) {
	output, err := exec.Command("git", "tag", "--points-at", "HEAD").Output()
	if err != nil {
		return nil, err
	}

	var tags []string
	for _, line := range strings.Split(string(output), "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			tags = append(tags, trimmed)
		}
	}
	return tags, nil
}

// /health answers with the version the build declares, and not with a second copy of it.
//
// The route is the only way an operator can ask a RUNNING engine what it is. When it read its own
// constant it could — and did — answer the previous release while the current one was being cut.
func TestHealthReportsTheDeclaredVersion(t *testing.T) {
	server, _ := newStockServer(t)

	recorder := httptest.NewRecorder()
	server.handleHealth(recorder, httptest.NewRequest("GET", "/health", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET /health: got %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}

	var health map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &health); err != nil {
		t.Fatalf("The health answer was not JSON: %v: %s", err, recorder.Body.String())
	}
	if health["version"] != Version {
		t.Fatalf("The engine reports version %q, want %q", health["version"], Version)
	}
}
