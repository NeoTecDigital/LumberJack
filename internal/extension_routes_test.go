// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/NeoTecDigital/LumberJack/core"
	"github.com/NeoTecDigital/LumberJack/extension"
	"github.com/gorilla/mux"
)

// The route seam (docs/extension-api.md §4.3): the engine's own table, extension routes, the
// application transport's table, the public flag and the backpressure flag.

// goldenHTTPRoutes is the HTTP surface of a store with no extensions, in registration order:
// method, pattern, and whether the session guard is in front of it.
var goldenHTTPRoutes = []string{
	"GET /health public", "POST /login public", "POST /refresh public",
	"POST /users/create session", "GET /time session", "POST /time/start session", "POST /time/stop session",
	"POST /events session", "POST /events/plan session", "POST /events/start session", "POST /events/append session",
	"POST /events/end session", "DELETE /events/{id} session", "PATCH /events/{id} session",
	"DELETE /entries/{id} session", "POST /entries session", "PATCH /entries/{id}/metadata session",
	"DELETE /time/{id} session", "POST /nodes session", "GET /forest session", "GET /forest/tree session",
	"POST /attachments/upload session", "GET /attachments/{id} session", "DELETE /attachments/{id} session",
	"POST /events/{eventId}/entries/{entryIndex}/attachments session", "POST /objects session",
	"GET,HEAD /objects/{id} session", "GET /logs session",
	"GET /access session", "POST /access/preview session", "POST /access/apply session",
	"POST /query session", "POST /aggregate session", "GET /events session", "GET /entries session",
	"POST /nodes/link session", "DELETE /nodes/link session",
	"GET /users session", "POST /users/assign session", "GET /users/profile session",
	"GET /settings/ session", "POST /settings/update session",
	"PATCH /nodes/{path:.*}/metadata session", "GET /nodes/{path:.*} session", "DELETE /nodes/{path:.*} session",
	"GET /stream session",
}

var goldenApplicationRoutes = []string{
	"POST /session public", "GET,DELETE /session session", "POST /session/activity session",
	"GET /principal session", "GET,POST /notifications session", "POST /changes session",
}

func routeTable(tables ...[]engineRoute) []string {
	var rows []string
	for _, table := range tables {
		for _, route := range table {
			access := "session"
			if route.access == routePublic {
				access = "public"
			}
			rows = append(rows, strings.Join(route.methods, ",")+" "+route.pattern+" "+access)
		}
	}
	return rows
}

// walkedRoutes is the method and pattern of every route on a built router, in registration order.
func walkedRoutes(t *testing.T, router *mux.Router) []string {
	t.Helper()
	var rows []string
	_ = router.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		pattern, _ := route.GetPathTemplate()
		methods, _ := route.GetMethods()
		rows = append(rows, strings.Join(methods, ",")+" "+pattern)
		return nil
	})
	return rows
}

func withoutAccess(rows []string) []string {
	trimmed := make([]string, len(rows))
	for index, row := range rows {
		trimmed[index] = row[:strings.LastIndex(row, " ")]
	}
	return trimmed
}

func TestRouteTableIsUnchangedWithNoExtensions(t *testing.T) {
	server, _ := newStockServer(t)
	if got := routeTable(server.fixedRoutes(), server.catchAllRoutes()); strings.Join(got, "\n") != strings.Join(goldenHTTPRoutes, "\n") {
		t.Fatalf("the HTTP table changed:\n%s", strings.Join(got, "\n"))
	}
	if got := walkedRoutes(t, server.routes()); strings.Join(got, "\n") != strings.Join(withoutAccess(goldenHTTPRoutes), "\n") {
		t.Fatalf("the built router is not the table, in order:\n%s", strings.Join(got, "\n"))
	}
	if got := routeTable(server.applicationRoutes()); strings.Join(got, "\n") != strings.Join(goldenApplicationRoutes, "\n") {
		t.Fatalf("the application table changed:\n%s", strings.Join(got, "\n"))
	}
}

type routeInstance struct {
	routes []extension.Route
}

func (i routeInstance) Close(context.Context) error { return nil }

func (i routeInstance) Routes(router extension.Router) error {
	for _, route := range i.routes {
		if err := router.Handle(route); err != nil {
			return err
		}
	}
	return nil
}

func withRoutes(t *testing.T, server *Server, routes ...extension.Route) error {
	t.Helper()
	ext := testExtension{spec: extension.Spec{Name: "routes"}, attach: func(extension.Host) (extension.Instance, error) {
		return routeInstance{routes: routes}, nil
	}}
	return server.AttachExtensions([]extension.Extension{ext})
}

func answering(text string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, text) }
}

func TestExtensionRouteCannotShadowOrPrecedeCatchAll(t *testing.T) {
	refused := []extension.Route{
		{Method: "GET", Pattern: "/forest", Handler: answering("x")},
		{Method: "POST", Pattern: "/session", Handler: answering("x"), Transport: extension.Application},
		{Method: "GET", Pattern: "/nodes/{rest:.*}", Handler: answering("x")},
		{Method: "PATCH", Pattern: "/nodes/{a}/{b}/metadata", Handler: answering("x")},
		{Method: "GET", Pattern: "/{any:.*}", Handler: answering("x")},
		{Method: "GET", Pattern: "/stream", Handler: answering("x"), Transport: extension.HTTP},
		{Method: "GET", Pattern: "relative", Handler: answering("x")},
		{Method: "GET", Pattern: "/no-handler"},
	}
	for _, route := range refused {
		server, _ := newStockServer(t)
		if err := withRoutes(t, server, route); !errors.Is(err, ErrExtensionSet) {
			t.Errorf("%s %s was accepted: %v", route.Method, route.Pattern, err)
		}
	}
	server, _ := newStockServer(t)
	twice := extension.Route{Method: "GET", Pattern: "/ext/thing", Handler: answering("x")}
	if err := withRoutes(t, server, twice, twice); !errors.Is(err, ErrExtensionSet) {
		t.Fatalf("one method and pattern was taken twice: %v", err)
	}
	server, _ = newStockServer(t)
	if err := withRoutes(t, server, twice); err != nil {
		t.Fatalf("a route of its own was refused: %v", err)
	}
	got := walkedRoutes(t, server.routes())
	if index := indexOf(got, "GET /ext/thing"); index < 0 || index > indexOf(got, "PATCH /nodes/{path:.*}/metadata") {
		t.Fatalf("the extension route is not ahead of the catch-alls: %v", got)
	}
}

func indexOf(rows []string, row string) int {
	for index, held := range rows {
		if held == row {
			return index
		}
	}
	return -1
}

func TestApplicationOnlyRouteAbsentFromHTTP(t *testing.T) {
	server, _ := newStockServer(t)
	if err := withRoutes(t, server,
		extension.Route{Method: "GET", Pattern: "/only/application", Handler: answering("application"), Access: extension.Public, Transport: extension.Application},
		extension.Route{Method: "GET", Pattern: "/only/http", Handler: answering("http"), Access: extension.Public, Transport: extension.HTTP},
		extension.Route{Method: "GET", Pattern: "/both", Handler: answering("both"), Access: extension.Public},
	); err != nil {
		t.Fatal(err)
	}
	httpAnswers := map[string]int{"/only/application": 404, "/only/http": 200, "/both": 200}
	for target, want := range httpAnswers {
		if got := serve(t, server, httptest.NewRequest("GET", target, nil)).Code; got != want {
			t.Errorf("HTTP %s answered %d, want %d", target, got, want)
		}
	}
	applicationAnswers := map[string]string{"/only/application": "application", "/both": "both"}
	for target, want := range applicationAnswers {
		if got := applicationCall(t, server, "GET", target, nil); got.Status != 200 || string(got.Body) != want {
			t.Errorf("application %s answered %d %q", target, got.Status, got.Body)
		}
	}
	if got := applicationCall(t, server, "GET", "/only/http", nil); got.Status != 404 {
		t.Errorf("an HTTP-only route answered the application transport %d", got.Status)
	}
}

func TestPublicFlagAndBackpressureFlag(t *testing.T) {
	server, _ := newStockServer(t)
	if err := withRoutes(t, server,
		extension.Route{Method: "POST", Pattern: "/ext/exchange", Handler: answering("exchanged"), Access: extension.Public, BackpressureExempt: true},
		extension.Route{Method: "POST", Pattern: "/ext/write", Handler: answering("written"), Access: extension.Public},
		extension.Route{Method: "GET", Pattern: "/ext/private", Handler: answering("private")},
	); err != nil {
		t.Fatal(err)
	}
	if got := applicationCall(t, server, "GET", "/ext/private", nil); got.Status != http.StatusUnauthorized {
		t.Fatalf("a session route answered %d without a session", got.Status)
	}
	bearer := sessionFor(t, server, adminID(t, server), "admin")
	request := httptest.NewRequest("GET", "/ext/private", nil)
	request.Header.Set("Authorization", "Bearer "+bearer)
	if got := serve(t, server, request); got.Code != 200 || got.Body.String() != "private" {
		t.Fatalf("a session route answered %d with one", got.Code)
	}
	if err := server.changeForest(func() error {
		pending := server.correspondenceState().Pending
		for index := 0; index < 4096; index++ {
			id := fmt.Sprintf("backlog-%d", index)
			pending[id] = core.OutboxChange{ID: id}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got := applicationCall(t, server, "POST", "/ext/write", nil); got.Status != http.StatusServiceUnavailable {
		t.Fatalf("a write behind a full backlog answered %d", got.Status)
	}
	if got := applicationCall(t, server, "POST", "/ext/exchange", nil); got.Status != 200 {
		t.Fatalf("an exempt credential exchange answered %d behind a full backlog", got.Status)
	}
}
