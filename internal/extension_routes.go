// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/NeoTecDigital/LumberJack/extension"
	"github.com/gorilla/mux"
)

// The routes extensions register (docs/extension-api.md §4.3). They are taken once, at attach, and
// held to three rules: no route takes a method and pattern the engine or another extension holds; no
// route matches a request meant for the engine's catch-alls, which are tried last; and a route is
// behind the session guard unless it says Public.

type routeTransport uint8

const (
	transportHTTP routeTransport = iota
	transportApplication
)

// extensionRoute is a registered extension route.
type extensionRoute struct {
	extension.Route
	owner string
}

func (route extensionRoute) on(transport routeTransport) bool {
	switch route.Transport {
	case extension.HTTP:
		return transport == transportHTTP
	case extension.Application:
		return transport == transportApplication
	}
	return true
}

func (route extensionRoute) engineRoute() engineRoute {
	access := routeSession
	if route.Access == extension.Public {
		access = routePublic
	}
	return engineRoute{methods: []string{route.Method}, pattern: route.Pattern, handler: route.Handler, access: access}
}

// catchAllProbes are requests only the engine's catch-alls may answer.
var catchAllProbes = []struct{ method, target string }{
	{"GET", "/nodes/lj-probe/child"}, {"DELETE", "/nodes/lj-probe/child"},
	{"PATCH", "/nodes/lj-probe/child/metadata"}, {"GET", "/stream"},
}

// routeRegistry is the Router an extension's RouteProvider registers through.
type routeRegistry struct {
	server *Server
	owner  string
	held   map[string]string // method + " " + pattern -> holder
	routes *[]extensionRoute
}

func (registry *routeRegistry) Handle(route extension.Route) error {
	if route.Method == "" || !strings.HasPrefix(route.Pattern, "/") || route.Handler == nil {
		return fmt.Errorf("%w: %s registers an incomplete route %s %q", ErrExtensionSet, registry.owner, route.Method, route.Pattern)
	}
	key := strings.ToUpper(route.Method) + " " + route.Pattern
	if holder, taken := registry.held[key]; taken {
		return fmt.Errorf("%w: %s cannot take %s, which %s holds", ErrExtensionSet, registry.owner, key, holder)
	}
	if err := refuseCatchAllPrecedence(route); err != nil {
		return fmt.Errorf("%w: %s %s: %v", ErrExtensionSet, registry.owner, key, err)
	}
	registry.held[key] = registry.owner
	*registry.routes = append(*registry.routes, extensionRoute{Route: route, owner: registry.owner})
	return nil
}

// refuseCatchAllPrecedence refuses a route that would answer a request the catch-alls exist for.
// Extension routes are registered before the catch-alls, so such a route would silently take
// /nodes/{path} or /stream away from the engine.
func refuseCatchAllPrecedence(route extension.Route) error {
	if route.Transport == extension.Application {
		return nil
	}
	probe := mux.NewRouter()
	probe.HandleFunc(route.Pattern, route.Handler).Methods(route.Method)
	for _, request := range catchAllProbes {
		var match mux.RouteMatch
		if probe.Match(httptest.NewRequest(request.method, request.target, nil), &match) {
			return fmt.Errorf("would answer %s %s ahead of the engine's catch-all", request.method, request.target)
		}
	}
	return nil
}

// engineHeldRoutes is every method and pattern the engine serves on either transport.
func (server *Server) engineHeldRoutes() map[string]string {
	held := map[string]string{}
	for _, table := range [][]engineRoute{server.fixedRoutes(), server.catchAllRoutes(), server.applicationRoutes()} {
		for _, route := range table {
			for _, method := range route.methods {
				held[method+" "+route.pattern] = "the engine"
			}
		}
	}
	return held
}

// collectRoutes asks each RouteProvider, in attach order, for its routes.
func (set *extensionSet) collectRoutes(server *Server, specs []extension.Spec) error {
	held := server.engineHeldRoutes()
	for index, instance := range set.instances {
		provider, ok := instance.(extension.RouteProvider)
		if !ok {
			continue
		}
		registry := &routeRegistry{server: server, owner: specs[index].Name, held: held, routes: &set.routes}
		if err := provider.Routes(registry); err != nil {
			return fmt.Errorf("%w: %s routes: %v", ErrExtensionSet, specs[index].Name, err)
		}
	}
	return nil
}

// extensionRoutes are the extension routes served on one transport, in registration order.
func (server *Server) extensionRoutes(transport routeTransport) []engineRoute {
	if server.extensions == nil {
		return nil
	}
	var routes []engineRoute
	for _, route := range server.extensions.routes {
		if route.on(transport) {
			routes = append(routes, route.engineRoute())
		}
	}
	return routes
}

// applicationRouter is the application transport's own table: the engine's application routes,
// then every extension route the transport serves.
func (server *Server) applicationRouter() *mux.Router {
	router := mux.NewRouter()
	for _, route := range server.applicationRoutes() {
		server.register(router, route)
	}
	for _, route := range server.extensionRoutes(transportApplication) {
		server.register(router, route)
	}
	return router
}

// backpressureExempt reports whether a write is a credential exchange the change-delivery backlog
// must not strand: the engine's own, or an extension route flagged BackpressureExempt.
func (server *Server) backpressureExempt(request *http.Request) bool {
	if engineBackpressureExempt[request.URL.Path] {
		return true
	}
	if server.extensions == nil {
		return false
	}
	exempt := mux.NewRouter()
	for _, route := range server.extensions.routes {
		if route.BackpressureExempt {
			exempt.HandleFunc(route.Pattern, route.Handler).Methods(route.Method)
		}
	}
	var match mux.RouteMatch
	return exempt.Match(request, &match)
}
