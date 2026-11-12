// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package extension

import "net/http"

// RouteProvider registers an extension's routes, once, at attach.
type RouteProvider interface {
	Routes(r Router) error
}

// Router takes an extension's routes. Handle refuses a method and pattern the engine or another
// extension holds, and any route that would match a request meant for the engine's catch-alls
// (/nodes/{path} and /stream), which are always tried last.
type Router interface {
	Handle(route Route) error
}

// Route is one extension route.
type Route struct {
	Method, Pattern    string           // gorilla/mux pattern
	Handler            http.HandlerFunc // principal via PrincipalFrom(r.Context()) or the engine's user id
	Access             Access           // Session (default) | Public
	Transport          Transport        // Both (default) | HTTP | Application
	BackpressureExempt bool             // a credential exchange that must not be stranded
}

// Access is whether a route is behind the engine's session guard.
type Access uint8

const (
	Session Access = iota // behind the session guard: authenticators, then the engine's bearer check
	Public                // no guard; the handler authenticates whatever it accepts
)

// Transport is which transport serves a route.
type Transport uint8

const (
	Both        Transport = iota // the HTTP mux and the application transport
	HTTP                         // the HTTP mux only
	Application                  // the application transport only; never on the HTTP mux
)
