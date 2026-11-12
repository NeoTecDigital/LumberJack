// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"net/http"

	"github.com/gorilla/mux"
)

// The engine's route table. One declarative list per kind of route, so what is public and what is
// protected, and in which order patterns are tried, can be asserted without binding a port
// (TestRouteTableIsUnchangedWithNoExtensions holds the golden list).
//
// ORDER IS MEANING. Gorilla matches in registration order: the engine's fixed routes first, then the
// routes extensions register (extension_routes.go), then the engine's catch-alls — /nodes/{path:.*}
// and /stream — last, so neither an extension nor a fixed route is ever swallowed by them.

type routeAccess uint8

const (
	routeSession routeAccess = iota // behind authMiddleware
	routePublic                     // the credential exchanges and the health probe
)

// engineRoute is one route the engine serves.
type engineRoute struct {
	methods []string
	pattern string
	handler http.HandlerFunc
	access  routeAccess
}

// fixedRoutes are the engine's routes that are not catch-alls.
func (s *Server) fixedRoutes() []engineRoute {
	return []engineRoute{
		// Public routes
		{[]string{"GET"}, "/health", s.handleHealth, routePublic},
		{[]string{"POST"}, "/login", s.handleLogin, routePublic},
		{[]string{"POST"}, "/refresh", s.handleRefreshToken, routePublic},

		// Protected routes
		//
		// /users/create IS ONE OF THEM. It was public, which meant anyone who could reach the port could
		// register themselves, receive ReadPermission on the root of the forest, and read the whole tree
		// and the entire user list. Creating a user is an administrative act; the handler checks for
		// AdminPermission and the middleware here is what gives it a caller to check.
		{[]string{"POST"}, "/users/create", s.handleCreateUser, routeSession},
		{[]string{"GET"}, "/time", s.handleGetTimeTracking, routeSession},
		{[]string{"POST"}, "/time/start", s.handleStartTimeTracking, routeSession},
		{[]string{"POST"}, "/time/stop", s.handleStopTimeTracking, routeSession},
		{[]string{"POST"}, "/events", s.handleGetEventEntries, routeSession},
		{[]string{"POST"}, "/events/plan", s.handlePlanEvent, routeSession},
		{[]string{"POST"}, "/events/start", s.handleStartEvent, routeSession},
		{[]string{"POST"}, "/events/append", s.handleAppendToEvent, routeSession},
		{[]string{"POST"}, "/events/end", s.handleEndEvent, routeSession},
		// Cancelling an event and moving one. Registered AFTER the named /events/* verbs, and matching
		// only DELETE and PATCH, so /events/plan can never be read as an event whose id is "plan":
		// gorilla matches in registration order and by method, and both guards are wanted here rather
		// than either alone.
		{[]string{"DELETE"}, "/events/{id}", s.handleDeleteEvent, routeSession},
		{[]string{"PATCH"}, "/events/{id}", s.handleUpdateEvent, routeSession},
		// Retracting one entry, and removing one tracked span. Both address the thing by ID and take
		// the node as ?path=, which is what DELETE /attachments/{id} already does.
		{[]string{"DELETE"}, "/entries/{id}", s.handleDeleteEntry, routeSession},
		// Writing a node-level entry, and reordering or reparenting one. POST /entries wraps
		// core.AddEntry; PATCH /entries/{id}/metadata addresses the entry by id the way DELETE does. Both
		// match only their own method, so neither collides with GET /entries (the feed listing, in
		// registerQueryRoutes) or DELETE /entries/{id}; and {id} matches a single segment, so
		// /entries/{id}/metadata is a distinct pattern, not the delete route with a trailing path.
		{[]string{"POST"}, "/entries", s.handleCreateEntry, routeSession},
		{[]string{"PATCH"}, "/entries/{id}/metadata", s.handlePatchEntryMetadata, routeSession},
		{[]string{"DELETE"}, "/time/{id}", s.handleDeleteTimeSpan, routeSession},
		{[]string{"POST"}, "/nodes", s.handleCreateNode, routeSession},
		{[]string{"GET"}, "/forest", s.handleGetForest, routeSession},
		{[]string{"GET"}, "/forest/tree", s.handleGetTree, routeSession},
		{[]string{"POST"}, "/attachments/upload", s.handleUploadAttachment, routeSession},
		{[]string{"GET"}, "/attachments/{id}", s.handleGetAttachment, routeSession},
		{[]string{"DELETE"}, "/attachments/{id}", s.handleDeleteAttachment, routeSession},
		{[]string{"POST"}, "/events/{eventId}/entries/{entryIndex}/attachments", s.handleAddEntryAttachment, routeSession},
		// The object log. Raw bytes addressed by their BLAKE3, appended beside the state file and never
		// rewritten with it. See api_objects.go for why the permission is the root's.
		{[]string{"POST"}, "/objects", s.handlePutObject, routeSession},
		{[]string{"GET", "HEAD"}, "/objects/{id}", s.handleGetObject, routeSession},
		{[]string{"GET"}, "/logs", s.handleGetLogs, routeSession},
		{[]string{"GET"}, "/access", s.handleAccess, routeSession},
		{[]string{"POST"}, "/access/preview", s.handleAccess, routeSession},
		{[]string{"POST"}, "/access/apply", s.handleAccess, routeSession},
		// The query layer. One predicate grammar, two entry points, and the discovery routes that are
		// thin wrappers over the first of them rather than a second implementation.
		{[]string{"POST"}, "/query", s.handleQuery, routeSession},
		{[]string{"POST"}, "/aggregate", s.handleAggregate, routeSession},
		// GET /events is the DISCOVERY primitive: POST /events needs an event_id the caller must
		// already possess, so until now there was no way to find out what events exist at all.
		{[]string{"GET"}, "/events", s.handleListEvents, routeSession},
		{[]string{"GET"}, "/entries", s.handleListEntries, routeSession},
		// The canvas routes. Registered BEFORE the {path} catch-all: gorilla matches in registration
		// order, and a catch-all registered first would swallow /nodes/link.
		{[]string{"POST"}, "/nodes/link", s.handleLinkNode, routeSession},
		{[]string{"DELETE"}, "/nodes/link", s.handleUnlinkNode, routeSession},

		// The user and settings routes.
		{[]string{"GET"}, "/users", s.handleGetUsers, routeSession},
		{[]string{"POST"}, "/users/assign", s.handleAssignUser, routeSession},
		{[]string{"GET"}, "/users/profile", s.handleGetUserProfile, routeSession},
		{[]string{"GET"}, "/settings/", s.handleGetServerSettings, routeSession},
		{[]string{"POST"}, "/settings/update", s.handleUpdateServerSettings, routeSession},
	}
}

// catchAllRoutes are registered after every other route.
func (s *Server) catchAllRoutes() []engineRoute {
	return []engineRoute{
		{[]string{"PATCH"}, "/nodes/{path:.*}/metadata", s.handlePatchNodeMetadata, routeSession},
		{[]string{"GET"}, "/nodes/{path:.*}", s.handleGetNode, routeSession},
		// DELETE /nodes/{path} removes a NODE. It is a catch-all and so registered AFTER /nodes/link:
		// a {path} catch-all registered before it would swallow DELETE /nodes/link and turn every edge
		// removal into an attempt to delete a node called "link". The two operations are different and
		// the router must not be able to confuse them either. See api_node_delete.go for why they are
		// different.
		{[]string{"DELETE"}, "/nodes/{path:.*}", s.handleDeleteNode, routeSession},
		// The live feed. Registered last of these because it never returns while a client is connected.
		{[]string{"GET"}, "/stream", s.handleStream, routeSession},
	}
}

// applicationRoutes are the engine's application-transport-only routes. They never appear on the
// HTTP mux; dispatchApplication tries them, then the extensions' application routes, then the mux.
func (s *Server) applicationRoutes() []engineRoute {
	return []engineRoute{
		{[]string{"POST"}, "/session", s.handleApplicationSession, routePublic},
		{[]string{"GET", "DELETE"}, "/session", s.handleApplicationSession, routeSession},
		{[]string{"POST"}, "/session/activity", s.handleApplicationActivity, routeSession},
		{[]string{"GET"}, "/principal", s.handlePrincipal, routeSession},
		{[]string{"GET", "POST"}, "/notifications", s.handleApplicationNotifications, routeSession},
		{[]string{"POST"}, "/changes", s.handleApplicationChanges, routeSession},
	}
}

// engineBackpressureExempt are the engine's credential exchanges and its change dispatcher, which a
// change-delivery backlog must not be able to strand.
var engineBackpressureExempt = map[string]bool{"/session": true, "/login": true, "/refresh": true, "/changes": true}

// register adds one route to a router, behind the session guard unless it is public.
func (s *Server) register(router *mux.Router, route engineRoute) {
	handler := route.handler
	if route.access == routeSession {
		handler = s.authMiddleware(handler)
	}
	router.HandleFunc(route.pattern, handler).Methods(route.methods...)
}

// routes builds the whole HTTP surface, including which parts of it require a session.
//
// It is SEPARATE from Start so that what is public and what is protected can be asserted without
// binding a port. The routing table used to be a local inside Start, which meant no test could tell
// a route registered publicly from one registered behind the middleware — and /users/create was
// registered publicly for exactly that long.
func (s *Server) routes() *mux.Router {
	return s.routesFor(transportHTTP)
}

// routesFor is the mux one transport falls through to: the engine's fixed routes, the extension
// routes that transport serves, then the catch-alls. An HTTP-only extension route is not on the
// application transport's, and an application-only one is not on the HTTP server's.
func (s *Server) routesFor(transport routeTransport) *mux.Router {
	router := mux.NewRouter()
	for _, route := range s.fixedRoutes() {
		s.register(router, route)
	}
	for _, route := range s.extensionRoutes(transport) {
		s.register(router, route)
	}
	for _, route := range s.catchAllRoutes() {
		s.register(router, route)
	}
	return router
}
