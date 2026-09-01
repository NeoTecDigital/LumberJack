package internal

import "strings"

// A node path names a node by the sequence of names from the forest root down to it. There is ONE
// form of it.
//
// THE DEFECT: there were two, and nothing reconciled them. POST /query answered
// `forest/momentum/x`, because the walk names its starting point after the root it started from;
// GET and PATCH /nodes/{path} answered 404 for that exact string and accepted only `momentum/x`,
// because the lookup resolves relative to the root and does not expect to be told about it. The
// `scope` parameter of /query behaved like the second while its results looked like the first, so a
// path could not even be round-tripped through the query surface. A client had to carry a
// translation layer between one route's output and another's input, and a translation layer between
// two halves of the same server is a disagreement, not a feature.
//
// THE CANONICAL FORM IS THE ROOTED ONE: every path begins with the forest root's own name.
//
//  1. IT IS TOTAL, and that is the decisive reason. The root is a real node — it holds every user,
//     it is what a permission is granted on, and GET /nodes/ returns it — and under the
//     root-relative form its path is the EMPTY STRING. An empty node_path in a query result or in
//     an /aggregate bucket key is not something a client can group on, link to, or tell apart from
//     a field that was not sent.
//  2. It is already what the query layer emits and what the walk builds, so the surface that
//     produces the most paths keeps saying what it said.
//
// THE ROOT-RELATIVE FORM IS STILL ACCEPTED, everywhere, so nothing that works today stops working:
// resolution strips one leading segment equal to the root's name and resolves the rest from the
// root. Every path therefore has exactly one meaning, including the awkward ones — `forest` is the
// root, `forest/forest` is a child of the root that happens to be called `forest`, and
// `momentum/x` and `forest/momentum/x` are the same node.

// pathSegments splits a path on its separators.
//
// Interior empty segments are KEPT. `a//b` is a malformed path and createNodePath refuses it by
// name; dropping the empty segment here would silently turn it into `a/b` and create something the
// caller did not ask for.
func pathSegments(raw string) []string {
	trimmed := strings.Trim(raw, "/")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "/")
}

// relativeSegments is a path's segments BELOW the root, whichever of the two forms it arrived in.
func relativeSegments(rootName, raw string) []string {
	segments := pathSegments(raw)
	if len(segments) > 0 && segments[0] == rootName {
		return segments[1:]
	}
	return segments
}

// canonicalNodePath is the one form a path is emitted in.
func canonicalNodePath(rootName, raw string) string {
	segments := relativeSegments(rootName, raw)
	if len(segments) == 0 {
		return rootName
	}
	return rootName + "/" + strings.Join(segments, "/")
}

// rootName is the name of the forest's root, which is the first segment of every canonical path.
//
// It is written once, when the forest is built or loaded, and never again while the server is
// serving — so this reads it without the forest hold, which is what lets a handler canonicalise the
// path it is about to answer with after its own hold has been released.
func (server *Server) rootName() string {
	if server.forest == nil {
		return ""
	}
	return server.forest.Name
}

// canonicalPath is the canonical form of a path a caller supplied.
func (server *Server) canonicalPath(raw string) string {
	return canonicalNodePath(server.rootName(), raw)
}

// segmentsFrom is a caller's path as the segments to walk from the root, in whichever form it
// arrived.
func (server *Server) segmentsFrom(raw string) []string {
	return relativeSegments(server.rootName(), raw)
}
