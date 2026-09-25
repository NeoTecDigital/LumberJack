// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"net"
	"testing"

	"github.com/NeoTecDigital/LumberJack/types"
)

// The engine used to build its listener with `Addr: ":" + port`, which is every interface on the
// host. On this machine that is loopback AND the LAN address AND Tailscale AND the VPN, with no
// TLS and no CORS in front of it, while the relay that is supposed to be the only door was bound
// to 127.0.0.1. The hole was the engine, and nothing here could see it: the routing tests assert
// which routes need a session, and not one of them looks at where the socket is.
//
// Both tests below read the ADDRESS OFF THE SHELL that NewServer and LoadServer are both built
// from, so they hold for either entrypoint without binding a port.
//
// BOTH WERE WATCHED TO FAIL, in ONE run against ONE tree: internal/api.go reverted to the version
// that had the defect (`git checkout HEAD -- internal/api.go`), with types.go and these tests as
// they stand. `go test ./internal/ -run TestServerBinds -v` printed:
//
//	=== RUN   TestServerBindsLoopbackByDefault
//	    api_bind_test.go:58: The default listen address is ":8085": an empty host binds every
//	        interface on this machine, including LAN, Tailscale and VPN addresses
//	--- FAIL: TestServerBindsLoopbackByDefault (0.00s)
//	=== RUN   TestServerBindsWhereItIsExplicitlyTold
//	    api_bind_test.go:79: An explicit bind host was ignored: listening on ":8085"
//	--- FAIL: TestServerBindsWhereItIsExplicitlyTold (0.00s)
//	FAIL
//	FAIL	github.com/NeoTecDigital/LumberJack/internal	0.002s
//	FAIL
//
// That is the whole of the evidence for this file, and it is one mutation rather than two: the
// default and the opt-in are the same missing rule seen from either side.

// A config that says nothing about where to bind is the case every install falls into, and it must
// come up on loopback.
func TestServerBindsLoopbackByDefault(t *testing.T) {
	server, err := newServerShell(types.ServerConfig{
		Process: types.ProcessInfo{ServerPort: "8085"},
	})
	if err != nil {
		t.Fatalf("Failed to build the server shell: %v", err)
	}

	host, port, err := net.SplitHostPort(server.server.Addr)
	if err != nil {
		t.Fatalf("The listen address %q is not host:port: %v", server.server.Addr, err)
	}
	if port != "8085" {
		t.Fatalf("The listen address %q does not carry the configured port", server.server.Addr)
	}

	// An EMPTY host is the defect, not a neutral value: net/http reads it as every interface.
	ip := net.ParseIP(host)
	if ip == nil {
		t.Fatalf("The default listen address is %q: an empty host binds every interface on this "+
			"machine, including LAN, Tailscale and VPN addresses", server.server.Addr)
	}
	if !ip.IsLoopback() {
		t.Fatalf("The default listen address is %q, which is reachable off this machine; binding "+
			"anywhere but loopback must be a deliberate act", server.server.Addr)
	}
}

// The other half of the rule: binding elsewhere must still be POSSIBLE, or the fix above is a
// feature removal rather than a default. An operator who says so explicitly gets what they asked
// for, and nothing else does. Where the ASKING happens - the flag, the environment, and the one
// assignment that carries either into this struct - is covered in cmd/serve_bind_test.go.
func TestServerBindsWhereItIsExplicitlyTold(t *testing.T) {
	server, err := newServerShell(types.ServerConfig{
		Process: types.ProcessInfo{ServerPort: "8085", BindHost: "0.0.0.0"},
	})
	if err != nil {
		t.Fatalf("Failed to build the server shell: %v", err)
	}
	if server.server.Addr != "0.0.0.0:8085" {
		t.Fatalf("An explicit bind host was ignored: listening on %q", server.server.Addr)
	}
}
