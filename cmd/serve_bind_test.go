package cmd

import (
	"testing"

	"github.com/NeoTecDigital/LumberJack/internal"
)

// `serve` is how the Momentum stack starts the engine, so whatever this resolves is what actually
// gets bound. The three answers are ordered, and the LAST of them is the one that matters: an
// operator who says nothing gets loopback, never every interface.
//
// WATCHED TO FAIL against the tree that had the defect — `serve` bound `:port` and hardcoded
// `ServerURL: "127.0.0.1"` in the banner it printed, so there was no host to resolve and no seam
// to carry it. With cmd/serve.go alone reverted to that state (`git checkout HEAD -- cmd/serve.go`)
// and the test files as they stand, `go test ./cmd/ -run TestResolveBindHost` printed:
//
//	# github.com/NeoTecDigital/LumberJack/cmd [github.com/NeoTecDigital/LumberJack/cmd.test]
//	cmd/serve_bind_test.go:41:13: undefined: bindHostEnv
//	cmd/serve_bind_test.go:42:14: undefined: resolveBindHost
//	cmd/serve_bind_test.go:44:21: undefined: bindHostEnv
//	cmd/serve_bind_test.go:99:13: undefined: bindHostEnv
//	cmd/serve_bind_test.go:102:16: undefined: resolveBindHost
//	cmd/serve_bind_test.go:103:31: undefined: serveProcessInfo
//	cmd/serve_bind_test.go:107:21: undefined: bindHostEnv
//	FAIL	github.com/NeoTecDigital/LumberJack/cmd [build failed]
//	FAIL
func TestResolveBindHost(t *testing.T) {
	for _, testCase := range []struct {
		name string
		flag string
		env  string
		want string
	}{
		{name: "nothing given binds loopback", want: "127.0.0.1"},
		{name: "the environment opts in", env: "0.0.0.0", want: "0.0.0.0"},
		{name: "the flag beats the environment", flag: "10.1.10.220", env: "0.0.0.0", want: "10.1.10.220"},
		{name: "blank is not an opt-in", flag: "  ", env: "  ", want: "127.0.0.1"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Setenv(bindHostEnv, testCase.env)
			if got := resolveBindHost(testCase.flag); got != testCase.want {
				t.Fatalf("resolveBindHost(%q) with %s=%q = %q, want %q",
					testCase.flag, bindHostEnv, testCase.env, got, testCase.want)
			}
		})
	}
}

// THE SEAM, which neither of the tests either side of it covers.
//
// TestResolveBindHost proves the flag and the environment are read. The tests in internal prove an
// unset BindHost binds loopback and a set one is honoured. Between them is ONE assignment — the
// resolved host into the record the server is built from — and deleting it leaves both of those
// green: every install still binds loopback, and --host and LUMBERJACK_HOST are silently ignored.
// A flag that is read, validated, warned about and then dropped is worse than no flag.
//
// So this goes end to end through the real functions: flag and environment -> resolveBindHost ->
// serveProcessInfo -> internal.ListenAddr, which is the same call newServerShell builds the
// listener from.
//
// WATCHED TO FAIL with `BindHost: bindHost,` deleted from serveProcessInfo — the mutation that
// otherwise leaves the whole submodule suite green. `go test ./cmd/ -run
// TestServeBindHostReachesTheListener -v` printed:
//
//	=== RUN   TestServeBindHostReachesTheListener
//	=== RUN   TestServeBindHostReachesTheListener/nothing_given_listens_on_loopback
//	=== RUN   TestServeBindHostReachesTheListener/the_environment_reaches_the_listener
//	    serve_bind_test.go:106: --host "" with LUMBERJACK_HOST="0.0.0.0" listens on
//	        "127.0.0.1:8085", want "0.0.0.0:8085"
//	=== RUN   TestServeBindHostReachesTheListener/the_flag_reaches_the_listener
//	    serve_bind_test.go:106: --host "10.1.10.220" with LUMBERJACK_HOST="" listens on
//	        "127.0.0.1:8085", want "10.1.10.220:8085"
//	--- FAIL: TestServeBindHostReachesTheListener (0.00s)
//	    --- PASS: TestServeBindHostReachesTheListener/nothing_given_listens_on_loopback (0.00s)
//	    --- FAIL: TestServeBindHostReachesTheListener/the_environment_reaches_the_listener (0.00s)
//	    --- FAIL: TestServeBindHostReachesTheListener/the_flag_reaches_the_listener (0.00s)
//	FAIL
//	FAIL	github.com/NeoTecDigital/LumberJack/cmd	0.002s
//	FAIL
func TestServeBindHostReachesTheListener(t *testing.T) {
	// serveProcessInfo reads the flags cobra would have filled in, so the test fills them the same
	// way and puts them back, as the CLI tests here already do for their directories.
	port, db := servePort, serveDBName
	t.Cleanup(func() { servePort, serveDBName = port, db })
	servePort, serveDBName = "8085", "bind-seam"

	for _, testCase := range []struct {
		name string
		flag string
		env  string
		want string
	}{
		{name: "nothing given listens on loopback", want: "127.0.0.1:8085"},
		{name: "the environment reaches the listener", env: "0.0.0.0", want: "0.0.0.0:8085"},
		{name: "the flag reaches the listener", flag: "10.1.10.220", want: "10.1.10.220:8085"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Setenv(bindHostEnv, testCase.env)

			// Exactly what RunE does, in the order it does it.
			bindHost := resolveBindHost(testCase.flag)
			got := internal.ListenAddr(serveProcessInfo(bindHost))

			if got != testCase.want {
				t.Fatalf("--host %q with %s=%q listens on %q, want %q",
					testCase.flag, bindHostEnv, testCase.env, got, testCase.want)
			}
		})
	}
}
