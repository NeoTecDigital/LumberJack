package peertransport

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
	"time"

	"github.com/hashicorp/raft"
)

func TestThreePeersRPCAndDestinationGuard(t *testing.T) {
	_, configs := fixture(t)
	nodes := []*Transport{openFixture(t, configs[0]), openFixture(t, configs[1]), openFixture(t, configs[2])}
	for _, node := range nodes {
		serveVotes(t, node)
	}
	for _, pair := range [][2]int{{0, 1}, {0, 2}, {1, 0}, {1, 2}, {2, 0}, {2, 1}} {
		assertVote(t, nodes[pair[0]], configs[pair[1]].LocalID, nodes[pair[1]].Raft().LocalAddr())
	}
	if err := vote(nodes[0], "unknown", nodes[1].Raft().LocalAddr()); err != ErrPeer {
		t.Fatalf("unknown ID: %v", err)
	}
	if err := vote(nodes[0], "b", nodes[2].Raft().LocalAddr()); err != ErrPeer {
		t.Fatalf("wrong configured address: %v", err)
	}
	if err := vote(nodes[0], "b", "127.0.0.1:1"); err != ErrPeer {
		t.Fatalf("unknown destination: %v", err)
	}
	if err := vote(nodes[0], "a", nodes[0].Raft().LocalAddr()); err != ErrPeer {
		t.Fatalf("self destination: %v", err)
	}
}
func assertVote(t *testing.T, from *Transport, id raft.ServerID, address raft.ServerAddress) {
	t.Helper()
	if err := vote(from, id, address); err != nil {
		t.Fatal(err)
	}
}

func TestInboundIdentityRefusals(t *testing.T) {
	ca, configs := fixture(t)
	otherCA := newAuthority(t)
	server := openFixture(t, configs[0])
	cases := map[string]tls.Certificate{
		"missing":   {},
		"unknown":   ca.issue(t, []string{"unknown.peer.test"}, false),
		"untrusted": otherCA.issue(t, []string{"b.peer.test"}, false),
		"expired":   ca.issue(t, []string{"b.peer.test"}, true),
		"wildcard":  ca.issue(t, []string{"*.peer.test"}, false),
		"ambiguous": ca.issue(t, []string{"b.peer.test", "c.peer.test"}, false),
		"self":      configs[0].Certificate,
	}
	for name, cert := range cases {
		t.Run(name, func(t *testing.T) { refuseClient(t, server, ca.roots, cert) })
	}
	serveVotes(t, server)
	good := openFixture(t, configs[1])
	assertVote(t, good, "a", server.Raft().LocalAddr())
}
func refuseClient(t *testing.T, server *Transport, roots *x509.CertPool, cert tls.Certificate) {
	t.Helper()
	raw, err := net.DialTimeout("tcp", string(server.Raft().LocalAddr()), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(time.Second))
	cfg := &tls.Config{RootCAs: roots, ServerName: "a.peer.test", MinVersion: tls.VersionTLS13}
	if len(cert.Certificate) > 0 {
		cfg.Certificates = []tls.Certificate{cert}
	}
	conn := tls.Client(raw, cfg)
	if err := conn.Handshake(); err != nil {
		return
	}
	_, err = conn.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("unauthorized stream accepted")
	}
	if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("unauthorized stream remained open")
	}
}

func TestWrongServerSANRefused(t *testing.T) {
	ca, configs := fixture(t)
	listener, err := net.Listen("tcp", string(configs[1].Peers["b"].Address))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	cert := ca.issue(t, []string{"c.peer.test"}, false)
	done := make(chan struct{})
	go func() {
		defer close(done)
		raw, err := listener.Accept()
		if err != nil {
			return
		}
		defer raw.Close()
		raw.SetDeadline(time.Now().Add(time.Second))
		conn := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
		conn.Handshake()
	}()
	client := openFixture(t, configs[0])
	if err := vote(client, "b", configs[0].Peers["b"].Address); err == nil {
		t.Fatal("wrong server SAN accepted")
	}
	<-done
}

func TestPlaintextAndStalledHandshakeCleanup(t *testing.T) {
	_, configs := fixture(t)
	server := openFixture(t, configs[0])
	raw, err := net.Dial("tcp", string(server.Raft().LocalAddr()))
	if err != nil {
		t.Fatal(err)
	}
	raw.SetDeadline(time.Now().Add(time.Second))
	raw.Write([]byte("plaintext is not raft TLS\n"))
	if _, err := raw.Read(make([]byte, 1)); err == nil {
		t.Fatal("plaintext accepted")
	}
	raw.Close()
	stalled, err := net.Dial("tcp", string(server.Raft().LocalAddr()))
	if err != nil {
		t.Fatal(err)
	}
	defer stalled.Close()
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	stalled.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := stalled.Read(make([]byte, 1)); err == nil {
		t.Fatal("stalled handshake survived Close")
	}
	if conn, err := net.DialTimeout("tcp", string(server.Raft().LocalAddr()), time.Second); err == nil {
		conn.Close()
		t.Fatal("listener survived Close")
	}
}

func TestAdvertisedAddressAndConfigurationIsolation(t *testing.T) {
	_, configs := fixture(t)
	c := configs[0]
	c.ListenAddress = "127.0.0.1:0"
	transport := openFixture(t, c)
	if transport.Raft().LocalAddr() != c.Peers[c.LocalID].Address {
		t.Fatal("advertised identity used listen port")
	}
	frozenName := transport.layer.config.Peers["b"].DNSName
	c.Peers["b"] = Peer{Address: "127.0.0.1:1", DNSName: "mutated.peer.test"}
	c.Certificate.Certificate[0][0] ^= 1
	c.Roots.AddCert(newAuthority(t).cert)
	if transport.layer.config.Peers["b"].DNSName != frozenName {
		t.Fatal("peer map aliased")
	}
	if _, err := x509.ParseCertificate(transport.layer.config.Certificate.Certificate[0]); err != nil {
		t.Fatal("certificate bytes aliased")
	}
	if len(transport.layer.config.Roots.Subjects()) != 1 {
		t.Fatal("roots aliased")
	}
}
