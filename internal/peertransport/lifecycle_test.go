package peertransport

import (
	"crypto/tls"
	"net"
	"testing"
	"time"
)

func TestTLS12Refused(t *testing.T) {
	ca, configs := fixture(t)
	server := openFixture(t, configs[0])
	cfg := &tls.Config{RootCAs: ca.roots, ServerName: "a.peer.test", Certificates: []tls.Certificate{configs[1].Certificate}, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", string(server.Raft().LocalAddr()), cfg)
	if err == nil {
		conn.Close()
		t.Fatal("TLS1.2 accepted")
	}
}

func TestHandshakeDeadlineAndAuthenticatedCleanup(t *testing.T) {
	_, configs := fixture(t)
	server := openFixture(t, configs[0])
	stalled, err := net.Dial("tcp", string(server.Raft().LocalAddr()))
	if err != nil {
		t.Fatal(err)
	}
	defer stalled.Close()
	assertSocketClosed(t, stalled)
	client := openFixture(t, configs[1])
	conn, err := client.layer.Dial(server.Raft().LocalAddr(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	server.Close()
	assertSocketClosed(t, conn)
}

func TestPooledRPCConnectionsClosed(t *testing.T) {
	_, configs := fixture(t)
	server, client := openFixture(t, configs[0]), openFixture(t, configs[1])
	serveVotes(t, server)
	assertVote(t, client, "a", server.Raft().LocalAddr())
	client.Close()
	client.layer.mu.Lock()
	remaining := len(client.layer.connections)
	client.layer.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("Close retained %d connections", remaining)
	}
	if err := vote(client, "a", server.Raft().LocalAddr()); err == nil {
		t.Fatal("closed transport accepted RPC")
	}
}

func assertSocketClosed(t *testing.T, conn net.Conn) {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(time.Second))
	_, err := conn.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("connection remained usable")
	}
	if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("connection was not closed within bound")
	}
}
