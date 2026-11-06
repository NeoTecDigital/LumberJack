package peertransport

import (
	"crypto/tls"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/raft"
)

type stream struct {
	net.Listener
	config      Config
	server      *tls.Config
	mu          sync.Mutex
	closed      bool
	connections map[*trackedConn]struct{}
}
type advertisedAddr string

func (a advertisedAddr) Network() string { return "tcp" }
func (a advertisedAddr) String() string  { return string(a) }
func (s *stream) Addr() net.Addr         { return advertisedAddr(s.config.Peers[s.config.LocalID].Address) }

func newStream(c Config) (*stream, error) {
	listener, err := net.Listen("tcp", c.ListenAddress)
	if err != nil {
		return nil, ErrConfig
	}
	s := &stream{Listener: listener, config: c, connections: map[*trackedConn]struct{}{}}
	s.server = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{c.Certificate}, ClientCAs: c.Roots, ClientAuth: tls.RequireAndVerifyClientCert, SessionTicketsDisabled: true, VerifyConnection: s.verifyClient}
	return s, nil
}

func (s *stream) verifyClient(state tls.ConnectionState) error {
	if len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 {
		return ErrPeer
	}
	name := identity(state.PeerCertificates[0])
	for id, peer := range s.config.Peers {
		if id != s.config.LocalID && name != "" && peer.DNSName == name {
			return nil
		}
	}
	return ErrPeer
}

func (s *stream) Accept() (net.Conn, error) {
	for {
		raw, err := s.Listener.Accept()
		if err != nil {
			return nil, err
		}
		conn, err := s.track(raw)
		if err != nil {
			return nil, err
		}
		secure := tls.Server(conn, s.server)
		if err := handshake(secure, s.config.Timeout); err != nil {
			conn.Close()
			continue
		}
		return secure, nil
	}
}

func (s *stream) Dial(address raft.ServerAddress, timeout time.Duration) (net.Conn, error) {
	name := ""
	for id, peer := range s.config.Peers {
		if id != s.config.LocalID && peer.Address == address {
			name = peer.DNSName
		}
	}
	if name == "" || timeout <= 0 {
		return nil, ErrPeer
	}
	if timeout > s.config.Timeout {
		timeout = s.config.Timeout
	}
	deadline := time.Now().Add(timeout)
	raw, err := net.DialTimeout("tcp", string(address), timeout)
	if err != nil {
		return nil, ErrPeer
	}
	conn, err := s.track(raw)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{s.config.Certificate}, RootCAs: s.config.Roots, ServerName: name}
	cfg.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 || identity(state.PeerCertificates[0]) != name {
			return ErrPeer
		}
		return nil
	}
	secure := tls.Client(conn, cfg)
	if err := handshake(secure, time.Until(deadline)); err != nil {
		conn.Close()
		return nil, ErrPeer
	}
	return secure, nil
}

func handshake(conn *tls.Conn, timeout time.Duration) error {
	if timeout <= 0 {
		return ErrPeer
	}
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return ErrPeer
	}
	if err := conn.Handshake(); err != nil {
		return ErrPeer
	}
	return conn.SetDeadline(time.Time{})
}

func (s *stream) track(raw net.Conn) (*trackedConn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		raw.Close()
		return nil, net.ErrClosed
	}
	conn := &trackedConn{Conn: raw, owner: s}
	s.connections[conn] = struct{}{}
	return conn, nil
}

func (s *stream) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	connections := make([]*trackedConn, 0, len(s.connections))
	for conn := range s.connections {
		connections = append(connections, conn)
	}
	s.mu.Unlock()
	s.Listener.Close()
	for _, conn := range connections {
		conn.Close()
	}
	return nil
}

type trackedConn struct {
	net.Conn
	owner *stream
	once  sync.Once
	err   error
}

func (c *trackedConn) Close() error {
	c.once.Do(func() {
		c.err = c.Conn.Close()
		c.owner.mu.Lock()
		delete(c.owner.connections, c)
		c.owner.mu.Unlock()
	})
	return c.err
}
