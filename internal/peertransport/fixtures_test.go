package peertransport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/hashicorp/raft"
)

type authority struct {
	cert  *x509.Certificate
	key   *ecdsa.PrivateKey
	roots *x509.CertPool
}

func newAuthority(t *testing.T) authority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "disposable test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return authority{cert, key, roots}
}
func (a authority) issue(t *testing.T, names []string, expired bool) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: serial, DNSNames: names, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	if expired {
		template.NotAfter = now.Add(-time.Minute)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.cert, &key.PublicKey, a.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func reserveAddress(t *testing.T) raft.ServerAddress {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := raft.ServerAddress(listener.Addr().String())
	listener.Close()
	return address
}
func fixture(t *testing.T) (authority, []Config) {
	t.Helper()
	ca := newAuthority(t)
	peers := map[raft.ServerID]Peer{}
	for _, id := range []raft.ServerID{"a", "b", "c"} {
		peers[id] = Peer{Address: reserveAddress(t), DNSName: string(id) + ".peer.test"}
	}
	configs := []Config{}
	for _, id := range []raft.ServerID{"a", "b", "c"} {
		configs = append(configs, Config{LocalID: id, ListenAddress: string(peers[id].Address), Peers: peers, Certificate: ca.issue(t, []string{peers[id].DNSName}, false), Roots: ca.roots, Timeout: 300 * time.Millisecond, MaxPool: 2})
	}
	return ca, configs
}
func openFixture(t *testing.T, c Config) *Transport {
	t.Helper()
	transport, err := Open(c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { transport.Close() })
	return transport
}
func serveVotes(t *testing.T, transport *Transport) {
	t.Helper()
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	go voteServerLoop(transport.Raft().Consumer(), done)
}
func voteServerLoop(consumer <-chan raft.RPC, done <-chan struct{}) {
	for {
		select {
		case rpc := <-consumer:
			rpc.Respond(&raft.RequestVoteResponse{Term: 1, Granted: true}, nil)
		case <-done:
			return
		}
	}
}

func vote(from *Transport, id raft.ServerID, address raft.ServerAddress) error {
	return from.Raft().RequestVote(id, address, &raft.RequestVoteRequest{Term: 1}, &raft.RequestVoteResponse{})
}
