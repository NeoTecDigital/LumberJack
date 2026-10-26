// Package peertransport provides explicitly configured mutual-TLS Raft streams.
package peertransport

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/raft"
)

var ErrConfig = errors.New("peertransport: invalid configuration")
var ErrPeer = errors.New("peertransport: peer refused")

type Peer struct {
	Address raft.ServerAddress
	DNSName string
}
type Config struct {
	LocalID       raft.ServerID
	ListenAddress string
	Peers         map[raft.ServerID]Peer
	Certificate   tls.Certificate
	Roots         *x509.CertPool
	Timeout       time.Duration
	MaxPool       int
}

func prepare(c Config) (Config, error) {
	if c.LocalID == "" || c.Roots == nil || len(c.Roots.Subjects()) == 0 || c.Timeout <= 0 || c.Timeout > time.Minute || c.MaxPool < 1 || c.MaxPool > 64 {
		return Config{}, ErrConfig
	}
	if _, _, err := net.SplitHostPort(c.ListenAddress); err != nil {
		return Config{}, ErrConfig
	}
	peers := make(map[raft.ServerID]Peer, len(c.Peers))
	names, addresses := map[string]bool{}, map[raft.ServerAddress]bool{}
	for id, p := range c.Peers {
		if id == "" || !validDNS(p.DNSName) || names[p.DNSName] || addresses[p.Address] {
			return Config{}, ErrConfig
		}
		if !validAddress(p.Address) {
			return Config{}, ErrConfig
		}
		names[p.DNSName], addresses[p.Address], peers[id] = true, true, p
	}
	local, ok := peers[c.LocalID]
	if !ok {
		return Config{}, ErrConfig
	}
	cert, err := cloneCertificate(c.Certificate)
	if err != nil {
		return Config{}, ErrConfig
	}
	c.Peers, c.Roots, c.Certificate = peers, c.Roots.Clone(), cert
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil || identity(leaf) != local.DNSName {
		return Config{}, ErrConfig
	}
	for _, usage := range []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth} {
		if err := verifyLeaf(leaf, cert.Certificate[1:], c.Roots, local.DNSName, usage); err != nil {
			return Config{}, ErrConfig
		}
	}
	return c, nil
}

func validDNS(s string) bool {
	if len(s) == 0 || len(s) > 253 || s != strings.ToLower(s) || net.ParseIP(s) != nil {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if !validLabel(label) {
			return false
		}
	}
	return true
}

func validLabel(label string) bool {
	if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, ch := range label {
		if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
			return false
		}
	}
	return true
}

func identity(cert *x509.Certificate) string {
	if cert == nil || len(cert.DNSNames) != 1 || len(cert.IPAddresses) != 0 || len(cert.URIs) != 0 || len(cert.EmailAddresses) != 0 {
		return ""
	}
	if !validDNS(cert.DNSNames[0]) {
		return ""
	}
	return cert.DNSNames[0]
}

func verifyLeaf(leaf *x509.Certificate, chain [][]byte, roots *x509.CertPool, name string, usage x509.ExtKeyUsage) error {
	intermediates := x509.NewCertPool()
	for _, der := range chain {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return ErrPeer
		}
		intermediates.AddCert(cert)
	}
	_, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: name, KeyUsages: []x509.ExtKeyUsage{usage}})
	return err
}

func cloneCertificate(c tls.Certificate) (tls.Certificate, error) {
	if len(c.Certificate) == 0 || c.PrivateKey == nil {
		return tls.Certificate{}, ErrConfig
	}
	der, err := x509.MarshalPKCS8PrivateKey(c.PrivateKey)
	if err != nil {
		return tls.Certificate{}, ErrConfig
	}
	var certPEM []byte
	for _, b := range c.Certificate {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b})...)
	}

	return tls.X509KeyPair(certPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func validAddress(address raft.ServerAddress) bool {
	host, port, err := net.SplitHostPort(string(address))
	if err != nil || host == "" {
		return false
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return !ip.IsUnspecified()
	}
	return validDNS(host)
}
