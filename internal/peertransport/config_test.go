package peertransport

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/hashicorp/raft"
)

type configMutation func(*Config, authority, *testing.T)

func invalidMutations() map[string]configMutation {
	return map[string]configMutation{
		"missing ID":          func(c *Config, _ authority, _ *testing.T) { c.LocalID = "" },
		"unknown local":       func(c *Config, _ authority, _ *testing.T) { c.LocalID = "unknown" },
		"missing roots":       func(c *Config, _ authority, _ *testing.T) { c.Roots = nil },
		"empty roots":         func(c *Config, _ authority, _ *testing.T) { c.Roots = x509.NewCertPool() },
		"missing certificate": func(c *Config, _ authority, _ *testing.T) { c.Certificate.Certificate = nil },
		"missing key":         func(c *Config, _ authority, _ *testing.T) { c.Certificate.PrivateKey = nil },
		"wrong key": func(c *Config, a authority, t *testing.T) {
			c.Certificate.PrivateKey = a.issue(t, []string{"a.peer.test"}, false).PrivateKey
		},
		"wrong local SAN": func(c *Config, a authority, t *testing.T) { c.Certificate = a.issue(t, []string{"b.peer.test"}, false) },
		"expired local":   func(c *Config, a authority, t *testing.T) { c.Certificate = a.issue(t, []string{"a.peer.test"}, true) },
		"untrusted local": func(c *Config, _ authority, t *testing.T) {
			c.Certificate = newAuthority(t).issue(t, []string{"a.peer.test"}, false)
		},
		"wildcard local": func(c *Config, a authority, t *testing.T) { c.Certificate = a.issue(t, []string{"*.peer.test"}, false) },
		"ambiguous local": func(c *Config, a authority, t *testing.T) {
			c.Certificate = a.issue(t, []string{"a.peer.test", "b.peer.test"}, false)
		},
		"duplicate DNS": func(c *Config, _ authority, _ *testing.T) {
			p := c.Peers["b"]
			p.DNSName = c.Peers["a"].DNSName
			c.Peers["b"] = p
		},
		"duplicate address": func(c *Config, _ authority, _ *testing.T) {
			p := c.Peers["b"]
			p.Address = c.Peers["a"].Address
			c.Peers["b"] = p
		},
		"wildcard DNS": func(c *Config, _ authority, _ *testing.T) {
			p := c.Peers["b"]
			p.DNSName = "*.peer.test"
			c.Peers["b"] = p
		},
		"uppercase DNS": func(c *Config, _ authority, _ *testing.T) {
			p := c.Peers["b"]
			p.DNSName = "B.peer.test"
			c.Peers["b"] = p
		},
		"bad address": func(c *Config, _ authority, _ *testing.T) {
			p := c.Peers["b"]
			p.Address = raft.ServerAddress("127.0.0.1:0")
			c.Peers["b"] = p
		},
		"bad listen":        func(c *Config, _ authority, _ *testing.T) { c.ListenAddress = "invalid" },
		"zero timeout":      func(c *Config, _ authority, _ *testing.T) { c.Timeout = 0 },
		"unbounded timeout": func(c *Config, _ authority, _ *testing.T) { c.Timeout = time.Hour },
		"zero pool":         func(c *Config, _ authority, _ *testing.T) { c.MaxPool = 0 },
		"unbounded pool":    func(c *Config, _ authority, _ *testing.T) { c.MaxPool = 65 },
	}
}

func TestInvalidConfigurations(t *testing.T) {
	for name, mutate := range invalidMutations() {
		t.Run(name, func(t *testing.T) { rejectConfiguration(t, mutate) })
	}
}
func rejectConfiguration(t *testing.T, mutate func(*Config, authority, *testing.T)) {
	t.Helper()
	ca, configs := fixture(t)
	mutate(&configs[0], ca, t)
	transport, err := Open(configs[0])
	if err == nil {
		transport.Close()
		t.Fatal("invalid configuration accepted")
	}
	if err != ErrConfig {
		t.Fatalf("unsanitized config error: %v", err)
	}
}
