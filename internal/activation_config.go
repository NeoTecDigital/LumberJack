// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ActivationConfig is private embedder configuration, never a browser credential.
// No environment/default origin is consulted. Absence leaves external auth disabled.
type ActivationConfig struct {
	VerifierEndpoint      string `json:"verifierEndpoint"`
	ChannelToken          string `json:"channelToken"`
	Audience              string `json:"audience"`
	Issuer                string `json:"issuer"`
	TimeoutMs             int64  `json:"timeoutMs"`
	MaxProofBytes         int    `json:"maxProofBytes"`
	MaxBodyBytes          int64  `json:"maxBodyBytes"`
	MaxResponseBytes      int64  `json:"maxResponseBytes"`
	MaxLifetimeSeconds    int64  `json:"maxLifetimeSeconds"`
	SyntheticLoopbackOnly bool   `json:"syntheticLoopbackOnly"`
	LocalHumanPreview     bool   `json:"localHumanPreview,omitempty"`
	ServerName            string `json:"serverName,omitempty"`
	TrustedCAPem          string `json:"trustedCAPem,omitempty"`
}

type activationVerifier struct {
	config ActivationConfig
	client *http.Client
}

func activationEndpoint(config ActivationConfig) (*url.URL, error) {
	loopback, err := activationLoopbackMode(config)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(config.VerifierEndpoint)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "/activation/verify" || u.RawPath != "" {
		return nil, fmt.Errorf("invalid Activation verifier endpoint")
	}
	if config.LocalHumanPreview && u.ForceQuery {
		return nil, fmt.Errorf("invalid local human verifier query")
	}
	ip, err := netip.ParseAddr(u.Hostname())
	port, portErr := strconv.Atoi(u.Port())
	if err != nil || ip.Zone() != "" || portErr != nil || u.Port() == "" || port < 1 || port > 65535 {
		return nil, fmt.Errorf("Activation requires an explicit literal IP and port")
	}
	if loopback {
		if u.Scheme != "http" || !ip.IsLoopback() || port < 1024 {
			return nil, fmt.Errorf("invalid explicit loopback endpoint")
		}
	} else if u.Scheme != "https" {
		return nil, fmt.Errorf("Activation requires verified TLS")
	}
	return u, nil
}

func activationTLS(config ActivationConfig) (*tls.Config, error) {
	loopback, err := activationLoopbackMode(config)
	if err != nil {
		return nil, err
	}
	if loopback {
		return nil, nil
	}
	roots := x509.NewCertPool()
	if config.ServerName == "" || !roots.AppendCertsFromPEM([]byte(config.TrustedCAPem)) {
		return nil, fmt.Errorf("Activation requires explicit TLS server name and CA trust")
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, ServerName: config.ServerName, RootCAs: roots}, nil
}

func activationLoopbackMode(config ActivationConfig) (bool, error) {
	if config.SyntheticLoopbackOnly && config.LocalHumanPreview {
		return false, fmt.Errorf("Activation loopback modes are mutually exclusive")
	}
	return config.SyntheticLoopbackOnly || config.LocalHumanPreview, nil
}

func activationTrustBounds(config ActivationConfig) error {
	if len(config.ChannelToken) < 32 || strings.TrimSpace(config.ChannelToken) == "" || strings.ContainsAny(config.ChannelToken, "\r\n") || strings.TrimSpace(config.Audience) == "" || strings.TrimSpace(config.Issuer) == "" || config.TimeoutMs < 1 || config.TimeoutMs > 60000 ||
		config.MaxProofBytes < 43 || config.MaxProofBytes > 1<<20 || config.MaxBodyBytes < 1 || config.MaxBodyBytes > applicationLimit ||
		config.MaxResponseBytes < 1 || config.MaxResponseBytes > applicationLimit || config.MaxLifetimeSeconds < 1 || config.MaxLifetimeSeconds > 3600 {
		return fmt.Errorf("explicit bounded Activation trust and limits are required")
	}
	return nil
}

func newActivationVerifier(config ActivationConfig) (*activationVerifier, error) {
	if err := activationTrustBounds(config); err != nil {
		return nil, err
	}
	endpoint, err := activationEndpoint(config)
	if err != nil {
		return nil, err
	}
	tlsConfig, err := activationTLS(config)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: time.Duration(config.TimeoutMs) * time.Millisecond}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: tlsConfig, DialContext: dialer.DialContext,
		TLSHandshakeTimeout: time.Duration(config.TimeoutMs) * time.Millisecond, DisableKeepAlives: true}
	client := &http.Client{Transport: transport, Timeout: time.Duration(config.TimeoutMs) * time.Millisecond,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	config.VerifierEndpoint = endpoint.String()
	return &activationVerifier{config: config, client: client}, nil
}

func ValidateActivationConfig(config ActivationConfig) error {
	_, err := newActivationVerifier(config)
	return err
}

func (s *Server) ConfigureActivation(config ActivationConfig) error {
	verifier, err := newActivationVerifier(config)
	if err != nil {
		return err
	}
	if !s.activation.CompareAndSwap(nil, verifier) {
		return fmt.Errorf("Activation already configured")
	}
	return nil
}
