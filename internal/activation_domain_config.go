// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func (s *Server) ConfigureDomain(config DomainConfig, products map[string]DomainProduct, policy DomainPolicy) error {
	s.sourceFence().requireFencing()
	d, err := newDomainEngine(config, products, policy)
	if err != nil {
		return err
	}
	d.source = s.sourceFence()
	s.forestMutex.Lock()
	if s.domain != nil || s.domainConfiguring {
		s.forestMutex.Unlock()
		return fmt.Errorf("domain already configured/configuring")
	}
	s.domainConfiguring = true
	s.forestMutex.Unlock()
	defer func() { s.forestMutex.Lock(); s.domainConfiguring = false; s.forestMutex.Unlock() }()
	for _, owned := range config.Scopes {
		if err = s.configureStagedScope(owned.Binding, owned.Bounds); err != nil {
			return err
		}
	}
	if err = s.restoreDomainRegistry(d); err != nil {
		return err
	}
	s.forestMutex.Lock()
	s.domain = d
	s.forestMutex.Unlock()
	return nil
}
func newDomainEngine(config DomainConfig, products map[string]DomainProduct, policy DomainPolicy) (*domainEngine, error) {
	raw, err := CanonicalDomainJSON(config)
	if err != nil {
		return nil, err
	}
	if err = DecodeDomainJSON(raw, &config); err != nil {
		return nil, err
	}
	ownedProducts := make(map[string]DomainProduct, len(products))
	for name, product := range products {
		ownedProducts[name] = product
	}
	products = ownedProducts
	if err = validateDomainEnginePolicy(config, policy); err != nil {
		return nil, err
	}
	verifier, err := newDomainVerifier(config.Trust)
	if err != nil {
		return nil, err
	}
	config.Trust = verifier.config
	epoch, err := newDomainID()
	if err != nil {
		return nil, err
	}
	d := &domainEngine{config: config, verifier: verifier, policy: policy, products: products, epoch: epoch, scopes: map[DomainScope]DomainOwnedScope{}, entries: map[string]*domainEntry{}, closed: map[DomainGateKey]bool{}, sessionFences: map[enrollmentSessionKey]bool{}}
	if config.ProvisioningProfile != nil {
		owner := policy.(*domainOwnerPolicy)
		d.policy = &domainOwnerPolicy{key: owner.key, sessionFenced: d.actorSessionFenced}
	}
	if err = validateDomainRootMode(config); err != nil {
		return nil, err
	}
	for _, owned := range config.Scopes {
		if err = addDomainScope(d, owned); err != nil {
			return nil, err
		}
	}
	if err = validateDomainCatalogConfig(d); err != nil {
		return nil, err
	}
	return d, nil
}

func domainOwnerTokensValid(config DomainConfig) bool {
	for _, token := range []string{config.ControlToken, config.OwnerControlToken} {
		if len(token) < 32 || strings.ContainsAny(token, "\r\n") {
			return false
		}
	}
	return config.ControlToken != config.OwnerControlToken
}

func newDomainVerifier(config ActivationConfig) (*activationVerifier, error) {
	if len(config.ChannelToken) < 32 || strings.ContainsAny(config.ChannelToken, "\r\n") || config.Audience == "" || config.Issuer == "" || config.TimeoutMs <= 0 || config.MaxProofBytes <= 0 || config.MaxBodyBytes <= 0 || config.MaxResponseBytes <= 0 || config.MaxLifetimeSeconds <= 0 {
		return nil, fmt.Errorf("explicit domain trust/bounds required")
	}
	if config.LocalHumanPreview {
		if err := activationTrustBounds(config); err != nil {
			return nil, err
		}
	}
	endpoint, err := domainVerifierEndpoint(config)
	if err != nil {
		return nil, err
	}
	tlsConfig, err := activationTLS(config)
	if err != nil {
		return nil, err
	}
	if config.TimeoutMs > int64((time.Duration(1<<63-1))/time.Millisecond) || config.MaxLifetimeSeconds > int64((time.Duration(1<<63-1))/time.Second) {
		return nil, fmt.Errorf("domain duration overflow")
	}
	timeout := time.Duration(config.TimeoutMs) * time.Millisecond
	dialer := &net.Dialer{Timeout: timeout}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: tlsConfig, DialContext: dialer.DialContext, TLSHandshakeTimeout: timeout, DisableKeepAlives: true}
	client := &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	config.VerifierEndpoint = endpoint.String()
	return &activationVerifier{config: config, client: client}, nil
}

func domainVerifierEndpoint(config ActivationConfig) (*url.URL, error) {
	if _, err := activationLoopbackMode(config); err != nil {
		return nil, err
	}
	endpoint, err := url.Parse(config.VerifierEndpoint)
	if err != nil || endpoint.Host == "" || endpoint.Path == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return nil, fmt.Errorf("invalid domain verifier endpoint")
	}
	if config.LocalHumanPreview {
		address, err := netip.ParseAddr(endpoint.Hostname())
		port, portErr := strconv.Atoi(endpoint.Port())
		if endpoint.Scheme != "http" || err != nil || !address.IsLoopback() || address.Zone() != "" || portErr != nil || port < 1024 || port > 65535 || endpoint.RawPath != "" || endpoint.ForceQuery || endpoint.Opaque != "" {
			return nil, fmt.Errorf("local human callback must be explicit literal loopback HTTP")
		}
	} else if config.SyntheticLoopbackOnly {
		address := net.ParseIP(endpoint.Hostname())
		if endpoint.Scheme != "http" || address == nil || !address.IsLoopback() {
			return nil, fmt.Errorf("synthetic callback must be literal loopback HTTP")
		}
	} else if endpoint.Scheme != "https" {
		return nil, fmt.Errorf("domain callback requires HTTPS")
	}
	return endpoint, nil
}
func addDomainScope(d *domainEngine, owned DomainOwnedScope) error {
	binding := owned.Binding
	scope := DomainScope{binding.AccountID, binding.ProductID}
	if binding.ProductID == "" || binding.BindingRevision == "" || d.products[binding.ProductID] == nil {
		return fmt.Errorf("product/binding revision/adapter absent")
	}
	if err := validateStagedBounds(owned.Bounds); err != nil {
		return err
	}
	if err := validateStagedIdentifiers(owned.Bounds, binding.ProductID, binding.BindingRevision); err != nil {
		return err
	}
	if _, present := d.scopes[scope]; present {
		return fmt.Errorf("ambiguous native scope binding")
	}
	d.scopes[scope] = owned
	return nil
}
func newDomainID() (string, error) {
	var data [16]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(data[:]), nil
}
func (s *Server) domainEngine() (*domainEngine, error) {
	s.forestMutex.RLock()
	d := s.domain
	s.forestMutex.RUnlock()
	if d == nil {
		return nil, fmt.Errorf("domain admission unconfigured")
	}
	return d, nil
}
func DomainIntentHash(intent DomainIntent) (string, error) {
	data, err := CanonicalDomainJSON(intent)
	return stagedHash(data), err
}

func validateDomainCatalogConfig(d *domainEngine) error {
	used := false
	layouts := append([]DomainOwnedScope(nil), d.config.Scopes...)
	if p := d.config.ProvisioningProfile; p != nil {
		layouts = append(layouts, DomainOwnedScope{Layout: p.Layout})
	}
	for _, owned := range layouts {
		revision := owned.Layout.ContractRevision
		if revision != "" && revision != "manifest-associates/0.1" && revision != "manifest-associates/0.2" {
			return fmt.Errorf("unsupported per-scope product revision")
		}
		if !domainV2(owned) && len(owned.Layout.CatalogRef) != 0 {
			return fmt.Errorf("legacy scope cannot adopt v2 catalog")
		}
		if !domainV2(owned) {
			continue
		}
		used = true
		var ref struct {
			CatalogID      string `json:"catalogId"`
			CatalogVersion string `json:"catalogVersion"`
			CatalogDigest  string `json:"catalogDigest"`
		}
		if DecodeDomainJSON(owned.Layout.CatalogRef, &ref) != nil || ref.CatalogID == "" || ref.CatalogVersion == "" || !domainValidHash(ref.CatalogDigest) || stagedHash(d.config.RoleCatalog) != ref.CatalogDigest {
			return fmt.Errorf("scope/catalog exact-byte pin mismatch")
		}
	}
	if !used && len(d.config.RoleCatalog) != 0 || used && (len(d.config.RoleCatalog) == 0 || len(d.config.RoleCatalog) > d.config.MaxRequestBytes) {
		return fmt.Errorf("explicit bounded v2-only catalog injection required")
	}
	return nil
}

func validateDomainEnginePolicy(config DomainConfig, policy DomainPolicy) error {
	if err := validateIntegrationTrust(config); err != nil {
		return err
	}
	if policy == nil || config.ACLMetadataKey == "" || config.HostID == "" || !domainOwnerTokensValid(config) {
		return fmt.Errorf("explicit native policy/host trust required")
	}
	bounds := []int{config.MaxLeases, config.MaxRetainedEpochs, config.MaxResources, config.MaxFields, config.MaxRequestBytes, config.MaxResponseBytes}
	for _, bound := range bounds {
		if bound <= 0 {
			return fmt.Errorf("explicit finite domain bounds required")
		}
	}
	if err := validateDomainProvisioningProfile(config); err != nil {
		return err
	}
	if config.ProvisioningProfile != nil {
		ownerPolicy, ok := policy.(*domainOwnerPolicy)
		if !ok || ownerPolicy.key != config.ACLMetadataKey {
			return fmt.Errorf("actual standard current native owner ACL policy required")
		}
	}
	return nil
}
