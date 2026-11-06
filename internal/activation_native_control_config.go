// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"time"
)

// Setup is private, explicit, once-only and on the SAME actual Server/forest.
func (s *Server) ConfigureNativeControl(raw []byte) (map[string]interface{}, error) {
	s.sourceFence().requireFencing()
	p := s.personalSource.Load()
	if p == nil {
		return nil, sourceUnavailable()
	}
	var config NativeControlConfig
	if sourceDecode(raw, &config, p.config.Bounds) != nil || validateNativeConfigBytes(raw, config) != nil {
		return nil, sourceInvalid()
	}
	runtime, err := p.prepareNativeControl(config)
	if err != nil {
		return nil, err
	}
	permit, err := p.coordinator.beginWrite(context.Background(), "native-control-configure")
	if err != nil {
		return nil, err
	}
	defer permit.noEffect(true)
	s.forestMutex.Lock()
	defer s.forestMutex.Unlock()
	p.mu.Lock()
	defer p.mu.Unlock()
	if s.nativeControl.Load() != nil || len(p.controls)+len(p.entries)+len(p.candidates) != 0 {
		return nil, sourceDenied()
	}
	selected := nativeJWTConfig(config.JWT)
	if !nativeJWTAbsent(s.jwtConfig) && !nativeJWTEqual(s.jwtConfig, selected) {
		return nil, sourceDenied()
	}
	s.jwtConfig = selected
	s.nativeControl.Store(runtime)
	return map[string]interface{}{"configured": true, "epoch": p.epoch, "sealKeyId": config.Seal.KeyID, "sealPublicKey": base64.StdEncoding.EncodeToString(runtime.publicKey)}, nil
}
func (p *personalSource) prepareNativeControl(c NativeControlConfig) (*nativeControlRuntime, error) {
	if c.ContractRevision != NativeCanonicalRevision || c.Epoch != p.epoch || c.HostID != p.config.HostID || c.SourceAuthorityRef != p.config.SourceAuthorityRef || c.SourcePolicyRevision != p.config.SourcePolicyRevision {
		return nil, sourceDenied()
	}
	if validateStagedIdentifiers(p.config.StagedBounds, c.Epoch, c.HostID, c.SourceAuthorityRef, c.SourcePolicyRevision, c.Seal.KeyID) != nil || p.config.StagedBounds.MaxIdentifierBytes < 114 {
		return nil, sourceInvalid()
	}
	if c.MappingCallback.ChannelToken == p.config.ControlToken || c.MappingCallback.ChannelToken == p.config.CoreCallback.ChannelToken {
		return nil, sourceInvalid()
	}
	clone := p.config
	clone.CoreCallback = c.MappingCallback
	if validatePersonalSourceConfig(clone) != nil {
		return nil, sourceInvalid()
	}
	client, err := sourceCallbackClient(clone)
	if err != nil {
		return nil, err
	}
	seed := append([]byte(nil), c.Seal.PrivateKey...)
	private := ed25519.NewKeyFromSeed(seed)
	return &nativeControlRuntime{c, client, private, append([]byte(nil), private[32:]...)}, nil
}
func validateNativeConfigBytes(raw []byte, c NativeControlConfig) error {
	if c.Seal.Algorithm != "Ed25519" || len(c.Seal.PrivateKey) != ed25519.SeedSize {
		return sourceInvalid()
	}
	t := c.JWT.ExpiresInSeconds
	if !domainFinite(t) || t <= 0 || t >= float64(math.MaxInt64)/float64(time.Second) || float64(time.Duration(t*float64(time.Second)))/float64(time.Second) != t {
		return sourceInvalid()
	}
	var shape struct {
		JWT  map[string]json.RawMessage `json:"jwt"`
		Seal map[string]json.RawMessage `json:"seal"`
	}
	if json.Unmarshal(raw, &shape) != nil {
		return sourceInvalid()
	}
	values := map[string][]byte{"sessionKey": c.JWT.SessionKey, "refreshKey": c.JWT.RefreshKey, "secretKey": c.JWT.SecretKey}
	for key, data := range values {
		if len(data) == 0 || bytes.Equal(data, c.Seal.PrivateKey) || !canonicalNativeBase64(shape.JWT[key], data) {
			return sourceInvalid()
		}
	}
	if !canonicalNativeBase64(shape.Seal["privateKey"], c.Seal.PrivateKey) {
		return sourceInvalid()
	}
	return nil
}
func canonicalNativeBase64(raw json.RawMessage, data []byte) bool {
	var encoded string
	return json.Unmarshal(raw, &encoded) == nil && encoded == base64.StdEncoding.EncodeToString(data)
}
func nativeJWTConfig(c nativeControlJWT) JWTConfig {
	return JWTConfig{append([]byte(nil), c.SessionKey...), append([]byte(nil), c.RefreshKey...), time.Duration(c.ExpiresInSeconds * float64(time.Second)), append([]byte(nil), c.SecretKey...)}
}
func nativeJWTAbsent(c JWTConfig) bool {
	return len(c.SessionKey)+len(c.RefreshKey)+len(c.SecretKey) == 0 && c.ExpiresIn == 0
}
func nativeJWTEqual(a, b JWTConfig) bool {
	return bytes.Equal(a.SessionKey, b.SessionKey) && bytes.Equal(a.RefreshKey, b.RefreshKey) && bytes.Equal(a.SecretKey, b.SecretKey) && a.ExpiresIn == b.ExpiresIn
}
func (c NativeControlConfig) Format(s fmt.State, verb rune) {
	fmt.Fprint(s, "NativeControlConfig{private}")
}
