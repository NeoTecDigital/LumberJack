// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"strings"
	"time"
)

const PersonalSourceSchemaSHA256 = "583acb726b99dc224644258ff968a4ed302713b71243db81eb984238b176d0b0"

type sourceFailure struct{ code string }

func (failure sourceFailure) Error() string { return "private source denied/unavailable" }
func sourceInvalid() error                  { return sourceFailure{"source_invalid"} }
func sourceDenied() error                   { return sourceFailure{"source_denied"} }
func sourceUnavailable() error              { return sourceFailure{"source_unavailable"} }
func PersonalSourceFailure(err error) []byte {
	code := "source_unavailable"
	if carried, ok := err.(sourceFailure); ok {
		code = carried.code
	}
	raw, _ := CanonicalDomainJSON(map[string]interface{}{"error": map[string]string{"code": code, "outcome": "unknown"}})
	return raw
}

// Closed typed publication; missing nullable members are not defaulted to null.
// Bound raw input first, then validate every nested member before typed decoding.
func sourceDecode(raw []byte, target interface{}, bounds PersonalSourceBounds) error {
	if len(raw) == 0 || len(raw) > bounds.MaxRequestBytes {
		return sourceInvalid()
	}
	t := reflect.TypeOf(target)
	if t == nil || t.Kind() != reflect.Ptr {
		return sourceInvalid()
	}
	if err := sourceModelMatch(raw, t.Elem(), bounds.MaxRequestBytes, 0); err != nil {
		return err
	}
	if DecodeDomainJSON(raw, target) != nil {
		return sourceInvalid()
	}
	return nil
}
func sourceModelMatch(raw []byte, t reflect.Type, budget, depth int) error {
	if depth > budget || len(raw) > budget {
		return sourceInvalid()
	}
	if t == reflect.TypeOf(json.RawMessage{}) {
		var value interface{}
		if DecodeDomainJSON(raw, &value) != nil {
			return sourceInvalid()
		}
		return nil
	}
	if t.Kind() == reflect.Ptr {
		if bytes.Equal(raw, []byte("null")) {
			return nil
		}
		return sourceModelMatch(raw, t.Elem(), budget, depth+1)
	}
	switch t.Kind() {
	case reflect.Struct:
		return sourceObjectMatch(raw, t, budget, depth+1)
	case reflect.Slice:
		return sourceArrayMatch(raw, t, budget, depth+1)
	case reflect.String:
		return sourceStringMatch(raw, budget)
	case reflect.Bool:
		if string(raw) != "true" && string(raw) != "false" {
			return sourceInvalid()
		}
	case reflect.Int, reflect.Int64:
		var value int64
		if json.Unmarshal(raw, &value) != nil || string(raw) == "null" || value <= 0 {
			return sourceInvalid()
		}
	case reflect.Float64:
		var value float64
		if json.Unmarshal(raw, &value) != nil || !domainFinite(value) || value <= 0 {
			return sourceInvalid()
		}
	default:
		return sourceInvalid()
	}
	return nil
}
func sourceStringMatch(raw []byte, budget int) error {
	var value string
	if json.Unmarshal(raw, &value) != nil || string(raw) == "null" || len(value) == 0 || len(value) > budget {
		return sourceInvalid()
	}
	return nil
}
func sourceObjectMatch(raw []byte, t reflect.Type, budget, depth int) error {
	var members map[string]json.RawMessage
	if DecodeDomainJSON(raw, &members) != nil || members == nil {
		return sourceInvalid()
	}
	fields := map[string]reflect.Type{}
	sourceModelFields(t, fields)
	if len(members) != len(fields) {
		return sourceInvalid()
	}
	for key, typ := range fields {
		value, present := members[key]
		if !present {
			return sourceInvalid()
		}
		if err := sourceModelMatch(value, typ, budget, depth); err != nil {
			return err
		}
	}
	return nil
}
func sourceModelFields(t reflect.Type, fields map[string]reflect.Type) {
	for index := 0; index < t.NumField(); index++ {
		field := t.Field(index)
		if field.Anonymous {
			sourceModelFields(field.Type, fields)
			continue
		}
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if name != "" && name != "-" {
			fields[name] = field.Type
		}
	}
}
func sourceArrayMatch(raw []byte, t reflect.Type, budget, depth int) error {
	if t.Elem().Kind() == reflect.Uint8 {
		var value []byte
		if json.Unmarshal(raw, &value) != nil || string(raw) == "null" || len(value) > budget {
			return sourceInvalid()
		}
		return nil
	}
	var values []json.RawMessage
	if DecodeDomainJSON(raw, &values) != nil || values == nil || len(values) > budget {
		return sourceInvalid()
	}
	for _, value := range values {
		if err := sourceModelMatch(value, t.Elem(), budget, depth); err != nil {
			return err
		}
	}
	return nil
}
func validatePersonalSourceConfig(config PersonalSourceConfig) error {
	b := config.Bounds
	integers := []int{b.MaxRequestBytes, b.MaxResponseBytes, b.MaxSources, b.MaxBindings, b.MaxContexts, b.MaxResources, b.MaxFields, b.MaxLeases, b.MaxRetainedEpochs}
	for _, value := range integers {
		if value <= 0 {
			return sourceInvalid()
		}
	}
	if !domainFinite(b.LeaseSeconds) || !domainFinite(b.RequestSeconds) || b.LeaseSeconds <= 0 || b.RequestSeconds <= 0 || b.LeaseSeconds >= float64(math.MaxInt64)/1e9 || b.RequestSeconds >= float64(math.MaxInt64)/1e9 {
		return sourceInvalid()
	}
	if config.ContractRevision != PersonalSourceRevision || validateStagedBounds(config.StagedBounds) != nil {
		return sourceInvalid()
	}
	names := []string{config.HostID, config.SourceAuthorityRef, config.SourcePolicyRevision, config.CoreCallback.Issuer, config.CoreCallback.Audience, config.CoreCallback.Endpoint}
	if enrollmentIdentifiers(b.MaxRequestBytes, names...) != nil {
		return sourceInvalid()
	}
	for _, token := range []string{config.ControlToken, config.CoreCallback.ChannelToken} {
		if len(token) < 32 || len(token) > b.MaxRequestBytes || strings.ContainsAny(token, "\r\n") {
			return sourceInvalid()
		}
	}
	if config.ControlToken == config.CoreCallback.ChannelToken {
		return sourceInvalid()
	}
	return nil
}
func validateSourceSubject(value SourceSubjectEvidence, requestID string, bounds PersonalSourceBounds) error {
	if value.RequestID != requestID || value.SessionID == "" || !domainFinite(value.CheckedAt) || !domainFinite(value.ValidUntil) || value.CheckedAt > domainNow() || value.ValidUntil <= domainNow() || domainNow()-value.CheckedAt > bounds.LeaseSeconds {
		return sourceDenied()
	}
	if value.Assurance != "aal1" && value.Assurance != "aal2" {
		return sourceDenied()
	}
	return nil
}
func validateSourceActorGrant(actor SourceActor, grant SourcePersonalGrant, requestID string, bounds PersonalSourceBounds) error {
	if err := validateSourceSubject(actor.Evidence, requestID, bounds); err != nil {
		return err
	}
	if actor.Kind != "human" || actor.SessionID != actor.Evidence.SessionID || grant.State != "active" || actor.PrincipalID != grant.PrincipalID {
		return sourceDenied()
	}
	if grant.Scope.Product != "momentum" || grant.Scope.AccountID != grant.Account.AccountID || grant.Account.AccountType != "personal" || grant.Account.SubjectRef.Kind != "user" || grant.Account.SubjectRef.SubjectID == "" || grant.Account.SubjectRef.SubjectID == actor.PrincipalID || grant.Account.AccountID == actor.PrincipalID || grant.Account.SubjectRef.SubjectID == grant.Account.AccountID {
		return sourceDenied()
	}
	if len(grant.Capabilities) == 0 || len(grant.Capabilities) > bounds.MaxFields || !domainContains(grant.Capabilities, "identity.read") {
		return sourceDenied()
	}
	return nil
}
func sourceResponse(request SourceEnvelope, result interface{}, maximum int) ([]byte, error) {
	raw, err := CanonicalDomainJSON(SourceResponse{request.ContractRevision, request.Action, request.Epoch, request.HostID, request.RequestID, result})
	if err != nil || len(raw) > maximum {
		return nil, sourceUnavailable()
	}
	return raw, nil
}
func (config PersonalSourceConfig) Format(state fmt.State, verb rune) {
	fmt.Fprint(state, "PersonalSourceConfig{private}")
}
func (request SourceEnvelope) Format(state fmt.State, verb rune) {
	fmt.Fprint(state, "SourceEnvelope{private}")
}

type sourceLeaseRecheck struct {
	LeaseRef      SourceLeaseRef `json:"leaseRef"`
	RequestSHA256 string         `json:"requestSha256"`
}
type sourceLeaseRelease struct {
	LeaseRef    SourceLeaseRef `json:"leaseRef"`
	Disposition string         `json:"disposition"`
}
type sourceReleaseAck struct {
	LeaseID string `json:"leaseId"`
	Epoch   string `json:"epoch"`
	State   string `json:"state"`
}

func (s *Server) PersonalSourceEpoch() (string, error) {
	p := s.personalSource.Load()
	if p == nil {
		return "", sourceUnavailable()
	}
	return p.epoch, nil
}
func (s *Server) PersonalSourceRetained() []string {
	p := s.personalSource.Load()
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	ids := []string{}
	for id, entry := range p.entries {
		if !entry.closed {
			ids = append(ids, id)
		}
	}
	for id, entry := range p.candidates {
		if entry.state != "released" {
			ids = append(ids, id)
		}
	}
	return ids
}
func (s *Server) PersonalSourceCall(ctx context.Context, raw []byte) ([]byte, error) {
	p := s.personalSource.Load()
	if p == nil {
		return nil, sourceUnavailable()
	}
	var input SourceEnvelope
	if sourceDecode(raw, &input, p.config.Bounds) != nil {
		return nil, sourceInvalid()
	}
	if err := p.validateEnvelope(input); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(time.Duration((input.ValidUntil - domainNow()) * float64(time.Second)))
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	result, err := p.dispatchSource(ctx, input)
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil || p.validateEnvelope(input) != nil {
		return nil, sourceUnavailable()
	}
	return sourceResponse(input, result, p.config.Bounds.MaxResponseBytes)
}
func (p *personalSource) dispatchSource(ctx context.Context, request SourceEnvelope) (interface{}, error) {
	if request.ContractRevision == NativeCanonicalRevision {
		return p.dispatchCanonical(ctx, request)
	}
	switch request.Action {
	case "control.capture":
		return p.captureControl(request)
	case "consent.establish":
		return p.establishConsent(request)
	case "consent.revoke":
		return p.revokeConsent(ctx, request)
	case "identity.open":
		return p.identityOpen(request, false)
	case "identity.openCurrent":
		return p.identityOpen(request, true)
	case "identity.recheck":
		return p.identityRecheck(request)
	case "binding.open":
		return p.bindingOpen(request)
	case "binding.recheck":
		return p.bindingRecheck(request)
	case "context.resolve":
		return p.resolveContext(request)
	case "resources.open":
		return p.resourcesOpen(request)
	case "resources.recheck":
		return p.resourcesRecheck(request)
	case "lease.recheck":
		return p.leaseRecheck(request)
	case "lease.release":
		return p.leaseRelease(ctx, request)
	case "roots.snapshot":
		return p.rootSnapshot(request)
	case "roots.state":
		return p.rootState(request, false)
	case "roots.recheck":
		return p.rootState(request, true)
	case "roots.close":
		return p.rootClose(ctx, request)
	case "provision.resolve":
		return p.provisionResolve(ctx, request)
	case "provision.admit":
		return p.admitPersonal(ctx, request)
	case "binding.provision":
		return p.executePersonal(ctx, request)
	case "provision.disclose":
		return p.disclosePersonal(ctx, request)
	}
	return nil, sourceInvalid()
}
func (p *personalSource) leaseRecheck(request SourceEnvelope) (interface{}, error) {
	var input sourceLeaseRecheck
	if sourceDecode(request.Payload, &input, p.config.Bounds) != nil {
		return nil, sourceInvalid()
	}
	entry, err := p.lookupEntry(input.LeaseRef, request.RequestID)
	if err != nil || entry.intent == nil || input.RequestSHA256 != entry.intent.RequestSHA256 || entry.read.recheck() != nil {
		return nil, sourceDenied()
	}
	return entry.ref, nil
}
func (p *personalSource) leaseRelease(ctx context.Context, request SourceEnvelope) (interface{}, error) {
	var input sourceLeaseRelease
	if sourceDecode(request.Payload, &input, p.config.Bounds) != nil {
		return nil, sourceInvalid()
	}
	if input.Disposition != "released" && input.Disposition != "refused" && input.Disposition != "unknown" {
		return nil, sourceInvalid()
	}
	entry, err := p.lookupReleaseEntry(input.LeaseRef, request.RequestID)
	if err != nil {
		return nil, err
	}
	if entry.provision != nil && !entry.guard {
		if err = p.releasePersonalSource(ctx, entry, input.Disposition); err != nil {
			return nil, err
		}
		return sourceReleaseAck{entry.ref.LeaseID, p.epoch, "released"}, nil
	}
	if entry.unknown {
		return nil, sourceUnavailable()
	}
	if entry.canonical != nil {
		entry.canonical.cleanupKnown = input.Disposition != "unknown"
		if !entry.canonical.cleanupKnown {
			return nil, sourceUnavailable()
		}
		entry.canonical = nil
	}
	p.closeReadEntry(entry)
	return sourceReleaseAck{entry.ref.LeaseID, p.epoch, "released"}, nil
}
func sourceSubjectSame(left, right SourceSubjectEvidence) bool {
	return left.Issuer == right.Issuer && left.Subject == right.Subject && left.Audience == right.Audience && left.SessionID == right.SessionID && left.Assurance == right.Assurance && left.RequestID == right.RequestID
}
func sourceActorSame(left, right SourceActor) bool {
	return left.PrincipalID == right.PrincipalID && left.Kind == right.Kind && left.SessionID == right.SessionID && sourceSubjectSame(left.Evidence, right.Evidence)
}
func sourceBindingSame(left, right SourceOwnerBinding) bool {
	left.CheckedAt, left.ValidUntil = 0, 0
	right.CheckedAt, right.ValidUntil = 0, 0
	return domainEqual(left, right)
}
