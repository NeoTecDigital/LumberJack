// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"math"
)

func domainFinite(value float64) bool { return !math.IsNaN(value) && !math.IsInf(value, 0) }

func domainV2(owned DomainOwnedScope) bool {
	return owned.Layout.ContractRevision == "manifest-associates/0.2"
}

func namespaceEqual(original, current *DomainResolutionNamespace) bool {
	if original == nil || current == nil {
		return original == nil && current == nil
	}
	copy := *original
	copy.CheckedAt, copy.ValidUntil = current.CheckedAt, current.ValidUntil
	return domainEqual(copy, *current)
}

type domainResultError struct{ cause error }

func (e domainResultError) Error() string {
	if e.cause != nil {
		return "enrollment unavailable: " + e.cause.Error()
	}
	return "enrollment response exceeds configured bound"
}

func (e domainResultError) Unwrap() error { return e.cause }

// The native ABI consumes the same closed JSON grammar as the direct API.
func (s *Server) DomainEnrollJSON(ctx context.Context, raw []byte) (DomainBegin, error) {
	d, err := s.domainEngine()
	if err != nil {
		return DomainBegin{}, err
	}
	input, err := DecodeEnrollmentInput(raw, d.config.MaxRequestBytes)
	if err != nil {
		return DomainBegin{}, err
	}
	return s.DomainEnroll(ctx, input)
}
