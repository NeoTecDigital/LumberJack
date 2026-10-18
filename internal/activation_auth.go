// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

const activationEmptyDigest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

type activationContextKey struct{}

func isActivationRequest(headers http.Header) bool {
	for _, value := range headers.Values("Authorization") {
		if strings.HasPrefix(strings.TrimSpace(value), "Activation") {
			return true
		}
	}
	return false
}

func invalidActivationHeaders(headers map[string]string) bool {
	h := make(http.Header)
	for key, value := range headers {
		h.Add(key, value)
	}
	if !isActivationRequest(h) {
		return false
	}
	_, ok := activationProof(h, 1<<20)
	return !ok
}

func activationProof(headers http.Header, limit int) (string, bool) {
	values := headers.Values("Authorization")
	if len(values) != 1 || len(headers.Values("Cookie")) != 0 || len(headers.Values("Proxy-Authorization")) != 0 {
		return "", false
	}
	proof, ok := strings.CutPrefix(values[0], "Activation ")
	if !ok || proof == "" || len(proof) > limit {
		return "", false
	}
	for _, c := range proof {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return "", false
		}
	}
	return proof, true
}

func activationWriteFailure(w http.ResponseWriter, failure activationFailure) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(failure.status)
	_ = json.NewEncoder(w).Encode(failure)
}

func activationApplicationError(status int, code string) ApplicationResponse {
	body, _ := json.Marshal(activationFailure{Code: code})
	return ApplicationResponse{Status: status, Headers: map[string]string{"Content-Type": "application/json", "Cache-Control": "no-store"}, Body: body}
}

func (s *Server) serveActivation(next http.HandlerFunc, w http.ResponseWriter, r *http.Request) {
	verifier := s.activation.Load()
	if verifier == nil {
		activationWriteFailure(w, activationFailure{"handoff_unavailable", 503})
		return
	}
	input, failure := verifier.requestBinding(r)
	if failure.Code != "" {
		activationWriteFailure(w, failure)
		return
	}
	actor, failure := verifier.check(r, input)
	if failure.Code != "" {
		activationWriteFailure(w, failure)
		return
	}
	if r.Context().Err() != nil {
		activationWriteFailure(w, activationFailure{"handoff_unavailable", 503})
		return
	}
	ctx, cancel := context.WithDeadline(r.Context(), timeFromActivationExpiry(actor.ExpiresAt))
	defer cancel()
	next.ServeHTTP(w, r.WithContext(context.WithValue(ctx, activationContextKey{}, actor)))
}

func (v *activationVerifier) requestBinding(r *http.Request) (activationCheck, activationFailure) {
	proof, ok := activationProof(r.Header, v.config.MaxProofBytes)
	if !ok {
		return activationCheck{}, activationFailure{"unauthenticated", 401}
	}
	target := r.URL.RequestURI()
	if r.Method != "GET" || target != "/principal" && target != "/activation/probe" {
		return activationCheck{}, activationFailure{"access_denied", 403}
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, v.config.MaxBodyBytes+1))
	if err != nil || int64(len(body)) > v.config.MaxBodyBytes {
		return activationCheck{}, activationFailure{"invalid_request", 422}
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	digest := sha256.Sum256(body)
	phase := "execute"
	if target == "/principal" {
		phase = "preflight"
	}
	return activationCheck{proof, phase, r.Method, target, hex.EncodeToString(digest[:]), v.config.Audience}, activationFailure{}
}
