// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"time"
)

// Mirrors the private backend-owned native-callback/0.1 schema. No actor is submitted.
type activationCheck struct {
	Proof      string `json:"proof"`
	Phase      string `json:"phase"`
	Method     string `json:"method"`
	Target     string `json:"target"`
	BodySHA256 string `json:"bodySha256"`
	Audience   string `json:"audience"`
}
type activationScope struct {
	AccountID   string  `json:"accountId"`
	Product     string  `json:"product"`
	WorkspaceID *string `json:"workspaceId,omitempty"`
}
type activationActor struct {
	PrincipalID      string          `json:"principalId"`
	Kind             string          `json:"kind"`
	SessionID        string          `json:"sessionId"`
	Scope            activationScope `json:"scope"`
	GrantRevision    string          `json:"grantRevision"`
	ResourceRevision string          `json:"resourceRevision"`
	ExpiresAt        float64         `json:"expiresAt"`
	Method           string          `json:"method"`
	Target           string          `json:"target"`
	BodySHA256       string          `json:"bodySha256"`
	Audience         string          `json:"audience"`
	Issuer           string          `json:"issuer"`
	Resource         struct {
		Kind       string `json:"kind"`
		ResourceID string `json:"resourceId"`
	} `json:"resource"`
	Action string   `json:"action"`
	Fields []string `json:"fields"`
}
type activationFailure struct {
	Code   string `json:"code"`
	status int
}

func strictActivationJSON(body []byte, target any) error {
	if err := checkActivationJSON(body); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func (v *activationVerifier) check(r *http.Request, input activationCheck) (activationActor, activationFailure) {
	body, _ := json.Marshal(input)
	req, err := http.NewRequestWithContext(r.Context(), "POST", v.config.VerifierEndpoint, bytes.NewReader(body))
	if err != nil {
		return activationActor{}, activationFailure{"handoff_unavailable", 503}
	}
	req.Header.Set("Authorization", "Bearer "+v.config.ChannelToken)
	req.Header.Set("Content-Type", "application/json")
	response, err := v.client.Do(req)
	if err != nil {
		return activationActor{}, activationFailure{"handoff_unavailable", 503}
	}
	defer response.Body.Close()
	answer, err := io.ReadAll(io.LimitReader(response.Body, v.config.MaxResponseBytes+1))
	if err != nil || int64(len(answer)) > v.config.MaxResponseBytes {
		return activationActor{}, activationFailure{"handoff_unavailable", 503}
	}
	if response.StatusCode != 200 {
		return activationActor{}, callbackFailure(response.StatusCode, answer)
	}
	var actor activationActor
	if strictActivationJSON(answer, &actor) != nil || !v.validActor(actor, input) {
		return activationActor{}, activationFailure{"handoff_unavailable", 503}
	}
	return actor, activationFailure{}
}

func (v *activationVerifier) validActor(actor activationActor, input activationCheck) bool {
	now := float64(time.Now().UnixNano()) / 1e9
	if actor.PrincipalID == "" || actor.Kind != "human" || actor.SessionID == "" || actor.Scope.AccountID == "" || actor.Scope.Product != "manifest" ||
		actor.GrantRevision == "" || actor.ResourceRevision == "" || actor.Audience != v.config.Audience || actor.Issuer != v.config.Issuer ||
		actor.ExpiresAt <= now || actor.ExpiresAt > now+float64(v.config.MaxLifetimeSeconds) || actor.Method != "GET" || actor.Target != "/activation/probe" ||
		actor.BodySHA256 != activationEmptyDigest || actor.Resource.Kind != "principal" || actor.Resource.ResourceID != actor.PrincipalID ||
		actor.Action != "identity.read" || len(actor.Fields) != 2 || actor.Fields[0] != "principalId" || actor.Fields[1] != "kind" {
		return false
	}
	if actor.Scope.WorkspaceID != nil && *actor.Scope.WorkspaceID == "" {
		return false
	}
	return input.Phase == "preflight" || actor.Method == input.Method && actor.Target == input.Target && actor.BodySHA256 == input.BodySHA256
}

func callbackFailure(status int, body []byte) activationFailure {
	var failure activationFailure
	if strictActivationJSON(body, &failure) != nil {
		return activationFailure{"handoff_unavailable", 503}
	}
	allowed := map[string]int{"unauthenticated": 401, "session_expired": 401, "session_revoked": 401,
		"access_denied": 403, "access_revoked": 403, "invalid_request": 422,
		"authority_unavailable": 503, "data_unavailable": 503, "handoff_unavailable": 503}
	if expected, ok := allowed[failure.Code]; ok && expected == status {
		failure.status = status
		return failure
	}
	return activationFailure{"handoff_unavailable", 503}
}
