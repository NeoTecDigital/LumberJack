// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"fmt"
	"strings"
)

func validateIntegrationTrust(config DomainConfig) error {
	if config.IntegrationIssuer == "" {
		return nil
	}
	if !strings.HasPrefix(config.IntegrationIssuer, "channel-integration:") || config.IntegrationIssuer == config.Trust.Issuer || strings.ContainsAny(config.IntegrationIssuer, "\r\n") {
		return fmt.Errorf("explicit distinct registered integration issuer required")
	}
	return nil
}

// Accepted only from the private CURRENT verifier callback, never a request DTO.
type DomainIntegrationActor struct {
	IntegrationID        string  `json:"integration_id"`
	ConnectorID          string  `json:"connector_id"`
	MessageID            string  `json:"message_id"`
	MessageHash          string  `json:"message_hash"`
	EffectiveAssociateID *string `json:"effective_associate_id"`
	CredentialRevision   string  `json:"credential_revision"`
	PolicyRevision       string  `json:"policy_revision"`
	RosterRevision       string  `json:"roster_revision"`
	SenderPhone          string  `json:"sender_phone"`
}

func (d *domainEngine) validDomainActorKind(actor DomainVerified) bool {
	if actor.Kind == "human" {
		return actor.Issuer == d.config.Trust.Issuer && actor.IntegrationActor == nil
	}
	if actor.Kind != "integration_actor" || actor.IntegrationActor == nil || d.config.IntegrationIssuer == "" {
		return false
	}
	if actor.Issuer != d.config.IntegrationIssuer || !strings.HasPrefix(actor.SessionID, "channel-message:") {
		return false
	}
	profile := actor.IntegrationActor
	values := []string{profile.IntegrationID, profile.ConnectorID, profile.MessageID, profile.MessageHash, profile.CredentialRevision, profile.PolicyRevision, profile.RosterRevision, profile.SenderPhone}
	for _, value := range values {
		if value == "" {
			return false
		}
	}
	for _, char := range profile.SenderPhone {
		if char < '0' || char > '9' {
			return false
		}
	}
	if !domainValidHash(profile.MessageHash) || actor.AuthorityResourceRevision != profile.PolicyRevision {
		return false
	}
	if profile.EffectiveAssociateID == nil {
		return actor.PrincipalID == "office-intake:"+profile.IntegrationID
	}
	return *profile.EffectiveAssociateID != "" && actor.PrincipalID == "associate:"+*profile.EffectiveAssociateID
}
