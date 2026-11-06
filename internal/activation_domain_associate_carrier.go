// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

// DomainAssociateCarrierPolicy is protected configuration, never caller data.
// Presence opts into a reviewed single-node business/graph identity contract.
type DomainAssociateCarrierPolicy struct {
	ContractRevision string   `json:"contractRevision"`
	Family           string   `json:"family"`
	NativeKind       string   `json:"nativeKind"`
	LabelField       string   `json:"labelField"`
	NullLabel        *string  `json:"nullLabel"`
	InitialRoleIDs   []string `json:"initialRoleIds"`
}
