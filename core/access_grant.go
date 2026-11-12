// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package core

// AccessGrant identifies one independent source of access. Policies live on the
// forest; materialized grants live on each included item. Neither is a node view.
type AccessGrant struct {
 ID string `json:"id"`
 RootID string `json:"root_id"`
 ParentID string `json:"parent_id,omitempty"`
 RecipientID string `json:"recipient_id"`
 GrantorID string `json:"grantor_id"`
 Permission Permission `json:"permission"`
 Scope string `json:"scope"`
 TargetIDs []string `json:"target_ids,omitempty"`
 ExpiresAt int64 `json:"expires_at,omitempty"`
}
