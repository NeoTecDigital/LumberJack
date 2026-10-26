// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"github.com/NeoTecDigital/LumberJack/internal/core"
	"sort"
)

type SourceOwnedContext struct {
	RuntimeID          string  `json:"runtimeId"`
	RootID             string  `json:"rootId"`
	NodeID             string  `json:"nodeId"`
	NativeOwnerID      string  `json:"nativeOwnerId"`
	AccountID          string  `json:"accountId"`
	Product            string  `json:"product"`
	WorkspaceID        *string `json:"workspaceId"`
	BindingRevision    string  `json:"bindingRevision"`
	SourceAuthorityRef string  `json:"sourceAuthorityRef"`
	SourceRevision     string  `json:"sourceRevision"`
	LineageRevision    string  `json:"lineageRevision"`
	ACLRevision        string  `json:"aclRevision"`
	PolicyRevision     string  `json:"policyRevision"`
	CheckedAt          float64 `json:"checkedAt"`
	ValidUntil         float64 `json:"validUntil"`
}
type sourceOriginalRequest struct {
	Method string `json:"method"`
	Target string `json:"target"`
	Body   []byte `json:"body"`
}
type sourceResolvedRequestBinding struct {
	Method     string `json:"method"`
	FullTarget string `json:"fullTarget"`
	BodySHA256 string `json:"bodySha256"`
}
type sourceResolvedRequest struct {
	Request          sourceResolvedRequestBinding `json:"request"`
	RequestSHA256    string                       `json:"requestSha256"`
	IntentSHA256     string                       `json:"intentSha256"`
	Action           string                       `json:"action"`
	Resources        []SourceResourceRef          `json:"resources"`
	Fields           []SourceFieldSet             `json:"fields"`
	Contexts         []SourceOwnedContext         `json:"contexts"`
	ResourceRevision string                       `json:"resourceRevision"`
	SourceLeaseRef   SourceLeaseRef               `json:"sourceLeaseRef"`
}
type sourceContextRequest struct {
	BindingRef string                `json:"bindingRef"`
	Request    sourceOriginalRequest `json:"request"`
	LeaseRef   SourceLeaseRef        `json:"leaseRef"`
}

// IDs come from actual Node graph ownership/lineage, never paths or a Project
// catalog. This is a source context; current core/data/family gates remain required.
func (p *personalSource) personalContextsLocked(binding SourceOwnerBinding, until float64) ([]SourceOwnedContext, error) {
	index, err := stagedForestIndex(p.server.forest)
	if err != nil {
		return nil, sourceUnavailable()
	}
	root := index[binding.OwnerRef.RootID]
	nodes, err := stagedForestIndex(root)
	if err != nil || root == nil || len(nodes) > p.config.Bounds.MaxContexts || len(nodes) > p.config.Bounds.MaxResources || len(sourceWorkspaceFields()) > p.config.Bounds.MaxFields {
		return nil, sourceUnavailable()
	}
	contexts := []SourceOwnedContext{}
	for _, node := range nodes {
		context, e := p.personalNodeContextLocked(binding, index, nodes, node, until)
		if e != nil {
			return nil, e
		}
		contexts = append(contexts, context)
	}
	sort.Slice(contexts, func(i, j int) bool { return contexts[i].NodeID < contexts[j].NodeID })
	return contexts, nil
}
func (p *personalSource) personalNodeContextLocked(binding SourceOwnerBinding, index, closure map[string]*core.Node, node *core.Node, until float64) (SourceOwnedContext, error) {
	if node == nil || !node.CheckPermission(binding.OwnerRef.OwnerID, core.ReadPermission) {
		return SourceOwnedContext{}, sourceDenied()
	}
	parents := map[string]string{}
	for id, name := range node.Parents {
		parent := index[id]
		boundary := node.ID == binding.OwnerRef.RootID && id == p.server.forest.ID
		if parent == nil || parent.Name != name || parent.Children[node.ID] != node || (!boundary && closure[id] != parent) {
			return SourceOwnedContext{}, sourceDenied()
		}
		parents[id] = name
	}
	for _, parent := range index {
		if parent.Children[node.ID] != nil && parent.Children[node.ID] != node {
			return SourceOwnedContext{}, sourceDenied()
		}
		if parent.Children[node.ID] == node && node.Parents[parent.ID] != parent.Name {
			return SourceOwnedContext{}, sourceDenied()
		}
	}
	acl := sourceCommandKey([]interface{}{node.CreatedBy, node.Users, node.AccessGrants})
	lineage := sourceCommandKey([]interface{}{binding.OwnerRef, node.ID, parents})
	return SourceOwnedContext{binding.OwnerRef.RuntimeID, binding.OwnerRef.RootID, node.ID, binding.OwnerRef.OwnerID, binding.Account.AccountID, "momentum", nil, binding.BindingRevision, p.config.SourceAuthorityRef, p.server.sourceForestRevisionLocked(), lineage, acl, p.config.SourcePolicyRevision, domainNow(), until}, nil
}
func sourceWorkspaceFields() []string {
	return []string{"attachments", "created_at", "created_by", "entries", "events", "id", "kind", "metadata", "name", "planned_events"}
}

// First source profile only, not whole Momentum application parity. Unsupported
// mutation/query/file/stream/admin families fail unavailable, never fall through.
func (p *personalSource) resolveContext(request SourceEnvelope) (interface{}, error) {
	var input sourceContextRequest
	if sourceDecode(request.Payload, &input, p.config.Bounds) != nil {
		return nil, sourceInvalid()
	}
	entry, err := p.lookupEntry(input.LeaseRef, request.RequestID)
	if err != nil || entry.binding == nil || input.BindingRef != entry.binding.BindingRevision || entry.read.recheck() != nil {
		return nil, sourceDenied()
	}
	if input.Request.Method != "GET" || input.Request.Target != "/workspace" || len(input.Request.Body) != 0 {
		return nil, sourceUnavailable()
	}
	p.server.forestMutex.RLock()
	contexts, err := p.personalContextsLocked(*entry.binding, entry.ref.ValidUntil)
	p.server.forestMutex.RUnlock()
	if err != nil {
		return nil, err
	}
	resources, fields := []SourceResourceRef{}, []SourceFieldSet{}
	for _, context := range contexts {
		ref := SourceResourceRef{"node", context.NodeID}
		resources = append(resources, ref)
		fields = append(fields, SourceFieldSet{ref, sourceWorkspaceFields()})
	}
	original := sourceResolvedRequestBinding{input.Request.Method, input.Request.Target, stagedHash(input.Request.Body)}
	intent := PersonalSourceIntent{"activation-personal-handoff/0.1", entry.grant.Scope, entry.binding.OwnerRef, entry.binding.BindingRevision, "workspace.read", original.Method, original.FullTarget, original.BodySHA256, sourceCommandKey(original), resources, fields}
	return sourceResolvedRequest{original, intent.RequestSHA256, sourceCommandKey(intent), intent.Action, resources, fields, contexts, entry.ref.SourceRevision, entry.ref}, nil
}

type sourceResourcesOpen struct {
	Actor    SourceActor          `json:"actor"`
	Grant    SourcePersonalGrant  `json:"grant"`
	Binding  SourceOwnerBinding   `json:"binding"`
	Intent   PersonalSourceIntent `json:"intent"`
	LeaseRef SourceLeaseRef       `json:"leaseRef"`
}
type sourceResourcesResult struct {
	LeaseRef SourceLeaseRef         `json:"leaseRef"`
	Decision SourceResourceDecision `json:"decision"`
}

func (p *personalSource) resourceDecisionLocked(entry *personalSourceEntry) (SourceResourceDecision, error) {
	binding, err := p.currentBindingLocked(entry)
	if err != nil {
		return SourceResourceDecision{}, err
	}
	contexts, err := p.personalContextsLocked(binding, binding.ValidUntil)
	if err != nil {
		return SourceResourceDecision{}, err
	}
	resources, fields := sourceContextSelections(contexts)
	original := sourceResolvedRequestBinding{"GET", "/workspace", stagedHash(nil)}
	intent := PersonalSourceIntent{"activation-personal-handoff/0.1", entry.grant.Scope, binding.OwnerRef, binding.BindingRevision, "workspace.read", original.Method, original.FullTarget, original.BodySHA256, sourceCommandKey(original), resources, fields}
	if !domainEqual(*entry.intent, intent) {
		return SourceResourceDecision{}, sourceUnavailable()
	}
	return SourceResourceDecision{entry.actor.PrincipalID, entry.actor.SessionID, entry.grant.Scope, binding.OwnerRef, binding.BindingRevision, intent.Action, resources, fields, sourceCommandKey(intent), entry.ref.RequestID, p.config.SourceAuthorityRef, entry.ref.SourceRevision, p.config.SourcePolicyRevision, domainNow(), binding.ValidUntil}, nil
}
func sourceContextSelections(contexts []SourceOwnedContext) ([]SourceResourceRef, []SourceFieldSet) {
	resources, fields := []SourceResourceRef{}, []SourceFieldSet{}
	for _, context := range contexts {
		ref := SourceResourceRef{"node", context.NodeID}
		resources = append(resources, ref)
		fields = append(fields, SourceFieldSet{ref, sourceWorkspaceFields()})
	}
	return resources, fields
}
func (p *personalSource) resourcesOpen(request SourceEnvelope) (interface{}, error) {
	var input sourceResourcesOpen
	if sourceDecode(request.Payload, &input, p.config.Bounds) != nil {
		return nil, sourceInvalid()
	}
	entry, err := p.lookupEntry(input.LeaseRef, request.RequestID)
	if err != nil || entry.binding == nil || entry.intent == nil || !sourceBindingSame(*entry.binding, input.Binding) || !sourceActorSame(entry.actor, input.Actor) || !domainEqual(entry.grant, input.Grant) || !domainEqual(*entry.intent, input.Intent) {
		return nil, sourceDenied()
	}
	if validateSourceActorGrant(input.Actor, input.Grant, request.RequestID, p.config.Bounds) != nil {
		return nil, sourceDenied()
	}
	p.server.forestMutex.RLock()
	local := *entry
	local.actor = input.Actor
	decision, err := p.resourceDecisionLocked(&local)
	p.server.forestMutex.RUnlock()
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	entry.decision = &decision
	p.mu.Unlock()
	return sourceResourcesResult{entry.ref, decision}, nil
}
func (p *personalSource) resourcesRecheck(request SourceEnvelope) (interface{}, error) {
	var input sourceBindingRecheck
	if sourceDecode(request.Payload, &input, p.config.Bounds) != nil {
		return nil, sourceInvalid()
	}
	entry, err := p.lookupEntry(input.LeaseRef, request.RequestID)
	if err != nil || entry.decision == nil || entry.intent == nil || !sourceActorSame(entry.actor, input.Actor) || !domainEqual(entry.grant, input.Grant) || !domainEqual(*entry.intent, input.Intent) {
		return nil, sourceDenied()
	}
	if validateSourceActorGrant(input.Actor, input.Grant, request.RequestID, p.config.Bounds) != nil {
		return nil, sourceDenied()
	}
	p.server.forestMutex.RLock()
	local := *entry
	local.actor = input.Actor
	decision, err := p.resourceDecisionLocked(&local)
	p.server.forestMutex.RUnlock()
	if err != nil {
		return nil, err
	}
	return sourceResourcesResult{entry.ref, decision}, nil
}
