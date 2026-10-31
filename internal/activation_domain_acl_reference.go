// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import "fmt"

const domainACLRevision = "lj.domain.acl/1"
const domainACLReferenceRevision = "lj.domain.acl.ref/1"

// A record created from its kind's template stores this instead of a copy of the template: its
// access list IS the current createACLs[kind] on its own root, so one list per kind is stored and a
// record costs its data. A record whose list differs from the template holds that full list, and
// so does every record written before references existed. An engine without this revision refuses
// a reference as an invalid ACL, so a rollback past it fails closed.
type domainACLReference struct {
	RootID string
	Kind   string
}

func domainACLReferenceValue(rootID, kind string) map[string]interface{} {
	return map[string]interface{}{"contractRevision": domainACLReferenceRevision, "rootId": rootID, "kind": kind}
}

// The second result says the value claims to be a reference, valid or not.
func domainACLReferenceOf(raw interface{}) (domainACLReference, bool, error) {
	value, ok := raw.(map[string]interface{})
	if !ok || value["contractRevision"] != domainACLReferenceRevision {
		return domainACLReference{}, false, nil
	}
	rootID, rootOK := value["rootId"].(string)
	kind, kindOK := value["kind"].(string)
	if len(value) != 3 || !rootOK || !kindOK || rootID == "" || kind == "" {
		return domainACLReference{}, true, fmt.Errorf("invalid native ACL reference")
	}
	return domainACLReference{RootID: rootID, Kind: kind}, true, nil
}

// A reference resolves only against the root of the scope being evaluated and only for the kind
// the record actually is, so a record cannot borrow another account's or another type's list.
func validateDomainACLReference(reference domainACLReference, owned DomainOwnedScope, root, record DomainRecord) error {
	if record.ID == owned.Binding.RootID {
		return fmt.Errorf("native root must hold its own ACL")
	}
	if reference.RootID != owned.Binding.RootID || root.ID != owned.Binding.RootID {
		return fmt.Errorf("native ACL reference names another root")
	}
	if record.Kind == "" || owned.Layout.Kinds[reference.Kind] != record.Kind {
		return fmt.Errorf("native ACL reference names another kind")
	}
	return nil
}

func domainACLTemplateValue(key string, root DomainRecord, kind string) (interface{}, error) {
	acl, ok := root.Metadata[key].(map[string]interface{})
	if !ok || acl["contractRevision"] != domainACLRevision {
		return nil, fmt.Errorf("invalid current native ACL")
	}
	templates, _ := acl["createACLs"].(map[string]interface{})
	template, present := templates[kind]
	if !present {
		return nil, fmt.Errorf("explicit owner new-record ACL template absent")
	}
	return template, nil
}

// domainRecordACLValue returns the list that governs the record, borrowed from the caller's
// records, and whether it came through a reference. A full list is returned as stored.
func domainRecordACLValue(key string, owned DomainOwnedScope, root, record DomainRecord) (interface{}, bool, error) {
	raw := record.Metadata[key]
	reference, isReference, err := domainACLReferenceOf(raw)
	if err != nil || !isReference {
		return raw, false, err
	}
	if err = validateDomainACLReference(reference, owned, root, record); err != nil {
		return nil, true, err
	}
	template, err := domainACLTemplateValue(key, root, reference.Kind)
	return template, true, err
}

// DomainRecordACL is the list governing a record in the view, for a product projecting what the
// policy decides. The decision itself stays with the engine's policy.
func DomainRecordACL(owned DomainOwnedScope, view DomainView, record DomainRecord) (interface{}, error) {
	value, _, err := domainRecordACLValue(view.ACLMetadataKey, owned, view.Records[owned.Binding.RootID], record)
	return value, err
}

// domainACLReader decodes each kind's template once for a walk over many records. Its results are
// shared between records and must only be read.
type domainACLReader struct {
	policy    *domainOwnerPolicy
	owned     DomainOwnedScope
	root      DomainRecord
	templates map[string]domainACL
}

func newDomainACLReader(key string, owned DomainOwnedScope, root DomainRecord) *domainACLReader {
	return &domainACLReader{policy: &domainOwnerPolicy{key: key}, owned: owned, root: root, templates: map[string]domainACL{}}
}

func (r *domainACLReader) acl(record DomainRecord) (domainACL, error) {
	reference, isReference, err := domainACLReferenceOf(record.Metadata[r.policy.key])
	if err != nil {
		return domainACL{}, err
	}
	if !isReference {
		return r.policy.acl(record)
	}
	if err = validateDomainACLReference(reference, r.owned, r.root, record); err != nil {
		return domainACL{}, err
	}
	return r.template(reference.Kind)
}

func (r *domainACLReader) template(kind string) (domainACL, error) {
	if acl, present := r.templates[kind]; present {
		return acl, nil
	}
	value, err := domainACLTemplateValue(r.policy.key, r.root, kind)
	if err != nil {
		return domainACL{}, err
	}
	acl, err := r.policy.acl(DomainRecord{Metadata: map[string]interface{}{r.policy.key: value}})
	if err != nil {
		return domainACL{}, err
	}
	r.templates[kind] = acl
	return acl, nil
}

// domainACLDecisionsEqual says two lists decide every access the same way. Grant.Reference is only
// consulted once every requested field is granted, and the one caller asking for reference access
// requests the "reference" field, so the flag decides nothing on a grant without that field.
func domainACLDecisionsEqual(left, right domainACL) bool {
	return domainEqual(domainACLDecisions(left), domainACLDecisions(right))
}

func domainACLDecisions(acl domainACL) domainACL {
	normalized := domainACL{ContractRevision: acl.ContractRevision, Principals: map[string]map[string]domainGrant{}, CreateACLs: acl.CreateACLs}
	for principal, grants := range acl.Principals {
		normalized.Principals[principal] = map[string]domainGrant{}
		for operation, grant := range grants {
			grant.Reference = grant.Reference && domainContains(grant.Fields, "reference")
			normalized.Principals[principal][operation] = grant
		}
	}
	return normalized
}
