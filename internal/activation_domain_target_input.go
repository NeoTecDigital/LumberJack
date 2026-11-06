// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

// DomainTargetInput contains parsed request data ONLY. Its lifetime is a single
// uninterrupted forest-lock evaluation; it must retain no permission decision,
// proof, policy result or native record. Targets still receive current copies.
type DomainTargetInput interface {
	NativeCreates(DomainOwnedScope, string) bool
	TargetFields(DomainOwnedScope, DomainRecord) []string
}

type DomainTargetInputBinder interface {
	BindTargetInput(DomainInput) (DomainTargetInput, error)
}

func (e *domainEvaluation) prepareTargetInput(entry *domainEntry) error {
	if e.targetPrepared {
		return nil
	}
	if binder, ok := entry.product.(DomainTargetInputBinder); ok {
		var err error
		e.targetInput, err = binder.BindTargetInput(entry.input)
		if err != nil {
			return err
		}
	}
	e.targetPrepared = true
	return nil
}

func domainTargetCreates(entry *domainEntry, access stagedAccess, parsed DomainTargetInput) bool {
	if parsed != nil {
		return parsed.NativeCreates(entry.owned, access.NodeID)
	}
	if resolver, ok := entry.product.(DomainCreationResolver); ok {
		return resolver.NativeCreates(entry.input, entry.owned, access.NodeID)
	}
	return entry.intent.Operation != nil && isDomainDefinition(*entry.intent.Operation) && access.NodeID != entry.owned.Binding.RootID
}

func domainTargetPublicFields(entry *domainEntry, view DomainView, access stagedAccess, keys []string, parsed DomainTargetInput) ([]string, error) {
	fields, err := entry.product.PublicFields(access.Kind, keys, entry.owned)
	if err != nil {
		return nil, err
	}
	resolver, hasResolver := entry.product.(DomainTargetFields)
	if parsed == nil && !hasResolver {
		return fields, nil
	}
	target := view.Records[access.NodeID]
	if target.ID == "" {
		target.Kind = access.Kind
	}
	target, err = cloneDomainEvaluationRecord(target, entry.owned.Bounds)
	if err != nil {
		return nil, err
	}
	if parsed != nil {
		return append(fields, parsed.TargetFields(entry.owned, target)...), nil
	}
	return append(fields, resolver.TargetFields(entry.input, entry.owned, target)...), nil
}
