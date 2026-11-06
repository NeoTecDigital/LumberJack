// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

// The compiled adapter identifies immutable create targets; callers cannot set it.
type DomainCreationResolver interface {
	NativeCreates(DomainInput, DomainOwnedScope, string) bool
}

type DomainTargetFields interface {
	TargetFields(DomainInput, DomainOwnedScope, DomainRecord) []string
}
