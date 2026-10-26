// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package pngstore

import engine "github.com/NeoTecDigital/LumberJack/internal"

type targetInput struct {
	request Request
	mode    string
}

// Parse strict request bytes once per uninterrupted native evaluation, never
// cache a current record, permission, disclosure result or acknowledgement.
func (Adapter) BindTargetInput(input engine.DomainInput) (engine.DomainTargetInput, error) {
	request, err := decode(input)
	if err != nil {
		return nil, err
	}
	return targetInput{request: request, mode: input.Mode}, nil
}

func (p targetInput) NativeCreates(owned engine.DomainOwnedScope, id string) bool {
	if id == owned.Binding.RootID {
		return false
	}
	for _, mutation := range p.request.Mutations {
		if mutation.NativeID == id {
			return false
		}
	}
	return p.mode == "command"
}

func (p targetInput) TargetFields(owned engine.DomainOwnedScope, native engine.DomainRecord) []string {
	return requestTargetFields(p.request, owned, native)
}
