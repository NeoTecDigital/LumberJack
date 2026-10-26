// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

// DomainReceiptProjection selects optional historical projection data, not
// command validation, durable acknowledgement, replay or authorization. Products
// without this interface retain the existing complete historical view.
type DomainReceiptProjection interface {
	IncludeRetainedReceipts(DomainInput) (bool, error)
}

func (s *Server) domainInputViewLocked(product DomainProduct, input DomainInput, owned DomainOwnedScope) (DomainView, error) {
	history := true
	if selector, ok := product.(DomainReceiptProjection); ok {
		var err error
		history, err = selector.IncludeRetainedReceipts(input)
		if err != nil {
			return DomainView{}, err
		}
	}
	return s.domainScopeViewLocked(owned, history, true)
}

func (s *Server) domainViewLocked(owned DomainOwnedScope) (DomainView, error) {
	return s.domainViewHistoryLocked(owned, true)
}
