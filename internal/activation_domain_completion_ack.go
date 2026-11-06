// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import "fmt"

// AcknowledgeDomainCompletion retires only a host-observed transient completion.
// Durable receipts and all revocation/closure fences are deliberately untouched.
func (s *Server) AcknowledgeDomainCompletion(input DomainControl) error {
	d, err := s.domainEngine()
	if err != nil {
		return err
	}
	entry, err := d.entry(input)
	if err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if input.Action != "finish" || d.entries[input.LeaseID] != entry || !entry.finished || entry.executing || entry.pendingKey != "" {
		return fmt.Errorf("native completion not ready for acknowledgement")
	}
	if input.ResponseHash != entry.responseHash || input.Disposition != entry.disposition {
		return fmt.Errorf("native completion acknowledgement mismatch")
	}
	if input.Disposition == "handed-off" && input.PermitID != entry.permitID {
		return fmt.Errorf("native completion acknowledgement permit mismatch")
	}
	delete(d.entries, input.LeaseID)
	d.rootGeneration++
	return nil
}
