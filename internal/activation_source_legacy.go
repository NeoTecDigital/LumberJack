// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import "context"

// Legacy-only snapshots still coalesce through stateWriter. Actual source setup
// irreversibly enables the stronger whole-forest evidence fence on this Server.
type sourceOrdinaryPermit struct {
	coordinator *sourceCoordinator
	writer      *sourceWritePermit
	active      bool
}

func (c *sourceCoordinator) requireFencing() {
	c.mu.Lock()
	c.required = true
	c.signalLocked()
	c.mu.Unlock()
}

func (s *Server) retainDescriptorFencing(descriptor stagedDescriptor) {
	if descriptor.SourceProfile != "" || descriptor.Binding.ProductID != "" || descriptor.ProfileID != "" || descriptor.ProfileRevision != "" || descriptor.ProfileDigest != "" {
		s.sourceFence().requireFencing()
	}
}

func (c *sourceCoordinator) beginOrdinaryWrite(ctx context.Context, key string) (*sourceOrdinaryPermit, error) {
	c.mu.Lock()
	if !c.required {
		c.legacyRunning++
		c.mu.Unlock()
		return &sourceOrdinaryPermit{coordinator: c, active: true}, nil
	}
	c.mu.Unlock()
	writer, err := c.beginWrite(ctx, key)
	if err != nil {
		return nil, err
	}
	return &sourceOrdinaryPermit{coordinator: c, writer: writer, active: true}, nil
}

func (p *sourceOrdinaryPermit) finish(known, changed bool) {
	if p.writer != nil {
		p.writer.finish(known, changed)
		return
	}
	p.releaseLegacy()
}

func (p *sourceOrdinaryPermit) noEffect(unchanged bool) {
	if p.writer != nil {
		p.writer.noEffect(unchanged)
		return
	}
	p.releaseLegacy()
}

func (p *sourceOrdinaryPermit) releaseLegacy() {
	c := p.coordinator
	c.mu.Lock()
	if p.active {
		c.legacyRunning--
		p.active = false
		c.signalLocked()
	}
	c.mu.Unlock()
}
