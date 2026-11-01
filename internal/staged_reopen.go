// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import "fmt"

// Reopening an already reconciled descriptor is not a new snapshot admission.
// prepareStagedScopeLocked has checked the exact descriptor, closure and edges.
// Keep its own byte bound, and never accept pending/unknown work as a clean reopen.
// New setup and every new write still use their unchanged whole-snapshot ceiling.
func (s *Server) reopenReconciledScopeLocked(scope *stagedScope) (bool, error) {
	if !scope.reconciled {
		return false, nil
	}
	if scope.pending != nil {
		return false, fmt.Errorf("owned scope has pending work during reopen")
	}
	root, err := s.forest.GetNode(scope.descriptor.Binding.RootID)
	if err != nil {
		return false, err
	}
	if _, err := validateOwnedCandidate(root, scope.descriptor.Bounds); err != nil {
		return false, err
	}
	scope.configured = true
	return true, nil
}
