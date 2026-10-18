// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

// An evaluation-private view may borrow forest metadata ONLY while its caller
// holds the uninterrupted forest lock. It never escapes to any callback:
// Resolve/Project get complete deep copies; policy/target callbacks get isolated
// record copies. This avoids making two full metadata copies before Resolve.
func domainScopeRecords(scope *stagedScope, snapshot domainScopeSnapshot, private bool) (stagedView, error) {
	if !private {
		return newStagedView(scope, snapshot.nodes, snapshot.revision, map[string]bool{})
	}
	view, err := newStagedView(scope, nil, snapshot.revision, map[string]bool{})
	if err != nil {
		return stagedView{}, err
	}
	for id, node := range snapshot.nodes {
		view.Records[id] = stagedRecord{ID: id, Kind: node.Kind, Name: node.Name, Metadata: node.Metadata}
	}
	return view, nil
}
