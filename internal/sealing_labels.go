// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"fmt"
	"github.com/NeoTecDigital/LumberJack/internal/keywrap"

	"github.com/NeoTecDigital/LumberJack/internal/compat"
	"github.com/NeoTecDigital/LumberJack/types"
)

// ErrSealingLabel is a refusal, never a signal to create, repair or migrate a store.
var ErrSealingLabel = types.ErrSealingLabel

func hostLabels(config types.StorageConfig) []compat.Label {
	labels := make([]compat.Label, 0, len(config.Labels))
	for _, l := range config.Labels {
		labels = append(labels, compat.Label{HostState: l.StatePrefix, HostObjects: l.ObjectsPrefix})
	}
	return labels
}
func writeLabel(config types.StorageConfig) compat.Label {
	for _, l := range config.Labels {
		if config.WriteLabel == l.Name {
			return compat.Label{HostState: l.StatePrefix, HostObjects: l.ObjectsPrefix}
		}
	}
	return compat.Label{}
}

// The wire family has no plaintext selector among host labels. Only successful authenticated
// unwrap can choose one. Neutral formats never try host prefixes, and vice versa.
func unwrapLabel(w keywrap.Wrapper, labels []compat.Label, neutral bool, wrapped keywrap.Wrapped, id, purpose string) (compat.Label, []byte, error) {
	if neutral {
		labels = []compat.Label{{}}
	}
	var last error
	for _, l := range labels {
		prefix := l.StatePrefix()
		if purpose == "master" {
			prefix = l.ObjectsPrefix()
		}
		raw, err := w.Unwrap(context.Background(), wrapped, []byte(prefix+id+"/"+purpose))
		if err == nil {
			return l, raw, nil
		}
		last = err
	}
	if neutral {
		return compat.Label{}, nil, last
	}
	if last != nil {
		return compat.Label{}, nil, fmt.Errorf("%w: %w", ErrSealingLabel, last)
	}
	return compat.Label{}, nil, ErrSealingLabel
}
