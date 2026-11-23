// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package types

import (
	"errors"
	"strings"
	"unicode"

	"github.com/NeoTecDigital/LumberJack/internal/compat"
)

const StorageLabelNeutral = "neutral"
const MaxSealingLabels = 16

var ErrSealingLabel = errors.New("storage sealing label not supplied or authentication failed")

// SealingLabel names two exact AAD prefixes. No label name is written to disk.
type SealingLabel struct {
	Name          string `json:"name" yaml:"name" mapstructure:"name"`
	StatePrefix   string `json:"state_prefix" yaml:"state_prefix" mapstructure:"state_prefix"`
	ObjectsPrefix string `json:"objects_prefix" yaml:"objects_prefix" mapstructure:"objects_prefix"`
}

func validLabelText(s string, limit int) bool {
	return len(s) > 0 && len(s) <= limit && strings.TrimSpace(s) == s && strings.IndexFunc(s, unicode.IsControl) < 0
}

// Distinct names and prefixes prevent ambiguous key selection. Never log supplied strings.
func (c StorageConfig) Validate() error {
	if len(c.Labels) > 0 && c.Mode == "" {
		return errors.New("host sealing labels require encrypted storage")
	}
	if len(c.Labels) > MaxSealingLabels {
		return errors.New("too many storage sealing labels")
	}
	neutral := compat.Label{}
	names := map[string]bool{StorageLabelNeutral: true}
	prefixes := map[string]bool{neutral.StatePrefix(): true, neutral.ObjectsPrefix(): true}
	for _, l := range c.Labels {
		if !validLabelText(l.Name, 64) || names[l.Name] {
			return errors.New("invalid or duplicate storage label name")
		}
		names[l.Name] = true
		for _, p := range []string{l.StatePrefix, l.ObjectsPrefix} {
			if !validLabelText(p, 256) || prefixes[p] {
				return errors.New("invalid or duplicate storage label prefix")
			}
			prefixes[p] = true
		}
	}
	if c.WriteLabel != "" && !names[c.WriteLabel] {
		return errors.New("unknown storage write_label")
	}
	return nil
}

// ResolveOpenStorage resolves a trusted host's open request. Labels alone inherit the wrapper;
// an explicit wrapper cannot replace a different ambient encryption configuration.
func ResolveOpenStorage(policy *StorageConfig) (*StorageConfig, error) {
	if policy == nil {
		return nil, nil
	}
	config := *policy
	ambient, _ := StorageFromEnvironment()
	if config.Mode == "" {
		if config.LocalKeyFile != "" || config.KMSKey != "" {
			return nil, errors.New("wrapper requires explicit storage mode")
		}
		config.Mode, config.LocalKeyFile, config.KMSKey = ambient.Mode, ambient.LocalKeyFile, ambient.KMSKey
	} else if ambient.Mode != "" && (ambient.Mode != config.Mode || ambient.LocalKeyFile != config.LocalKeyFile || ambient.KMSKey != config.KMSKey) {
		return nil, errors.New("storage wrapper conflicts with environment")
	}
	if config.Mode == "" {
		return nil, errors.New("sealing labels require encrypted storage")
	}
	// An explicit per-open policy must never inherit permission to mutate an existing format.
	if config.MigrateLegacy || config.RewrapKeys || ambient.MigrateLegacy || ambient.RewrapKeys {
		return nil, errors.New("maintenance flags are not an open policy")
	}
	if config.WriteLabel == "" {
		config.WriteLabel = ambient.WriteLabel
	}
	return &config, config.Validate()
}
