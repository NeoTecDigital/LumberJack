// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package abi

import (
	"encoding/json"

	"github.com/NeoTecDigital/LumberJack/embedded"
)

// The body of ic_lj_application_configure: the engine's own parts and every other part, which
// belongs to the extension that declared it (docs/extension-api.md §4.7). A part no extension
// declared is refused, so a caller sending one to an archive that does not carry its owner is
// answered LJ_INVALID rather than ignored.

// engineConfigurationParts are the parts the engine reads itself.
var engineConfigurationParts = map[string]bool{"username": true, "password": true, "secret": true}

type applicationConfiguration struct {
	Username string
	Password string
	Secret   string
	Parts    map[string]json.RawMessage
}

func decodeApplicationConfiguration(body []byte) (applicationConfiguration, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return applicationConfiguration{}, err
	}
	config := applicationConfiguration{Parts: map[string]json.RawMessage{}}
	for name, raw := range fields {
		if !engineConfigurationParts[name] {
			config.Parts[name] = raw
		}
	}
	for name, target := range map[string]*string{"username": &config.Username, "password": &config.Password, "secret": &config.Secret} {
		if raw, present := fields[name]; present {
			if err := json.Unmarshal(raw, target); err != nil {
				return applicationConfiguration{}, err
			}
		}
	}
	return config, nil
}

func configureApplication(handle *embedded.Handle, config applicationConfiguration) error {
	return handle.ConfigureApplicationParts(config.Username, config.Password, config.Secret, config.Parts)
}
