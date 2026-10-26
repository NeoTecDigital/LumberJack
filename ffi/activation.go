// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package main

import (
	"encoding/json"
	"github.com/NeoTecDigital/LumberJack/embedded"
)

type applicationConfiguration struct {
	Username   string          `json:"username"`
	Password   string          `json:"password"`
	Secret     string          `json:"secret"`
	Activation json.RawMessage `json:"activation"`
}

func configureApplication(handle *embedded.Handle, config applicationConfiguration) error {
	var activation *embedded.ActivationConfig
	if len(config.Activation) > 0 {
		decoded, err := embedded.DecodeActivationConfig(config.Activation)
		if err != nil {
			return err
		}
		activation = &decoded
	}
	if err := handle.ConfigureApplication(config.Username, config.Password, config.Secret); err != nil {
		return err
	}
	if activation != nil {
		return handle.ConfigureActivation(*activation)
	}
	return nil
}
