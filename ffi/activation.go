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
	Admission  json.RawMessage `json:"admission"`
}

// Each optional part is decoded before anything is configured, so a bad one fails the whole open
// rather than leaving a half-configured application behind it.
func configureApplication(handle *embedded.Handle, config applicationConfiguration) error {
	var activation *embedded.ActivationConfig
	if len(config.Activation) > 0 {
		decoded, err := embedded.DecodeActivationConfig(config.Activation)
		if err != nil {
			return err
		}
		activation = &decoded
	}
	var admission *embedded.SessionAdmissionConfig
	if len(config.Admission) > 0 {
		decoded, err := embedded.DecodeSessionAdmissionConfig(config.Admission)
		if err != nil {
			return err
		}
		admission = &decoded
	}
	if err := handle.ConfigureApplication(config.Username, config.Password, config.Secret); err != nil {
		return err
	}
	if activation != nil {
		if err := handle.ConfigureActivation(*activation); err != nil {
			return err
		}
	}
	if admission != nil {
		return handle.ConfigureSessionAdmission(*admission)
	}
	return nil
}
