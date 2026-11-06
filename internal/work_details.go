// Written by Richard Christopher, Copyright 2026 Mindfull
package internal

import (
	"github.com/NeoTecDigital/LumberJack/internal/core"
	"regexp"
	"strings"
	"time"
)

type workMoney struct {
	Amount string `json:"amount"`
	Unit   string `json:"unit"`
	Payee  string `json:"payee,omitempty"`
}
type workAsset struct {
	Type        string `json:"type"`
	Amount      string `json:"amount,omitempty"`
	Unit        string `json:"unit,omitempty"`
	AsOf        string `json:"as_of,omitempty"`
	Institution string `json:"institution,omitempty"`
}

var moneyDecimal = regexp.MustCompile(`^-?(0|[1-9][0-9]{0,14})(\.[0-9]{1,4})?$`)

func validateMoney(amount, unit string, negative bool) error {
	if !moneyDecimal.MatchString(amount) || (!negative && strings.HasPrefix(amount, "-")) {
		return apiErrorf(400, "Enter a decimal amount with at most four decimal places")
	}
	if strings.TrimSpace(unit) == "" || len(unit) > 12 {
		return apiErrorf(400, "Specify the currency or monetary unit")
	}
	return nil
}

func workDetails(node *core.Node, cmd WorkCommand) error {
	if err := workEditorDetails(node, cmd); err != nil {
		return err
	}
	if value := cmd.FinancialTarget; value != nil {
		if value.Amount == "" {
			delete(node.Metadata, "momentum.financial_target")
		} else {
			if err := validateMoney(value.Amount, value.Unit, false); err != nil {
				return err
			}
			if len(value.Payee) > 200 {
				return apiErrorf(400, "Recipient description is too long")
			}
			node.Metadata["momentum.financial_target"] = workMetadataValue(*value)
		}
	}
	if value := cmd.Asset; value != nil {
		if node.Kind != "asset" {
			return apiErrorf(400, "Asset details belong to an asset record")
		}
		if err := validateAsset(*value); err != nil {
			return err
		}
		node.Metadata["momentum.asset"] = workMetadataValue(*value)
	}
	return nil
}

func validateAsset(value workAsset) error {
	if value.Type != "tangible" && value.Type != "financial_account" {
		return apiErrorf(400, "Choose a tangible asset or financial account")
	}
	if len(value.Institution) > 200 {
		return apiErrorf(400, "Institution name is too long")
	}
	if value.Amount != "" {
		if err := validateMoney(value.Amount, value.Unit, value.Type == "financial_account"); err != nil {
			return err
		}
		if _, err := time.Parse("2006-01-02", value.AsOf); err != nil {
			return apiErrorf(400, "Date the stated valuation or balance")
		}
	}
	return nil
}

func (s *Server) checkRequirements(node *core.Node, value temporalInput) error {
	if value.Type != "event" || value.Outcome != "completed" {
		return nil
	}
	incomplete := false
	err := s.walkScope("", nil, func(at visit) {
		if at.node.Metadata["momentum.required_for"] != node.ID {
			return
		}
		required := nodeTemporal(at.node)
		if required.Type != "event" || required.Outcome != "completed" {
			incomplete = true
		}
	})
	if err != nil {
		return err
	}
	if incomplete {
		return apiErrorf(409, "Complete the required steps before completing this item")
	}
	return nil
}
