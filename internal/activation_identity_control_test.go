// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"fmt"
	"strings"
	"testing"
)

func TestPersonalSourceExistingControlAndSealedMappingRequired(t *testing.T) {
	f := sourceUnitFixtureNew(t)
	if _, err := f.p.captureControl(sourceUnitRequest(f, "control.capture", sourceControlCapture{"unit_not_a_real_credential"})); err == nil {
		t.Fatal("missing actual control verifier bypassed")
	}
	input := sourceConsentEstablish{CommandID: "unit-consent", ControlRef: "unit-absent", SupabaseEvidence: f.actor.Evidence, CanonicalMappingRef: "unit-unsealed", RootID: "record-a", OwnerID: "unit-owner"}
	if _, err := f.p.establishConsent(sourceUnitRequest(f, "consent.establish", input)); err == nil {
		t.Fatal("unsealed mapping forged canonical owner")
	}
	if strings.Contains(fmt.Sprint(f.config), f.config.ControlToken) {
		t.Fatal("protected config leaked via formatting")
	}
}
