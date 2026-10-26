package internal

import (
	"encoding/json"
	"testing"
	"time"
)

func TestAccountCaptureTargetAndRequiredStep(t *testing.T) {
	s := setupTestForest(t)
	create := WorkCommand{Command: "create", Path: "root", ClientID: "fixture-goal", Kind: "goal", Title: "Fixture goal", FinancialTarget: &workMoney{Amount: "1234.50", Unit: "USD", Payee: "Fixture recipient"}}
	first := workTestCommand(t, s, "admin", create, 200)
	path := first["path"].(string)
	if workTestCommand(t, s, "admin", create, 200)["path"] != path {
		t.Fatal("duplicate retry")
	}
	step := workTestCommand(t, s, "admin", WorkCommand{Command: "create", Path: path, ClientID: "fixture-step", Kind: "action", Title: "Fixture required step", Required: true}, 200)
	goal, _ := s.getNodeFromPath(path)
	required, _ := s.getNodeFromPath(step["path"].(string))
	if required.Metadata["momentum.required_for"] != goal.ID {
		t.Fatal("missing required relationship")
	}
	targetRaw, _ := json.Marshal(goal.Metadata["momentum.financial_target"])
	var target workMoney
	_ = json.Unmarshal(targetRaw, &target)
	if target.Amount != "1234.50" || target.Unit != "USD" {
		t.Fatal("target changed")
	}
	value := &temporalInput{Type: "event", Status: "done", Outcome: "completed", OccurredAt: time.Now().UTC().Format(time.RFC3339Nano)}
	workTestCommand(t, s, "admin", WorkCommand{Command: "temporal", Path: path, ClientID: "blocked-goal", Revision: workRevision(goal), Temporal: value}, 409)
	required, _ = s.getNodeFromPath(step["path"].(string))
	workTestCommand(t, s, "admin", WorkCommand{Command: "temporal", Path: step["path"].(string), ClientID: "complete-step", Revision: workRevision(required), Temporal: value}, 200)
	goal, _ = s.getNodeFromPath(path)
	workTestCommand(t, s, "admin", WorkCommand{Command: "temporal", Path: path, ClientID: "complete-goal", Revision: workRevision(goal), Temporal: value}, 200)
	goal, _ = s.getNodeFromPath(path)
	if goal.ID != first["result"].(map[string]interface{})["id"] || goal.Kind != "goal" {
		t.Fatal("identity changed")
	}
	raw, _ := encodeState(s.forest)
	restored, err := decodeState(raw)
	if err != nil {
		t.Fatal(err)
	}
	s.forest = restored
	goal, _ = s.getNodeFromPath(path)
	encoded, _ := json.Marshal(goal.Metadata["momentum.financial_target"])
	var recovered workMoney
	_ = json.Unmarshal(encoded, &recovered)
	if recovered != target {
		t.Fatal("target did not persist")
	}
}
func TestAccountCaptureRollbackAndStaleEdits(t *testing.T) {
	s := setupTestForest(t)
	before := len(s.forest.Children)
	cmd := WorkCommand{Command: "create", Path: "root", ClientID: "invalid-target", Title: "Fixture", Kind: "goal", FinancialTarget: &workMoney{Amount: "not money", Unit: "USD"}}
	workTestCommand(t, s, "admin", cmd, 400)
	if len(s.forest.Children) != before {
		t.Fatal("partial create after validation failure")
	}
	cmd.ClientID = "valid-target"
	cmd.FinancialTarget.Amount = "50"
	path := workTestCommand(t, s, "admin", cmd, 200)["path"].(string)
	node, _ := s.getNodeFromPath(path)
	edit := WorkCommand{Command: "update", Path: path, ClientID: "edit-target", Revision: workRevision(node), Title: "Edited fixture", Kind: "goal", Status: "idea", Content: "Preserved words"}
	workTestCommand(t, s, "admin", edit, 200)
	edit.ClientID = "stale-target"
	workTestCommand(t, s, "admin", edit, 409)
	node, _ = s.getNodeFromPath(path)
	if node.Metadata["momentum.financial_target"] == nil || node.Metadata["description"] != "Preserved words" {
		t.Fatal("lost unrelated data")
	}
}
func TestManualAccountAssetsAndValuationValidation(t *testing.T) {
	s := setupTestForest(t)
	for i, kind := range []string{"tangible", "financial_account"} {
		id := []string{"tangible", "account"}[i]
		value := &workAsset{Type: kind, Amount: "25.50", Unit: "USD", AsOf: "2026-01-01"}
		if kind == "financial_account" {
			value.Amount = "-25.50"
		}
		cmd := WorkCommand{Command: "create", Path: "root", ClientID: id, Title: "Fixture asset", Kind: "asset", Asset: value}
		path := workTestCommand(t, s, "admin", cmd, 200)["path"].(string)
		node, _ := s.getNodeFromPath(path)
		if node.Metadata["momentum.asset"] == nil || node.Kind != "asset" {
			t.Fatal("missing asset details")
		}
	}
	bad := WorkCommand{Command: "create", Path: "root", ClientID: "bad-asset", Title: "Fixture", Kind: "asset", Asset: &workAsset{Type: "tangible", Amount: "-1", Unit: "USD", AsOf: "2026-01-01"}}
	workTestCommand(t, s, "admin", bad, 400)
}
