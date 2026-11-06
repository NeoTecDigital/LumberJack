// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package pngstore

import (
	"encoding/json"
	"fmt"
	engine "github.com/NeoTecDigital/LumberJack/internal"
)

const HistoryFamily = "native.command_receipt"

func historyRecords(request Request, view engine.DomainView) ([]Record, error) {
	retained, present := view.RetainedReceipts[request.Query.Key]
	if !present {
		return []Record{}, nil
	}
	var data struct {
		Records []Record        `json:"records"`
		Result  json.RawMessage `json:"result"`
	}
	if err := engine.DecodeDomainJSON(retained.Receipt.ProductIntent, &data); err != nil {
		return nil, err
	}
	return data.Records, nil
}
func historyBody(id string, request Request, intent engine.DomainIntent, view engine.DomainView) ([]byte, error) {
	retained, present := view.RetainedReceipts[request.Query.Key]
	body := map[string]interface{}{"contractRevision": Revision, "requestId": id, "scope": intent.Scope, "revision": view.Revision, "records": []Record{}}
	if !present {
		return engine.CanonicalDomainJSON(body)
	}
	if view.VerifiedAuthority == nil || view.VerifiedAuthority.PrincipalID != retained.Receipt.Command.PrincipalID {
		return nil, fmt.Errorf("retained command actor mismatch")
	}
	var data map[string]interface{}
	if err := engine.DecodeDomainJSON(retained.Receipt.ProductIntent, &data); err != nil {
		return nil, err
	}
	rows, err := historyRecords(request, view)
	if err != nil {
		return nil, err
	}
	rows = maskRecords(rows, request.Query.Fields)
	data["records"] = rows
	body["records"] = rows
	body["data"] = data
	body["receipt"] = map[string]interface{}{"commandId": retained.Receipt.Command.CommandID, "expectedRevision": retained.Receipt.Command.ExpectedRevision, "operation": retained.Receipt.Command.Action, "requestFingerprint": retained.Receipt.Command.BodySHA256, "status": "replayed", "revision": retained.Receipt.AfterRevision, "receiptKey": retained.Key}
	return engine.CanonicalDomainJSON(body)
}
