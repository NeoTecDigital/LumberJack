// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package pngstore

import (
	"encoding/json"
	engine "github.com/NeoTecDigital/LumberJack/internal"
	"testing"
)

func TestRetainedReceiptsOnlyForExplicitHistoryQueries(t *testing.T) {
	for _, family := range []string{HistoryFamily, "business:associate", "business:job", ""} {
		body, _ := json.Marshal(Request{ContractRevision: Revision, Action: "read", Query: Query{Family: family}})
		include, err := (Adapter{}).IncludeRetainedReceipts(engine.DomainInput{Mode: "read", Body: body})
		if err != nil || include != (family == HistoryFamily) {
			t.Fatalf("incorrect selector for %q: %t, %v", family, include, err)
		}
	}
}

func TestRetainedReceiptProjectionInvalidInputDenies(t *testing.T) {
	for _, input := range []engine.DomainInput{
		{Mode: "read", Body: []byte(`{"contractRevision":"wrong","action":"read"}`)},
		{Mode: "read", Body: []byte(`{"action":"read","unknown":true}`)},
		{Mode: "command", Body: []byte(`{"contractRevision":"png-native-store/0.1","action":"write"}`)},
	} {
		if _, err := (Adapter{}).IncludeRetainedReceipts(input); err == nil {
			t.Fatal("invalid selector input accepted")
		}
	}
}
