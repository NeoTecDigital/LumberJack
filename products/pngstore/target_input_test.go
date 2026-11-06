// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package pngstore

import (
	"encoding/json"
	"reflect"
	"testing"

	engine "github.com/NeoTecDigital/LumberJack/internal"
)

func TestBoundTargetInputMatchesFreshFieldsForNewAndExistingTargets(t *testing.T) {
	owned, view := testView()
	request := Request{ContractRevision: Revision, Action: "write", Operation: WriteOperation,
		CommandID: "synthetic", ExpectedRevision: "revision", Mutations: []Mutation{
			{Family: "business:job", Key: "job-1", NativeID: "native-1", Data: map[string]interface{}{"name": "exact", "id": "job-1", "account_id": "account"}},
			{Family: "business:job", Key: "new", Data: map[string]interface{}{"name": "new", "id": "new", "account_id": "account"}},
		}}
	body, _ := json.Marshal(request)
	input := engine.DomainInput{Mode: "command", Body: body}
	parsed, err := (Adapter{}).BindTargetInput(input)
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range []engine.DomainRecord{view.Records["native-1"], {Kind: owned.Layout.Kinds["png_record"]}} {
		if !reflect.DeepEqual(parsed.TargetFields(owned, record), TargetFields(input, owned, record)) {
			t.Fatal("parsed input changed exact target field coverage")
		}
	}
	if parsed.NativeCreates(owned, owned.Binding.RootID) || parsed.NativeCreates(owned, "native-1") || !parsed.NativeCreates(owned, "newly-allocated") {
		t.Fatal("parsed create/update/root classification changed")
	}
	want := parsed.TargetFields(owned, view.Records["native-1"])
	for index := range body {
		body[index] = ' '
	}
	if !reflect.DeepEqual(want, parsed.TargetFields(owned, view.Records["native-1"])) {
		t.Fatal("parsed target input retained mutable source bytes")
	}
}

func TestBoundTargetInputRejectsInvalidContractAndCommand(t *testing.T) {
	for _, body := range []string{`{}`, `{"contractRevision":"png-native-store/0.1","action":"write"}`, `{"contractRevision":"wrong","action":"read"}`} {
		if parsed, err := (Adapter{}).BindTargetInput(engine.DomainInput{Mode: "command", Body: []byte(body)}); err == nil || parsed != nil {
			t.Fatal("invalid parsed target input admitted")
		}
	}
}
