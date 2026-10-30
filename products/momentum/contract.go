// Written by Richard Christopher, Copyright 2026 Mindfull
package momentum

import (
	"fmt"
	"strings"
	"unicode/utf8"

	engine "github.com/NeoTecDigital/LumberJack/internal"
)

const Revision = "momentum-workspace/0.1"
const Initialize = "workspace.initialize.define"
const Create = "workspace.create.define"
const Update = "workspace.update"

type Adapter struct{}

func New() engine.DomainProduct { return Adapter{} }

type envelope struct {
	ContractRevision string             `json:"contractRevision"`
	Scope            engine.DomainScope `json:"scope"`
	CommandID        string             `json:"commandId,omitempty"`
	ExpectedRevision string             `json:"expectedRevision,omitempty"`
	Operation        string             `json:"operation,omitempty"`
	Payload          payload            `json:"payload,omitempty"`
}
type payload struct {
	NodeID   string `json:"nodeId,omitempty"`
	ParentID string `json:"parentId,omitempty"`
	Title    string `json:"title,omitempty"`
	Kind     string `json:"kind,omitempty"`
	Content  string `json:"content,omitempty"`
}

var Operations = []string{"read", Initialize, Create, Update}
var Fields = []string{"accountId", "parentId", "title", "kind", "content", "createdBy", "createdAt", "personalOwner", "defaultsVersion"}

func text(value string, maximum int, empty bool) bool {
	return utf8.ValidString(value) && len(value) <= maximum && (empty || strings.TrimSpace(value) != "") && !strings.ContainsRune(value, 0)
}

func validKind(value string) bool {
	for _, kind := range []string{"idea", "project", "category", "goal", "action", "procedure", "workflow", "document", "run", "workspace", "collection"} {
		if value == kind {
			return true
		}
	}
	return false
}

func (Adapter) Command(input engine.DomainInput) (engine.DomainCommand, error) {
	request, err := decode(input)
	return engine.DomainCommand{CommandID: request.CommandID, ExpectedRevision: request.ExpectedRevision, Operation: request.Operation}, err
}

func checkedRecord(id string, owned engine.DomainOwnedScope, view engine.DomainView) (engine.DomainRecord, string, error) {
	record, present := view.Records[id]
	kind := "work"
	if id == owned.Binding.RootID {
		kind = "root"
	}
	if !present || record.Kind != owned.Layout.Kinds[kind] {
		return record, kind, fmt.Errorf("workspace record missing or wrong kind")
	}
	if kind != "root" && record.Metadata[owned.Layout.Fields["accountId"]] != owned.Binding.AccountID {
		return record, kind, fmt.Errorf("workspace record outside account")
	}
	return record, kind, nil
}
