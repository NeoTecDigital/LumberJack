// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"time"
	"unicode/utf8"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

func cloneStagedValue(value interface{}, depth, limit int) (interface{}, error) {
	if value == nil {
		return nil, nil
	}
	if depth > limit {
		return nil, fmt.Errorf("owned value exceeds depth bound")
	}
	if instant, ok := value.(time.Time); ok {
		return instant, nil
	}
	if _, raw := value.(json.RawMessage); raw {
		return nil, fmt.Errorf("raw JSON is not an owned structured value")
	}
	if copy, handled, err := cloneStagedStructured(value, depth, limit); handled {
		return copy, err
	}
	cloned, err := cloneStagedReflect(reflect.ValueOf(value), depth, limit)
	if err != nil {
		return nil, err
	}
	return cloned.Interface(), nil
}

func cloneStagedReflect(value reflect.Value, depth, limit int) (reflect.Value, error) {
	if value.Kind() == reflect.String && !utf8.ValidString(value.String()) {
		return reflect.Value{}, fmt.Errorf("owned text is not valid UTF-8")
	}
	switch value.Kind() {
	case reflect.Map:
		return cloneStagedMap(value, depth, limit)
	case reflect.Slice, reflect.Array:
		return cloneStagedSequence(value, depth, limit)
	case reflect.Bool, reflect.String, reflect.Int, reflect.Int8, reflect.Int16,
		reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16,
		reflect.Uint32, reflect.Uint64, reflect.Float32, reflect.Float64:
		return value, nil
	default:
		return reflect.Value{}, fmt.Errorf("unsupported owned value type %s", value.Type())
	}
}

func cloneStagedMap(value reflect.Value, depth, limit int) (reflect.Value, error) {
	if value.Type().Key().Kind() != reflect.String {
		return reflect.Value{}, fmt.Errorf("owned map keys must be strings")
	}
	if value.IsNil() {
		return reflect.Zero(value.Type()), nil
	}
	copy := reflect.MakeMapWithSize(value.Type(), value.Len())
	iterator := value.MapRange()
	for iterator.Next() {
		if !utf8.ValidString(iterator.Key().String()) {
			return reflect.Value{}, fmt.Errorf("owned map key is not valid UTF-8")
		}
		cloned, err := cloneStagedValue(iterator.Value().Interface(), depth+1, limit)
		if err != nil {
			return reflect.Value{}, err
		}
		copy.SetMapIndex(iterator.Key(), stagedReflectValue(cloned, value.Type().Elem()))
	}
	return copy, nil
}

func cloneStagedSequence(value reflect.Value, depth, limit int) (reflect.Value, error) {
	if value.Kind() == reflect.Slice && value.IsNil() {
		return reflect.Zero(value.Type()), nil
	}
	copy := reflect.New(value.Type()).Elem()
	if value.Kind() == reflect.Slice {
		copy = reflect.MakeSlice(value.Type(), value.Len(), value.Len())
	}
	for i := 0; i < value.Len(); i++ {
		cloned, err := cloneStagedValue(value.Index(i).Interface(), depth+1, limit)
		if err != nil {
			return reflect.Value{}, err
		}
		copy.Index(i).Set(stagedReflectValue(cloned, value.Type().Elem()))
	}
	return copy, nil
}

func stagedReflectValue(value interface{}, target reflect.Type) reflect.Value {
	if value == nil {
		return reflect.Zero(target)
	}
	return reflect.ValueOf(value)
}

func cloneStagedMetadata(metadata map[string]interface{}, bounds stagedBounds) (map[string]interface{}, error) {
	copy, err := cloneStagedValue(metadata, 0, bounds.MaxValueDepth)
	if err != nil {
		return nil, err
	}
	if _, err := json.Marshal(copy); err != nil {
		return nil, err
	}
	return copy.(map[string]interface{}), nil
}

func cloneStagedNode(node *core.Node, bounds stagedBounds) (*core.Node, error) {
	metadata, err := cloneStagedMetadata(node.Metadata, bounds)
	if err != nil {
		return nil, err
	}
	receipts, err := cloneStagedReceiptMap(node.CommandReceipts)
	if err != nil {
		return nil, err
	}
	return &core.Node{ID: node.ID, Type: node.Type, Kind: node.Kind, Name: node.Name,
		Parents: copyStringMap(node.Parents), Children: map[string]*core.Node{},
		Metadata: metadata, CommandReceipts: receipts, CreatedBy: node.CreatedBy,
		CreatedAt: node.CreatedAt, ModifiedBy: node.ModifiedBy, ModifiedAt: node.ModifiedAt}, nil
}

func cloneStagedNodes(nodes map[string]*core.Node, bounds stagedBounds) (map[string]*core.Node, error) {
	cloned := map[string]*core.Node{}
	for id, node := range nodes {
		copy, err := cloneStagedNode(node, bounds)
		if err != nil {
			return nil, err
		}
		cloned[id] = copy
	}
	for id, node := range nodes {
		if node.Children == nil {
			cloned[id].Children = nil
		}
		for key, child := range node.Children {
			cloned[id].Children[key] = cloned[child.ID]
		}
	}
	return cloned, nil
}

func newStagedView(scope *stagedScope, nodes map[string]*core.Node, revision string, allocated map[string]bool) (stagedView, error) {
	view := stagedView{Binding: scope.descriptor.Binding, Revision: revision,
		Records: map[string]stagedRecord{}}
	for id, node := range nodes {
		metadata, err := cloneStagedMetadata(node.Metadata, scope.descriptor.Bounds)
		if err != nil {
			return stagedView{}, err
		}
		view.Records[id] = stagedRecord{ID: id, Kind: node.Kind, Name: node.Name, Metadata: metadata}
	}
	view.AllocateID = func() (string, error) {
		if len(allocated) >= scope.descriptor.Bounds.MaxChanges {
			return "", fmt.Errorf("native ID allocation bound reached")
		}
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return "", err
		}
		id := hex.EncodeToString(random[:])
		if err := validateStagedIdentifiers(scope.descriptor.Bounds, id); err != nil {
			return "", err
		}
		allocated[id] = true
		return id, nil
	}
	return view, nil
}

func applyStagedDelta(scope *stagedScope, nodes map[string]*core.Node, delta stagedDelta, allocated map[string]bool, command stagedCommand, authorize stagedAuthorizer, occupied map[string]*core.Node) ([]stagedTarget, error) {
	if len(delta.Writes)+len(delta.Creates) > scope.descriptor.Bounds.MaxChanges {
		return nil, fmt.Errorf("owned command exceeds change bound")
	}
	var targets []stagedTarget
	for _, create := range delta.Creates {
		target, err := addStagedRecord(scope, nodes, create, allocated, command, authorize, occupied)
		if err != nil {
			return nil, err
		}
		targets = append(targets, target)
		parent := nodes[create.ParentID]
		targets = append(targets, stagedTarget{NodeID: parent.ID, Kind: parent.Kind, Fields: []string{"children"}})
	}
	for _, write := range delta.Writes {
		target, err := writeStagedField(scope, nodes, write, command, authorize)
		if err != nil {
			return nil, err
		}
		targets = append(targets, target)
	}
	return targets, nil
}

func addStagedRecord(scope *stagedScope, nodes map[string]*core.Node, create stagedCreate, allocated map[string]bool, command stagedCommand, authorize stagedAuthorizer, occupied map[string]*core.Node) (stagedTarget, error) {
	if !allocated[create.ID] || occupied[create.ID] != nil || nodes[create.ID] != nil {
		return stagedTarget{}, fmt.Errorf("new record ID was not uniquely allocated by the engine")
	}
	parent := nodes[create.ParentID]
	if parent == nil || len(nodes) >= scope.descriptor.Bounds.MaxNodes {
		return stagedTarget{}, fmt.Errorf("new record has no owned parent or exceeds node bound")
	}
	if err := validateStagedIdentifiers(scope.descriptor.Bounds, create.ID, create.ParentID); err != nil {
		return stagedTarget{}, err
	}
	if len(create.Kind) > scope.descriptor.Bounds.MaxIdentifierBytes || len(create.Name) > scope.descriptor.Bounds.MaxIdentifierBytes ||
		!utf8.ValidString(create.Kind) || !utf8.ValidString(create.Name) {
		return stagedTarget{}, fmt.Errorf("new kind/name is invalid or exceeds its bound")
	}
	metadata, err := cloneStagedMetadata(create.Metadata, scope.descriptor.Bounds)
	if err != nil {
		return stagedTarget{}, err
	}
	target := stagedTarget{NodeID: create.ID, Kind: create.Kind, Fields: sortedStagedKeys(metadata)}
	if err := authorizeStagedTarget(authorize, scope.descriptor.Binding, command, target); err != nil {
		return stagedTarget{}, err
	}
	parentTarget := stagedTarget{NodeID: parent.ID, Kind: parent.Kind, Fields: []string{"children"}}
	if err := authorizeStagedTarget(authorize, scope.descriptor.Binding, command, parentTarget); err != nil {
		return stagedTarget{}, err
	}
	node := &core.Node{ID: create.ID, Name: create.Name, Kind: create.Kind, Metadata: metadata,
		Parents: map[string]string{parent.ID: parent.Name}, CommandReceipts: map[string]interface{}{stagedScopeKey: scope.descriptor}}
	if parent.Children == nil {
		parent.Children = map[string]*core.Node{}
	}
	parent.Children[node.ID] = node
	nodes[node.ID] = node
	return target, nil
}

func writeStagedField(scope *stagedScope, nodes map[string]*core.Node, write stagedWrite, command stagedCommand, authorize stagedAuthorizer) (stagedTarget, error) {
	node := nodes[write.NodeID]
	if node == nil || write.Key == "" || len(write.Key) > scope.descriptor.Bounds.MaxIdentifierBytes || !utf8.ValidString(write.Key) {
		return stagedTarget{}, fmt.Errorf("field write is outside the owned bounded scope")
	}
	target := stagedTarget{NodeID: node.ID, Kind: node.Kind, Fields: []string{write.Key}}
	if err := authorizeStagedTarget(authorize, scope.descriptor.Binding, command, target); err != nil {
		return stagedTarget{}, err
	}
	value, err := cloneStagedValue(write.Value, 0, scope.descriptor.Bounds.MaxValueDepth)
	if err != nil {
		return stagedTarget{}, err
	}
	if node.Metadata == nil {
		node.Metadata = map[string]interface{}{}
	}
	node.Metadata[write.Key] = value
	return target, nil
}

func stagedProfileField(name string) bool {
	switch name {
	case "ID", "Type", "Kind", "Name", "Parents", "Children", "Metadata", "CommandReceipts",
		"CreatedBy", "CreatedAt", "ModifiedBy", "ModifiedAt":
		return true
	default:
		return false
	}
}

func validateStagedProfile(node *core.Node, bounds stagedBounds) error {
	value := reflect.ValueOf(node).Elem()
	for i := 0; i < value.NumField(); i++ {
		field := value.Type().Field(i)
		if field.PkgPath == "" && !stagedProfileField(field.Name) && !value.Field(i).IsZero() {
			return fmt.Errorf("owned profile refuses legacy field %s", field.Name)
		}
	}
	if err := validateStagedIdentifiers(bounds, node.ID); err != nil {
		return err
	}
	if len(node.Name) > bounds.MaxIdentifierBytes || len(node.Kind) > bounds.MaxIdentifierBytes || !utf8.ValidString(node.Name) || !utf8.ValidString(node.Kind) {
		return fmt.Errorf("owned name/kind exceeds its bound")
	}
	_, err := cloneStagedMetadata(node.Metadata, bounds)
	return err
}

func validateStagedSetup(nodes map[string]*core.Node, descriptor stagedDescriptor) error {
	cloned, err := cloneStagedNodes(nodes, descriptor.Bounds)
	if err != nil {
		return err
	}
	if err := markStagedClosure(cloned, descriptor); err != nil {
		return err
	}
	root := cloned[descriptor.Binding.RootID]
	if len(root.CommandReceipts)-1 > descriptor.Bounds.MaxReceipts {
		return fmt.Errorf("loaded owned receipt count exceeds its explicit capacity")
	}
	_, err = validateOwnedCandidate(root, descriptor.Bounds)
	return err
}

func sortedStagedKeys(metadata map[string]interface{}) []string {
	keys := make([]string, 0, len(metadata))
	for key := range metadata {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func clearStagedLegacyFields(node *core.Node) {
	value := reflect.ValueOf(node).Elem()
	for i := 0; i < value.NumField(); i++ {
		field := value.Type().Field(i)
		if field.PkgPath == "" && !stagedProfileField(field.Name) {
			value.Field(i).Set(reflect.Zero(value.Field(i).Type()))
		}
	}
}
