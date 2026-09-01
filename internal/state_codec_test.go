package internal

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vaziolabs/lumberjack/internal/core"
)

// What nodeRecord's EMBEDDING buys, asserted rather than assumed.
//
// nodeRecord embeds *core.Node instead of restating its fields, so a field added to core.Node is
// persisted without state_codec.go having to be told about it. That is a promise about a file
// nobody looks at until a restart, and the failure mode of breaking it is silent: a serializer that
// lists the fields it knows about is a serializer that quietly stops saving the next one, and
// nothing says so until the field is gone after a reload.
//
// These tests are reflective ON PURPOSE. A test that names today's fields is the same defect as a
// codec that names today's fields — it would pass on the day someone adds a sixteenth field and
// forgets it. This walks whatever core.Node has.

// populatedNode is a node with EVERY exported field carrying a value, because several are tagged
// omitempty and a zero one is indistinguishable from a dropped one.
func populatedNode(t *testing.T) *core.Node {
	t.Helper()

	stamp := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	child := core.NewNode(core.LeafNode, "child")
	child.ID = "child-id"

	node := core.NewNode(core.BranchNode, "populated")
	node.ID = "populated-id"
	node.Parents = map[string]string{"parent-id": "parent"}
	node.Children = map[string]*core.Node{child.ID: child}
	node.Events = map[string]core.Event{"shift": {Metadata: map[string]interface{}{"kind": "inspection"}}}
	node.PlannedEvents = map[string]core.Event{"planned": {Metadata: map[string]interface{}{"kind": "planned"}}}
	node.Users = []core.User{{ID: "user-id", Username: "auditor"}}
	node.Entries = []core.Entry{{Content: "an entry", UserID: "user-id", Timestamp: stamp}}
	node.Attachments = map[string]core.Attachment{"hash": {ID: "hash", Name: "file.bin", Size: 3, Data: []byte{1, 2, 3}}}
	node.Metadata = map[string]interface{}{CanvasMetadataKey: map[string]interface{}{"x": 1.0}}
	node.CreatedBy = "user-id"
	node.CreatedAt = stamp
	node.ModifiedBy = "user-id"
	node.ModifiedAt = stamp
	return node
}

// jsonName is the key a field is written under, or "" if it is not written at all.
func jsonName(field reflect.StructField) string {
	if field.PkgPath != "" {
		return "" // unexported: encoding/json never sees it
	}
	tag := field.Tag.Get("json")
	if tag == "-" {
		return ""
	}
	if name, _, _ := strings.Cut(tag, ","); name != "" {
		return name
	}
	return field.Name
}

// nodeJSONNames is every key core.Node contributes to a state file.
func nodeJSONNames() []string {
	nodeType := reflect.TypeOf(core.Node{})

	var names []string
	for index := 0; index < nodeType.NumField(); index++ {
		if name := jsonName(nodeType.Field(index)); name != "" {
			names = append(names, name)
		}
	}
	return names
}

// EVERY field a node carries reaches the state file, including ones added after this was written.
func TestNodeRecordWritesEveryFieldANodeCarries(t *testing.T) {
	encoded, err := json.Marshal(&nodeRecord{Node: populatedNode(t), Children: []string{"child-id"}})
	if err != nil {
		t.Fatalf("Failed to encode a node record: %v", err)
	}

	var written map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &written); err != nil {
		t.Fatalf("A node record did not encode as an object: %v: %s", err, encoded)
	}

	names := nodeJSONNames()
	if len(names) < 10 {
		t.Fatalf("core.Node reflected as %d persisted fields, which cannot be right: %v", len(names), names)
	}
	for _, name := range names {
		if _, present := written[name]; !present {
			t.Errorf("core.Node's %q is not in the state file: the record wrote %v", name, keysOf(written))
		}
	}
}

// The one shadow is the INTENDED one, and it turns the nesting into ids.
//
// nodeRecord's outer Children beats core.Node's by JSON's shallower-field rule. That is the whole
// mechanism of the flat table — and it is also a loaded gun, because any other outer field whose
// name collides with a node's would swallow that field the same way, silently.
func TestTheOnlyShadowedNodeFieldIsChildren(t *testing.T) {
	recordType := reflect.TypeOf(nodeRecord{})

	outer := map[string]bool{}
	for index := 0; index < recordType.NumField(); index++ {
		field := recordType.Field(index)
		if field.Anonymous {
			continue // the embedded node: its fields are the shallower ones' victims, not rivals
		}
		if name := jsonName(field); name != "" {
			outer[name] = true
		}
	}

	for _, name := range nodeJSONNames() {
		if outer[name] && name != "children" {
			t.Errorf("nodeRecord's own %q shadows core.Node's: the node's value is silently not persisted", name)
		}
	}
	if !outer["children"] {
		t.Error("nodeRecord no longer declares children of its own, so the state file is nested again")
	}

	// The shadow does what it is for: an ARRAY of ids, not the node's map of children.
	encoded, err := json.Marshal(&nodeRecord{Node: populatedNode(t), Children: []string{"child-id"}})
	if err != nil {
		t.Fatalf("Failed to encode a node record: %v", err)
	}
	var written struct {
		Children []string `json:"children"`
	}
	if err := json.Unmarshal(encoded, &written); err != nil {
		t.Fatalf("children did not encode as a list of ids: %v: %s", err, encoded)
	}
	if !reflect.DeepEqual(written.Children, []string{"child-id"}) {
		t.Errorf("children encoded as %v, want the id list [child-id]", written.Children)
	}
}

// THE LATENT TRAP: a second core.Node field tagged `json:"children"`.
//
// Two fields at the same depth under one name make encoding/json drop BOTH — the node's real
// children would stop being written and nothing would say so, because the record's outer children
// still fills the key. Names are asserted unique so that the collision is a failing test rather
// than an empty forest.
func TestNoTwoNodeFieldsClaimTheSameName(t *testing.T) {
	seen := map[string]string{}
	nodeType := reflect.TypeOf(core.Node{})

	for index := 0; index < nodeType.NumField(); index++ {
		field := nodeType.Field(index)
		name := jsonName(field)
		if name == "" {
			continue
		}
		if first, taken := seen[name]; taken {
			t.Errorf("core.Node's %s and %s are both written as %q, so encoding/json writes neither",
				first, field.Name, name)
			continue
		}
		seen[name] = field.Name
	}
}

// The values themselves make the round trip, field for field.
//
// The presence tests above prove the KEYS are written; this proves the codec's own edge rebuilding
// does not lose what is under them.
func TestANodeSurvivesTheCodecWithEverythingOnIt(t *testing.T) {
	node := populatedNode(t)
	root := core.NewNode(core.BranchNode, "root")
	root.ID = "root-id"
	root.Children = map[string]*core.Node{node.ID: node}

	encoded, err := encodeState(root)
	if err != nil {
		t.Fatalf("Failed to encode the forest: %v", err)
	}
	decoded, err := decodeState(encoded)
	if err != nil {
		t.Fatalf("Failed to decode the forest: %v", err)
	}

	after, present := decoded.Children[node.ID]
	if !present {
		t.Fatalf("The node is not under the root after the round trip: %v", keysOfNodes(decoded.Children))
	}

	if after.Name != node.Name || after.Type != node.Type {
		t.Errorf("The node came back as %s/%v, want %s/%v", after.Name, after.Type, node.Name, node.Type)
	}
	if !reflect.DeepEqual(after.Parents, node.Parents) {
		t.Errorf("Parents came back as %v, want %v", after.Parents, node.Parents)
	}
	if !reflect.DeepEqual(after.Users, node.Users) {
		t.Errorf("Users came back as %v, want %v", after.Users, node.Users)
	}
	if len(after.Entries) != len(node.Entries) || len(after.Events) != len(node.Events) {
		t.Errorf("The node came back with %d entries and %d events, want %d and %d",
			len(after.Entries), len(after.Events), len(node.Entries), len(node.Events))
	}
	if len(after.PlannedEvents) != len(node.PlannedEvents) {
		t.Errorf("Planned events came back as %v, want %v", after.PlannedEvents, node.PlannedEvents)
	}
	if !reflect.DeepEqual(after.Attachments, node.Attachments) {
		t.Errorf("Attachments came back as %v, want %v", after.Attachments, node.Attachments)
	}
	if !reflect.DeepEqual(after.Metadata, node.Metadata) {
		t.Errorf("Metadata came back as %v, want %v", after.Metadata, node.Metadata)
	}
	if after.CreatedBy != node.CreatedBy || !after.CreatedAt.Equal(node.CreatedAt) {
		t.Errorf("Authorship came back as %s/%v, want %s/%v",
			after.CreatedBy, after.CreatedAt, node.CreatedBy, node.CreatedAt)
	}
	if after.ModifiedBy != node.ModifiedBy || !after.ModifiedAt.Equal(node.ModifiedAt) {
		t.Errorf("Modification came back as %s/%v, want %s/%v",
			after.ModifiedBy, after.ModifiedAt, node.ModifiedBy, node.ModifiedAt)
	}
	if len(after.Children) != len(node.Children) {
		t.Errorf("The node came back with %d children, want %d", len(after.Children), len(node.Children))
	}
}

// keysOf names what an object actually carried, for a failure that has to say what it found.
func keysOf(object map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	return keys
}

// keysOfNodes does the same for a child map.
func keysOfNodes(children map[string]*core.Node) []string {
	keys := make([]string, 0, len(children))
	for key := range children {
		keys = append(keys, key)
	}
	return keys
}
