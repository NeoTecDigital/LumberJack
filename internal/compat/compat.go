// Written by Richard Christopher, Copyright 2026 NeoTec, LLC

// Package compat is the whole of what generic LumberJack knows about stores written by the
// builds that carried product code: byte marks, sealing labels and key names. It is a table of
// names and values, with no product logic, so the engine can keep reading and protecting those
// stores without importing the products that wrote them. See docs/extension-api.md §7.
package compat

// ACLReferenceRevision is the contract revision every stored domain ACL reference carries. A state
// document holding ReferenceMark was written by a build that understood references, and a build
// from before them must not open it: such a document is written under the STATE-3 banner and the
// references envelope versions (docs/extension-api.md §7.3).
const ACLReferenceRevision = "lj.domain.acl.ref/1"

// ReferenceMark is the byte sequence a stored ACL reference always marshals to: its keys sort
// contractRevision first, and the same text inside a JSON string cannot match because its quotes
// are escaped.
const ReferenceMark = `"contractRevision":"` + ACLReferenceRevision + `"`

// State levels select the plaintext banner and the encrypted envelope version. A store's level
// never goes down under generic LumberJack: level = max(level read at open, ReferenceMark present).
const (
	StateLevelTable      = 2 // LUMBERJACK-STATE-2; envelope 3 (legacy label) or 5 (neutral)
	StateLevelReferences = 3 // LUMBERJACK-STATE-3; envelope 4 (legacy label) or 6 (neutral)
)

// Label holds the authenticated prefixes chosen by the host. Zero is the built-in neutral format.
type Label struct{ HostState, HostObjects string }

func (l Label) StatePrefix() string {
	if l == (Label{}) {
		return "lumberjack/storage/v5/"
	}
	return l.HostState
}

func (l Label) ObjectsPrefix() string {
	if l == (Label{}) {
		return "lumberjack/objects/v2/"
	}
	return l.HostObjects
}

func (l Label) EnvelopeVersion(level int) int {
	version := 3
	if level >= StateLevelReferences {
		version++
	}
	if l == (Label{}) {
		version += 2
	}
	return version
}

// EnvelopeFormat identifies only the wire family. The old family did not store a label name.
func EnvelopeFormat(version int) (neutral bool, level int, known bool) {
	if version < 3 || version > 6 {
		return false, 0, false
	}
	level = StateLevelTable
	if version%2 == 0 {
		level = StateLevelReferences
	}
	return version >= 5, level, true
}

// Object key file versions and record flags (docs/extension-api.md §7.5).
const (
	ObjectKeyFileLegacy  = 1 // a host label
	ObjectKeyFileNeutral = 2 // neutral label
	ObjectRecordLegacy   = 1 // sealed under the key file's label
	ObjectRecordNeutral  = 2 // sealed under the neutral prefix
)

// OwnedScopeMarker is the CommandReceipts key that marks the root of an owned scope in a store
// written before the split. Generic LumberJack hides every node carrying it from generic reads and
// guards its subtree even when its owning extension is absent (docs/extension-api.md §4.2).
const OwnedScopeMarker = "lumberjack.staged.scope/v1"

// RecordOrder is the order a node record's keys were written in by the builds that carried
// product fields on core.Node: encoding/json's struct order of that Node. The record codec emits a
// record's keys in this order — typed fields and slot keys alike — then any other slot keys sorted,
// then "children", so a store those builds wrote re-encodes to the same bytes
// (docs/extension-api.md §7.1).
var RecordOrder = []string{
	"personal_bindings", "id", "type", "kind", "name", "parents", "events", "planned_events", "users",
	"entries", "attachments", "metadata", "command_receipts", "correspondence", "application_sessions",
	"subscriptions", "conversations", "access_policies", "access_grants", "account_security",
	"mfa_challenges", "admitted_commands", "created_by", "created_at", "modified_by", "modified_at",
}

// OutboxOrder is the same for the root's "correspondence" object.
var OutboxOrder = []string{"feed", "pending", "inbox", "delivered", "last_delivery", "outbound"}
