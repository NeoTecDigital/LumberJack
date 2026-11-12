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

// Label selects the additional-data prefixes an encrypted store is sealed under.
type Label uint8

const (
	// LabelLegacy is the label every encrypted store written before the split carries. It stays the
	// write default for the transition release (owner decision Q3(a)).
	LabelLegacy Label = iota
	// LabelNeutral is the product-free label. A store written under it cannot be opened by the cut
	// build, which is why it is opt-in.
	LabelNeutral
)

// StatePrefix is the additional-data prefix of an encrypted state file under the label.
func (label Label) StatePrefix() string {
	if label == LabelNeutral {
		return "lumberjack/storage/v5/"
	}
	return "momentum/storage/v3/"
}

// ObjectsPrefix is the additional-data prefix of an object store's key file under the label.
func (label Label) ObjectsPrefix() string {
	if label == LabelNeutral {
		return "lumberjack/objects/v2/"
	}
	return "momentum/objects/v1/"
}

// EnvelopeVersion is the encrypted state envelope version for a label and a state level.
func (label Label) EnvelopeVersion(level int) int {
	version := 3
	if level >= StateLevelReferences {
		version = 4
	}
	if label == LabelNeutral {
		version += 2
	}
	return version
}

// EnvelopeLabel reads an envelope version back into its label and state level; ok is false for a
// version no build has written.
func EnvelopeLabel(version int) (label Label, level int, ok bool) {
	switch version {
	case 3, 4:
		label = LabelLegacy
	case 5, 6:
		label = LabelNeutral
	default:
		return LabelLegacy, 0, false
	}
	level = StateLevelTable
	if version%2 == 0 {
		level = StateLevelReferences
	}
	return label, level, true
}

// Object key file versions and record flags (docs/extension-api.md §7.5).
const (
	ObjectKeyFileLegacy  = 1 // label LabelLegacy
	ObjectKeyFileNeutral = 2 // label LabelNeutral
	ObjectRecordLegacy   = 1 // sealed under the key file's label
	ObjectRecordNeutral  = 2 // sealed under LabelNeutral's prefix
)

// OwnedScopeMarker is the CommandReceipts key that marks the root of an owned scope in a store
// written before the split. Generic LumberJack hides every node carrying it from generic reads and
// guards its subtree (docs/extension-api.md §4.2); its owners are manifest-domain and
// momentum-personal.
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
