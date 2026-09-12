// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
// Non-commercial use only; see LICENSE.

// Package canon is the Go reader for SPEC.md §11.2: the canonical form every runtime must
// produce identically before an id means anything, and the id derivation over it.
//
// It is written from the specification and the corpus note alone and shares nothing with the
// Rust and C readers — not a parser, not a bignum, not a normalisation table. Three readers
// that agree on a frozen hex are evidence; one reader transliterated three times is not.
package canon

// Tag is the one-byte discriminator that opens every canonical value. The specification closes
// the set, so it is closed here: a Value is one of the shapes below and nothing else.
type Tag byte

// The tags, as §11.2 numbers them.
const (
	TagNull      Tag = 0x00
	TagBool      Tag = 0x01
	TagInt       Tag = 0x02
	TagDecimal   Tag = 0x03
	TagString    Tag = 0x04
	TagTimestamp Tag = 0x05
	TagDate      Tag = 0x06
	TagDuration  Tag = 0x07
	TagUUID      Tag = 0x08
	TagList      Tag = 0x10
	TagMap       Tag = 0x11
	TagRef       Tag = 0x20
	TagRecord    Tag = 0x21
)

// MaxDepth is the deepest node a conforming reader accepts. The root is at depth 0, and a node
// deeper than this is refused, never truncated.
const MaxDepth = 64

// IDSize is the width of a derived identity, and so of a reference body.
const IDSize = 32

// Value is anything the canonical form can carry. The interface is sealed by an unexported
// method: the shapes are the specification's and a caller cannot add one.
type Value interface {
	canonTag() Tag
}

// Null is the null scalar: a tag and zero length. It is a value, and distinct from absence.
type Null struct{}

// Bool is one byte, 0x00 or 0x01.
type Bool bool

// Int is an i64, two's complement, little-endian.
type Int int64

// String is UTF-8, NFC-normalised when encoded.
type String string

// Timestamp is i64 nanoseconds since the Unix epoch, UTC.
type Timestamp int64

// Date is i32 days since the Unix epoch.
type Date int32

// Duration is i64 nanoseconds.
type Duration int64

// UUID is 16 bytes in network order.
type UUID [16]byte

// Ref is a reference: the referent's id and nothing else. The one unframed value.
type Ref [IDSize]byte

// List preserves written order; order is semantic.
type List []Value

// Entry is one map entry. Keys are any value and compare as encodings.
type Entry struct {
	Key   Value
	Value Value
}

// Map is an unordered collection of entries; the encoder sorts them.
type Map []Entry

// Field is one declared field of a record. An absent field is declared but carries nothing: it
// is omitted from the encoding entirely, yet still counts as a declaration of its name.
type Field struct {
	Name   string
	Value  Value // nil when Absent
	Absent bool
}

// Record is an owned structured value: the fields are sorted by NFC name when encoded.
type Record []Field

func (Null) canonTag() Tag      { return TagNull }
func (Bool) canonTag() Tag      { return TagBool }
func (Int) canonTag() Tag       { return TagInt }
func (Decimal) canonTag() Tag   { return TagDecimal }
func (String) canonTag() Tag    { return TagString }
func (Timestamp) canonTag() Tag { return TagTimestamp }
func (Date) canonTag() Tag      { return TagDate }
func (Duration) canonTag() Tag  { return TagDuration }
func (UUID) canonTag() Tag      { return TagUUID }
func (Ref) canonTag() Tag       { return TagRef }
func (List) canonTag() Tag      { return TagList }
func (Map) canonTag() Tag       { return TagMap }
func (Record) canonTag() Tag    { return TagRecord }
