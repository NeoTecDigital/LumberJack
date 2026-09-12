// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
// Non-commercial use only; see LICENSE.

package canon

import (
	"encoding/hex"

	"lukechampine.com/blake3"
)

// ID is a derived identity: BLAKE3 over the canonical kind name and the canonical identity
// record, 32 bytes. Never minted, never sequential, a function of content alone.
type ID [IDSize]byte

// Hex is the lowercase hex the corpus freezes ids as.
func (id ID) Hex() string { return hex.EncodeToString(id[:]) }

// Kind is what identity derivation needs of a kind: its fully-qualified name and which fields
// bear identity. A nil IDFrom is a value kind — every field participates. A non-nil empty
// IDFrom is read literally as an entity kind with no identity-bearing field; the specification
// does not name that shape.
type Kind struct {
	FQN    string
	IDFrom []string
}

// DeriveID computes id(instance) = BLAKE3(canonical(fqn) || canonical(identity record)). The
// identity record holds the fields id_from names, or every field for a value kind; a
// duplicate among fields it does not name is not seen here.
func DeriveID(k Kind, r Record) (ID, error) {
	identity, err := identityRecord(k, r)
	if err != nil {
		return ID{}, err
	}
	kindBytes, err := Encode(String(k.FQN))
	if err != nil {
		return ID{}, err
	}
	recordBytes, err := Encode(identity)
	if err != nil {
		return ID{}, err
	}
	return ID(blake3.Sum256(append(kindBytes, recordBytes...))), nil
}

func identityRecord(k Kind, r Record) (Record, error) {
	if k.IDFrom == nil {
		return r, nil
	}
	names, err := identityNames(k.IDFrom)
	if err != nil {
		return nil, err
	}
	identity := make(Record, 0, len(names))
	for _, name := range names {
		field, present, err := identityField(name, r)
		if err != nil {
			return nil, err
		}
		if present {
			identity = append(identity, field)
		}
	}
	return identity, nil
}

// identityNames is id_from after NFC. A name listed twice is a malformed kind, refused as a
// duplicate rather than deduplicated.
func identityNames(idFrom []string) ([]string, error) {
	seen := make(map[string]struct{}, len(idFrom))
	names := make([]string, 0, len(idFrom))
	for _, raw := range idFrom {
		name := nfc(raw)
		if _, dup := seen[name]; dup {
			return nil, refuse(DuplicateField, "id_from names %q twice", name)
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	return names, nil
}

// identityField selects the one field carrying name, NFC on both sides. None is an unknown
// identity field; two is a duplicate, never first-wins; one that is absent contributes
// nothing and is reported as not present.
func identityField(name string, r Record) (field Field, present bool, err error) {
	found := -1
	for i := range r {
		if nfc(r[i].Name) != name {
			continue
		}
		if found >= 0 {
			return Field{}, false, refuse(DuplicateField, "the identity field %q is declared twice", name)
		}
		found = i
	}
	if found < 0 {
		return Field{}, false, refuse(UnknownIdentityField, "id_from names %q, which the record does not declare", name)
	}
	if r[found].Absent {
		return Field{}, false, nil
	}
	return Field{Name: name, Value: r[found].Value}, true, nil
}
