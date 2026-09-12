// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
// Non-commercial use only; see LICENSE.

package canon

import (
	"bytes"
	"encoding/hex"
	"fmt"
)

// CheckCase holds one case against this reader: the frozen hex must be reproduced, the named
// refusal raised at the named locus, and a self-reference must equal the derived id. A
// disagreement is returned, not resolved — the corpus is the oracle.
func CheckCase(c Case) error {
	switch c.Expect {
	case "accepted":
		return checkAccepted(c)
	case "refused":
		return checkRefused(c)
	case "id_only":
		return checkIDOnly(c)
	}
	return fmt.Errorf("unknown expect %q", c.Expect)
}

func checkAccepted(c Case) error {
	got, err := Encode(c.Value)
	if err != nil {
		return fmt.Errorf("canonical() refused: %w", err)
	}
	if err := matchHex("canonical", c.CanonicalHex, got); err != nil {
		return err
	}
	if c.Kind == nil {
		if c.IDHex != "" {
			return fmt.Errorf("id_hex without a kind")
		}
		return nil
	}
	id, err := deriveFromCase(c)
	if err != nil {
		return fmt.Errorf("id derivation refused: %w", err)
	}
	if err := matchHex("id", c.IDHex, id[:]); err != nil {
		return err
	}
	return checkSelfRef(c, id)
}

// checkRefused: without a kind, canonical() must refuse; with one, id derivation must.
func checkRefused(c Case) error {
	if c.Kind == nil {
		_, err := Encode(c.Value)
		return expectRefusal("canonical()", err, c.Error)
	}
	_, err := deriveFromCase(c)
	return expectRefusal("id derivation", err, c.Error)
}

// checkIDOnly: canonical() must refuse with the named error and the id must still derive.
func checkIDOnly(c Case) error {
	_, encodeErr := Encode(c.Value)
	if err := expectRefusal("canonical()", encodeErr, c.Error); err != nil {
		return err
	}
	id, err := deriveFromCase(c)
	if err != nil {
		return fmt.Errorf("id derivation refused: %w", err)
	}
	return matchHex("id", c.IDHex, id[:])
}

func deriveFromCase(c Case) (ID, error) {
	record, ok := c.Value.(Record)
	if !ok {
		return ID{}, fmt.Errorf("a kind on a %T; only a record derives an id", c.Value)
	}
	return DeriveID(*c.Kind, record)
}

func matchHex(what, wantHex string, got []byte) error {
	if wantHex == "" {
		return fmt.Errorf("no %s_hex to compare against", what)
	}
	want, err := hex.DecodeString(wantHex)
	if err != nil {
		return fmt.Errorf("%s_hex is not hex: %w", what, err)
	}
	if !bytes.Equal(want, got) {
		return fmt.Errorf("%s differs\n  want %x\n  got  %x", what, want, got)
	}
	return nil
}

func expectRefusal(locus string, err error, wantName string) error {
	if _, known := ParseCode(wantName); !known {
		return fmt.Errorf("the corpus names an error %q this reader does not know", wantName)
	}
	if err == nil {
		return fmt.Errorf("%s accepted, want refusal %s", locus, wantName)
	}
	code, refused := CodeOf(err)
	if !refused {
		return fmt.Errorf("%s failed but did not refuse: %v (want %s)", locus, err, wantName)
	}
	if code.String() != wantName {
		return fmt.Errorf("%s refused with %s, want %s", locus, code, wantName)
	}
	return nil
}

// checkSelfRef asserts the named field is a reference carrying the case's own derived id.
func checkSelfRef(c Case, id ID) error {
	if c.SelfRef == "" {
		return nil
	}
	record := c.Value.(Record) // deriveFromCase already proved the shape
	for _, f := range record {
		if nfc(f.Name) != nfc(c.SelfRef) {
			continue
		}
		ref, isRef := f.Value.(Ref)
		if !isRef {
			return fmt.Errorf("self_ref field %q is a %T, not a ref", c.SelfRef, f.Value)
		}
		if ID(ref) != id {
			return fmt.Errorf("self_ref field %q carries %x, the derived id is %x", c.SelfRef, ref[:], id[:])
		}
		return nil
	}
	return fmt.Errorf("self_ref names %q, which the record does not declare", c.SelfRef)
}

// CheckPair holds one pair: the two cases' canonical bytes or ids are the same or differ, as
// the corpus states.
func CheckPair(p Pair, byName map[string]Case) error {
	a, known := byName[p.A]
	if !known {
		return fmt.Errorf("names the unknown case %q", p.A)
	}
	b, known := byName[p.B]
	if !known {
		return fmt.Errorf("names the unknown case %q", p.B)
	}
	left, right, err := pairSides(p.Compare, a, b)
	if err != nil {
		return err
	}
	same := bytes.Equal(left, right)
	switch p.Expect {
	case "same":
		if !same {
			return fmt.Errorf("%s bytes differ, want same (%s)", p.Compare, p.Rule)
		}
	case "differ":
		if same {
			return fmt.Errorf("%s bytes are the same, want differ (%s)", p.Compare, p.Rule)
		}
	default:
		return fmt.Errorf("unknown pair expect %q", p.Expect)
	}
	return nil
}

func pairSides(compare string, a, b Case) ([]byte, []byte, error) {
	switch compare {
	case "canonical":
		left, err := Encode(a.Value)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", a.Name, err)
		}
		right, err := Encode(b.Value)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", b.Name, err)
		}
		return left, right, nil
	case "id":
		left, err := deriveFromCase(a)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", a.Name, err)
		}
		right, err := deriveFromCase(b)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", b.Name, err)
		}
		return left[:], right[:], nil
	}
	return nil, nil, fmt.Errorf("unknown compare %q", compare)
}
