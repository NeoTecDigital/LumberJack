// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
// Non-commercial use only; see LICENSE.

// The rules of §11.2 as this reader understands them, stated without the corpus. Each is a
// byte string the specification's prose fixes, or a refusal it names; the corpus test then
// says whether the other readers read the same prose the same way.
package canon

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"lukechampine.com/blake3"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func encoded(t *testing.T, v Value) []byte {
	t.Helper()
	b, err := Encode(v)
	if err != nil {
		t.Fatalf("Encode(%#v): %v", v, err)
	}
	return b
}

func refusedWith(t *testing.T, err error, want Code) {
	t.Helper()
	code, refused := CodeOf(err)
	if !refused || code != want {
		t.Fatalf("want refusal %s, got %v", want, err)
	}
}

// The BLAKE3 the id formula names is the one whose empty digest begins af1349b9.
func TestBlake3IsTheStandardOne(t *testing.T) {
	sum := blake3.Sum256(nil)
	want := "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
	if hex.EncodeToString(sum[:]) != want {
		t.Fatalf("BLAKE3(\"\") = %x, want %s", sum, want)
	}
}

// Framing: a scalar's prefix counts bytes, a collection's counts items, a ref has none.
func TestFramingCountsWhatTheShapeSays(t *testing.T) {
	if got := encoded(t, String("ab")); !bytes.Equal(got, mustHex(t, "04 02000000 6162")) {
		t.Errorf("string: %x", got)
	}
	// One element of nine bytes: the prefix is 1, not 9.
	if got := encoded(t, List{Int(1)}); !bytes.Equal(got[:5], mustHex(t, "10 01000000")) {
		t.Errorf("list prefix: %x", got[:5])
	}
	ref := Ref{}
	if got := encoded(t, ref); len(got) != 33 || got[0] != byte(TagRef) {
		t.Errorf("ref: %d bytes starting %#x, want 33 starting 0x20", len(got), got[0])
	}
}

func TestIntegersAreTwosComplementLittleEndian(t *testing.T) {
	if got := encoded(t, Int(-1)); !bytes.Equal(got, mustHex(t, "02 08000000 ffffffffffffffff")) {
		t.Errorf("int -1: %x", got)
	}
	if got := encoded(t, Date(-2147483648)); !bytes.Equal(got, mustHex(t, "06 04000000 00000080")) {
		t.Errorf("date i32::MIN: %x", got)
	}
}

func TestDecimalNormalForm(t *testing.T) {
	same := [][2]string{{"1.50", "1.5"}, {"150", "1.5e2"}, {"0", "-0"}, {"0.00", "0e5"}, {"+2", "2"}, {"00100", "1E2"}}
	for _, pair := range same {
		a, errA := ParseDecimal(pair[0])
		b, errB := ParseDecimal(pair[1])
		if errA != nil || errB != nil {
			t.Fatalf("%q/%q: %v %v", pair[0], pair[1], errA, errB)
		}
		if !bytes.Equal(encoded(t, a), encoded(t, b)) {
			t.Errorf("%q and %q encode differently", pair[0], pair[1])
		}
	}
	d, _ := ParseDecimal("-2.30")
	if got := encoded(t, d); !bytes.Equal(got, mustHex(t, "03 06000000 01 ffffffff 17")) {
		t.Errorf("-2.30: %x", got)
	}
	if got := encoded(t, Decimal{}); !bytes.Equal(got, mustHex(t, "03 05000000 00 00000000")) {
		t.Errorf("zero value: %x", got)
	}
	for _, bad := range []string{"", "-", ".", "1.2.3", "abc", "1e", "1e99999999999", "0x10", " 1"} {
		if _, err := ParseDecimal(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

// NFC is the whole algorithm, not the Latin-1 corner the corpus exercises: decomposed Hangul
// and a Devanagari sequence with a composition exclusion both come out as Unicode says.
func TestStringsAreNFCBeyondLatin1(t *testing.T) {
	cases := [][2]string{
		{"café", "café"},
		{"한", "한"},   // Hangul jamo -> precomposed syllable
		{"Å", "Å"},    // A + ring above -> Å
		{"Å", "Å"},     // angstrom sign is a singleton decomposition
		{"क़", "क़"},    // composition exclusion stays decomposed
		{"ȩ́", "ȩ́"}, // canonical reordering of marks (ccc 230, 202)
	}
	for _, c := range cases {
		if !bytes.Equal(encoded(t, String(c[0])), encoded(t, String(c[1]))) {
			t.Errorf("%q and %q encode differently", c[0], c[1])
		}
	}
}

func nested(depth int, inner Value) Value {
	for i := 0; i < depth; i++ {
		inner = List{inner}
	}
	return inner
}

func TestDepthIsTestedOnTheNode(t *testing.T) {
	if _, err := Encode(nested(MaxDepth, Int(0))); err != nil {
		t.Errorf("scalar at %d: %v", MaxDepth, err)
	}
	if _, err := Encode(nested(MaxDepth, List{})); err != nil {
		t.Errorf("empty list at %d: %v", MaxDepth, err)
	}
	_, err := Encode(nested(MaxDepth+1, Int(0)))
	refusedWith(t, err, NestingTooDeep)
	// A ref is a leaf, but it is still a node: at 65 it is refused like any other.
	_, err = Encode(nested(MaxDepth+1, Ref{}))
	refusedWith(t, err, NestingTooDeep)
	// Map keys are nodes one deeper than the map.
	_, err = Encode(nested(MaxDepth, Map{{Key: Int(0), Value: Int(0)}}))
	refusedWith(t, err, NestingTooDeep)
}

func TestRecordsRefuseDuplicatesAndOmitAbsent(t *testing.T) {
	_, err := Encode(Record{{Name: "café", Value: Int(1)}, {Name: "café", Absent: true}})
	refusedWith(t, err, DuplicateField)
	absent := encoded(t, Record{{Name: "a", Absent: true}})
	if !bytes.Equal(absent, mustHex(t, "21 00000000")) {
		t.Errorf("absent field counted: %x", absent)
	}
	null := encoded(t, Record{{Name: "a", Value: Null{}}})
	if bytes.Equal(absent, null) {
		t.Error("absent and present-null collide")
	}
}

func TestMapKeysCompareAsEncodings(t *testing.T) {
	one, _ := ParseDecimal("1.5")
	two, _ := ParseDecimal("1.50")
	_, err := Encode(Map{{Key: one, Value: Int(1)}, {Key: two, Value: Int(2)}})
	refusedWith(t, err, DuplicateMapKey)
	got := encoded(t, Map{{Key: String("ab"), Value: Null{}}, {Key: String("b"), Value: Null{}}})
	if !bytes.HasPrefix(got[5:], mustHex(t, "04 01000000 62")) {
		t.Errorf("\"b\" should precede \"ab\": %x", got)
	}
}

func TestIdentityReadsOnlyWhatIDFromNames(t *testing.T) {
	entity := Kind{FQN: "acme::thing", IDFrom: []string{"name", "tag"}}
	withAbsent, err := DeriveID(entity, Record{{Name: "name", Value: String("x")}, {Name: "tag", Absent: true}})
	if err != nil {
		t.Fatal(err)
	}
	only, err := DeriveID(Kind{FQN: "acme::thing", IDFrom: []string{"name"}}, Record{{Name: "name", Value: String("x")}})
	if err != nil {
		t.Fatal(err)
	}
	if withAbsent != only {
		t.Error("an absent identity field contributed something")
	}
	_, err = DeriveID(entity, Record{{Name: "name", Value: String("x")}})
	refusedWith(t, err, UnknownIdentityField)
	_, err = DeriveID(Kind{FQN: "k", IDFrom: []string{"a", "a"}}, Record{{Name: "a", Value: Int(1)}})
	refusedWith(t, err, DuplicateField)
	// A value kind sees every field, so a duplicate anywhere refuses the id too.
	_, err = DeriveID(Kind{FQN: "k"}, Record{{Name: "a", Value: Int(1)}, {Name: "a", Value: Int(2)}})
	refusedWith(t, err, DuplicateField)
	// An entity kind does not see a duplicate among the fields it does not name.
	if _, err := DeriveID(Kind{FQN: "k", IDFrom: []string{"a"}}, Record{{Name: "a", Value: Int(1)}, {Name: "z", Value: Int(1)}, {Name: "z", Value: Int(2)}}); err != nil {
		t.Errorf("a duplicate non-identity field reached the id: %v", err)
	}
}

// The corpus carries numbers as strings because a JSON number would be a float64 by the time
// a generic decoder is done with it. A number where a string belongs is refused, not rounded.
func TestCorpusGrammarNeverDecodesThroughFloat(t *testing.T) {
	for _, raw := range []string{
		`{"t":"int","v":9007199254740993}`,
		`{"t":"timestamp","v":1700000000000000000}`,
		`{"t":"date","v":19000}`,
		`{"t":"decimal","v":1.5}`,
		`{"t":"int","v":"1","extra":true}`,
	} {
		var r rawValue
		if err := strictUnmarshal([]byte(raw), &r); err == nil {
			if _, err := r.build(); err == nil {
				t.Errorf("%s built", raw)
			}
		}
	}
	var r rawValue
	if err := strictUnmarshal([]byte(`{"t":"int","v":"9007199254740993"}`), &r); err != nil {
		t.Fatal(err)
	}
	v, err := r.build()
	if err != nil || v != Int(9007199254740993) {
		t.Errorf("exact i64 lost: %v %v", v, err)
	}
}
