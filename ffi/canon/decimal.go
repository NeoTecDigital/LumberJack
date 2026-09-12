// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
// Non-commercial use only; see LICENSE.

package canon

import (
	"encoding/binary"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"
)

// Decimal is a base-10 number in the normal form §11.2 hashes: a sign, an i32 exponent and a
// coefficient magnitude with every base-10 trailing zero moved into the exponent. The fields
// are unexported so the normal form is held from construction: 1.50, 1.5 and 15e-1 are one
// Decimal, and 0, -0 and 0.00 are another. The zero value is the decimal zero.
type Decimal struct {
	negative  bool
	exponent  int32
	magnitude *big.Int
}

// ParseDecimal reads `[+-]digits[.digits][(e|E)[+-]digits]`. Nothing on the path is a float:
// the digits become a big.Int and the exponent an integer, and a value whose exponent cannot
// fit the i32 the encoding carries is an error rather than a wrap.
func ParseDecimal(text string) (Decimal, error) {
	negative, mantissa, exponent, err := splitDecimal(text)
	if err != nil {
		return Decimal{}, err
	}
	digits := strings.TrimLeft(mantissa, "0")
	stripped := strings.TrimRight(digits, "0")
	if stripped == "" {
		return Decimal{}, nil // zero: sign 0, exponent 0, empty coefficient
	}
	exponent += int64(len(digits) - len(stripped))
	if exponent < math.MinInt32 || exponent > math.MaxInt32 {
		return Decimal{}, fmt.Errorf("canon: decimal %q: exponent %d does not fit an i32", text, exponent)
	}
	magnitude, ok := new(big.Int).SetString(stripped, 10)
	if !ok {
		return Decimal{}, fmt.Errorf("canon: decimal %q: coefficient is not decimal digits", text)
	}
	return Decimal{negative: negative, exponent: int32(exponent), magnitude: magnitude}, nil
}

// splitDecimal separates the sign, the mantissa digits with the point removed, and the
// exponent that makes those digits the whole number.
func splitDecimal(text string) (negative bool, digits string, exponent int64, err error) {
	body := text
	switch {
	case strings.HasPrefix(body, "-"):
		negative, body = true, body[1:]
	case strings.HasPrefix(body, "+"):
		body = body[1:]
	}
	if at := strings.IndexAny(body, "eE"); at >= 0 {
		exponent, err = strconv.ParseInt(body[at+1:], 10, 32)
		if err != nil {
			return false, "", 0, fmt.Errorf("canon: decimal %q: the exponent is not an i32", text)
		}
		body = body[:at]
	}
	integral, fraction, _ := strings.Cut(body, ".")
	if !allDigits(integral) || !allDigits(fraction) || integral+fraction == "" {
		return false, "", 0, fmt.Errorf("canon: decimal %q: not a decimal literal", text)
	}
	return negative, integral + fraction, exponent - int64(len(fraction)), nil
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// body is the decimal's canonical body: the sign byte, the i32 little-endian exponent, then
// the coefficient magnitude as minimal big-endian bytes — empty for zero.
func (d Decimal) body() []byte {
	var magnitude []byte
	if d.magnitude != nil {
		magnitude = d.magnitude.Bytes()
	}
	out := make([]byte, 0, 5+len(magnitude))
	out = append(out, boolByte(d.negative))
	out = binary.LittleEndian.AppendUint32(out, uint32(d.exponent))
	return append(out, magnitude...)
}

func boolByte(b bool) byte {
	if b {
		return 0x01
	}
	return 0x00
}
