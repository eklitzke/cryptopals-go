package cryptopals

import (
	"encoding/hex"
	"errors"
)

// FixedXOR takes two equal-length hex strings and produces their hex-encoded
// XOR combination.
func FixedXOR(hexl, hexr string) (out string, err error) {
	if len(hexl) != len(hexr) {
		err = errors.New("strings must be the same length")
		return
	}
	var l, r []byte
	l, err = hex.DecodeString(hexl)
	if err != nil {
		return
	}
	r, err = hex.DecodeString(hexr)
	if err != nil {
		return
	}

	var outb []byte
	for i, lb := range l {
		rb := r[i]
		outb = append(outb, lb^rb)
	}
	out = hex.EncodeToString(outb)
	return
}
