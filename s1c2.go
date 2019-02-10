// Copyright (C) 2019  Evan Klitzke <evan@eklitzke.org>

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package cryptopals

import (
	"encoding/hex"
	"fmt"
)

// FixedXOR computes the fixed XOR of two byte arrays, and saves the output to out.
func FixedXORInPlace(a, b, out []byte) error {
	if len(a) != len(b) {
		return fmt.Errorf("inputs have mismatched sizes %d and %d", len(a), len(b))

	}
	for i, x := range a {
		out[i] = x ^ b[i]
	}
	return nil
}

// FixedXOR computes the fixed XOR of two byte arrays.
func FixedXOR(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, fmt.Errorf("inputs have mismatched sizes %d and %d", len(a), len(b))
	}
	out := make([]byte, len(a))
	err := FixedXORInPlace(a, b, out)
	return out, err
}

// FixedXORHexString takes two equal-length hex strings and produces their
// hex-encoded XOR combination.
func FixedXORHexString(hexl, hexr string) (out string, err error) {
	var l, r []byte
	l, err = hex.DecodeString(hexl)
	if err != nil {
		return
	}
	r, err = hex.DecodeString(hexr)
	if err != nil {
		return
	}

	var bytes []byte
	bytes, err = FixedXOR(l, r)
	if err != nil {
		return
	}
	out = hex.EncodeToString(bytes)
	return
}
