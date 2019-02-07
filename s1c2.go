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
