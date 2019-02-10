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
	"strings"
	"testing"
)

func TestC320(t *testing.T) {
	lines := DecodeBase64Lines(t, "challenge-data/20.txt")

	ctr, err := NewCTR(CTROpts{Key: AESRandomBytes()})
	if err != nil {
		t.Error(err)
	}

	ciphers := make([][]byte, len(lines))
	for i, line := range lines {
		//fmt.Printf("i=%d plain: %s\n", i, string(line))
		ciphers[i] = ctr.Encrypt(line)
		ctr.Reset()
	}

	minLength := len(ciphers[0])
	for _, cipher := range ciphers {
		if len(cipher) < minLength {
			minLength = len(cipher)
		}
	}

	var concat []byte
	for _, cipher := range ciphers {
		concat = append(concat, cipher[:minLength]...)
	}

	_, out, err := BreakRepeatingKeyXOR(concat, BreakOpts{minKey: minLength, maxKey: minLength + 1})
	if err != nil {
		t.Error(err)
	}
	if !strings.Contains(out, "happened to peace") {
		t.Error("failed")
	}
}
