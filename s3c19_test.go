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
	"fmt"
	"testing"
)

func TestC319(t *testing.T) {
	const printCipher = false

	ctr, err := NewCTR(CTROpts{Key: AESRandomBytes()})
	if err != nil {
		t.Error(err)
		return
	}
	lines := DecodeBase64Lines(t, "challenge-data/19.txt")
	for i, line := range lines {
		if printCipher {
			fmt.Printf("i = %d: %s\n", i, string(line))
			out := ctr.Encrypt(line)
			PrintBlocks("", out)
			PrintLine("-")
		} else {
			ctr.Encrypt(line)
			ctr.Reset()
		}
	}
}
