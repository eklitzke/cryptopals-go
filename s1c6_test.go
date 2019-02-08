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

func TestS1C6(t *testing.T) {
	const haml = "this is a test"
	const hamr = "wokka wokka!!!"
	dist := HammingDistance([]byte(haml), []byte(hamr))
	const expectedDist = 37
	if dist != expectedDist {
		t.Errorf("expected hamming distance %d, got %d", expectedDist, dist)
	}

	data := DecodeBase64File(t, "challenge-data/6.txt")
	_, plain, err := BreakRepeatingKeyXOR(data, BreakOpts{})
	if err != nil {
		t.Error(err)
	}
	if !strings.Contains(plain, "Play that funky music") {
		t.Errorf("bad plaintext: %s\n", plain)
	}
}
