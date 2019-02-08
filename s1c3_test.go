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

import "testing"

func TestS1C3(t *testing.T) {
	const input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	const expected = "Cooking MC's like a pound of bacon"
	_, _, output, err := SingleByteXOR(input)
	if err != nil {
		t.Errorf("error from SingleByteXOR: %v", err)
	}
	if output != expected {
		t.Errorf("Got output %s, expected output %s", expected, output)
	}
}
