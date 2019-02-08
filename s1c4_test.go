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
	"os"
	"testing"
)

func TestS1C4(t *testing.T) {
	f, err := os.Open("challenge-data/4.txt")
	if err != nil {
		t.Errorf("failed to open file: %v\n", err)
	}
	defer f.Close()

	const expected = "Now that the party is jumping\n"
	output, err := SearchSingleByteXOR(f)
	if err != nil {
		t.Errorf("error from SearchSingleByteXOR: %v", err)
	}
	if output != expected {
		t.Errorf("Got output %s, expected output %s", expected, output)
	}
}
