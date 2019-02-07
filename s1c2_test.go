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

package cryptopals_test

import (
	"testing"

	"github.com/eklitzke/cryptopals"
)

func TestS1C2(t *testing.T) {
	const hexl = "1c0111001f010100061a024b53535009181c"
	const hexr = "686974207468652062756c6c277320657965"
	const expected = "746865206b696420646f6e277420706c6179"
	output, err := cryptopals.FixedXOR(hexl, hexr)
	if err != nil {
		t.Errorf("error from FixedXOR: %v", err)
	}
	if output != expected {
		t.Errorf("Got output %s, expected output %s", expected, output)
	}
}
