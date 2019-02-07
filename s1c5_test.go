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
	"encoding/hex"
	"testing"

	"github.com/eklitzke/cryptopals"
)

func TestS1C5(t *testing.T) {
	const key = "ICE"
	const input = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	const expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
	output, err := cryptopals.EncryptRepeatingXOR([]byte(input), []byte(key))
	if err != nil {
		t.Errorf("error from EncryptRepeatingXOR: %v", err)
	}
	hexOut := hex.EncodeToString(output)
	if hexOut != expected {
		t.Errorf("Got output %s, expected output %s", hexOut, expected)
	}
}
