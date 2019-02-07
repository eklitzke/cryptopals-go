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
	"bufio"
	"encoding/hex"
	"os"
	"testing"

	"github.com/eklitzke/cryptopals"
)

func TestS1C8(t *testing.T) {
	f, err := os.Open("challenge-data/8.txt")
	if err != nil {
		t.Error(err)
	}
	defer f.Close()

	var ciphers [][]byte // a list of the decoded ciphers
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		bytes, err := hex.DecodeString(scanner.Text())
		if err != nil {
			t.Error(err)
			break
		}
		ciphers = append(ciphers, bytes)
	}

	const aesECBModeCipherCount = 4
	_, repeats, err := cryptopals.DetectAESECBMode(ciphers)
	if err != nil {
		t.Error(err)
	}
	if repeats != aesECBModeCipherCount {
		t.Errorf("failed to find repeats")
	}
}
