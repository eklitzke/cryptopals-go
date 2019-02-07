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
	"strings"
	"testing"

	"github.com/eklitzke/cryptopals"
)

func TestS2C10(t *testing.T) {
	const key = "YELLOW SUBMARINE"

	data, err := cryptopals.DecodeBase64File("challenge-data/10.txt")
	if err != nil {
		t.Error(err)
	}
	iv := make([]byte, cryptopals.AESBlockSize)
	decrypted, err := cryptopals.DecryptAESCBC(data, []byte(key), iv)
	if err != nil {
		t.Error(err)
	}
	plaintext := string(decrypted)
	if !strings.Contains(plaintext, "go white boy go") {
		t.Errorf("failed to decrypt string")
	}
}
