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

func TestS2C14(t *testing.T) {
	r := randomPrefixECBCrypter{
		key:    AESRandomBytes(),
		prefix: variableRandomBytes(5, 50),
		suffix: DecodeBase64File(t, "challenge-data/12.txt"),
	}

	known, err := BreakAESECBWithPrefix(r)
	if err != nil {
		t.Error(err)
	}
	plaintext := string(known)
	if !strings.Contains(plaintext, "waving just to say hi") {
		t.Error("failed to break aes ecb with prefix")
	}
}
