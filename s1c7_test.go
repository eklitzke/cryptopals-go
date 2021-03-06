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
	"bytes"
	"strings"
	"testing"
)

func TestS1C7(t *testing.T) {
	const key = "YELLOW SUBMARINE"

	data := DecodeBase64File(t, "challenge-data/7.txt")
	decrypted, err := DecryptAESECB(data, []byte(key))
	if err != nil {
		t.Error(err)
	}
	plaintext := string(decrypted)
	if !strings.Contains(plaintext, "Play that funky music") {
		t.Errorf("bad plaintext: %s\n", plaintext)
	}

	encrypted, err := EncryptAESECB(decrypted, []byte(key))
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(encrypted, data) {
		t.Errorf("encrypt failed")
	}
}
