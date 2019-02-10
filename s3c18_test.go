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
	"encoding/base64"
	"io/ioutil"
	"strings"
	"testing"
)

func TestS3C18(t *testing.T) {
	const test = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
	r := strings.NewReader(test)
	dec := base64.NewDecoder(base64.StdEncoding, r)
	b, err := ioutil.ReadAll(dec)
	if err != nil {
		t.Error(err)
	}

	ctr := NewCTR([]byte("YELLOW SUBMARINE"))
	out, err := ctr.Decrypt(b)
	if err != nil {
		t.Error(err)
	}

	plaintext := string(out)
	if !strings.Contains(plaintext, "Ice, Ice, baby") {
		t.Error("failed to decrypt ctr")
	}
}
