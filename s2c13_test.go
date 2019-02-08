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
	"fmt"
	"net/url"
	"strings"
	"testing"
)

func profileFor(email string) string {
	email = strings.Replace(email, "=", "", -1)
	email = strings.Replace(email, "&", "", -1)
	return fmt.Sprintf("email=%s&uid=10&role=user", email)
}

type cutAndPasteCrypter struct {
	key []byte
}

func (c cutAndPasteCrypter) Encode(email string) ([]byte, error) {
	s := profileFor(email)
	return EncryptAESECB(PadAESString(s), c.key)
}

func (c cutAndPasteCrypter) Decode(data []byte) (url.Values, error) {
	plain, err := DecryptAESECB(data, c.key)
	if err != nil {
		return nil, err
	}
	plain, err = UnpadPKCS7(plain)
	if err != nil {
		return nil, err
	}
	return url.ParseQuery(string(plain))
}

func isAdmin(vals url.Values) bool {
	return vals.Get("role") == "admin"
}

func TestS2C13(t *testing.T) {
	crypt := cutAndPasteCrypter{key: AESRandomBytes()}

	// generate email, where first 16 bytes are email=xxxxxx .. and the next 16 are xxxx + padding
	frontPad := AESBlockSize - len("email=")
	email := strings.Repeat("x", frontPad) + "admin"
	trailingCount := 2*AESBlockSize - len(email) - len("email=")
	trailingByte := byte(trailingCount)
	email += string(bytes.Repeat([]byte{trailingByte}, trailingCount))

	// encode the bogus email address
	data, err := crypt.Encode(email)
	if err != nil {
		t.Error(err)
	}

	// figure out the encrypted value of "admin"
	encryptedAdmin := data[AESBlockSize : AESBlockSize*2]

	// generate a string that has the first 32 bytes like: email=xxxxx...uid=10role=
	frontPad = 2*AESBlockSize - len("email=&uid=10&role=")
	email = strings.Repeat("x", frontPad)

	// encode that string
	data, err = crypt.Encode(string(email))
	if err != nil {
		t.Error(err)
	}

	// cut and paste
	adminBytes := append(data[:2*AESBlockSize], encryptedAdmin...)

	// check our work
	vals, err := crypt.Decode(adminBytes)
	if err != nil {
		t.Error(err)
	}

	if !isAdmin(vals) {
		t.Errorf("failed to construct admin profile: %v", vals)
	}
}
