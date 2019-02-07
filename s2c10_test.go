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
	"crypto/rand"
	"fmt"
	"strings"
	"testing"

	"github.com/eklitzke/cryptopals"
)

func RandomBytes(size int) []byte {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		panic(fmt.Sprintf("failed to read random bytes: %v", err))
	}
	return buf
}

func ZeroBytes(size int) []byte {
	return make([]byte, size)
}

func AESRandomBytes() []byte {
	return RandomBytes(cryptopals.AESBlockSize)
}

func AESZeroBytes() []byte {
	return ZeroBytes(cryptopals.AESBlockSize)
}

func TestS2C10(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")

	data, err := cryptopals.DecodeBase64File("challenge-data/10.txt")
	if err != nil {
		t.Error(err)
	}
	iv := AESZeroBytes()
	decrypted, err := cryptopals.DecryptAESCBC(data, key, iv)
	if err != nil {
		t.Error(err)
	}
	plaintext1 := string(decrypted)
	if !strings.Contains(plaintext1, "go white boy go") {
		t.Errorf("failed to decrypt string")
	}

	iv = AESRandomBytes()
	encrypted, err := cryptopals.EncryptAESCBC(decrypted, key, iv)
	if err != nil {
		t.Error(err)
	}
	decrypted, err = cryptopals.DecryptAESCBC(encrypted, key, iv)
	if err != nil {
		t.Error(err)
	}
	plaintext2 := string(decrypted)
	if plaintext1 != plaintext2 {
		//t.Errorf("strings are not equal: %s", plaintext2)
		t.Errorf("strings are not equal")
	}
}
