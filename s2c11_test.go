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
	"math/rand"
	"testing"

	"github.com/eklitzke/cryptopals"
)

// generate an array of bytes with size between [minSize, maxSize)
func variableRandomBytes(minSize, maxSize int) []byte {
	size := minSize + rand.Intn(maxSize-minSize)
	return RandomBytes(size)
}

func scrambleAndEncrypt(data []byte) (cipher []byte, mode cryptopals.EncryptionMode, err error) {
	key := AESRandomBytes()

	buf := variableRandomBytes(5, 11)
	buf = append(buf, data...)
	buf = append(buf, variableRandomBytes(5, 11)...)
	buf = cryptopals.PadAES(buf)

	if rand.Intn(2) == 0 {
		mode = cryptopals.ECB
	} else {
		mode = cryptopals.CBC
	}
	coin := rand.Intn(2)
	if coin == 0 {
		mode = cryptopals.ECB
		cipher, err = cryptopals.EncryptAESECB(buf, key)
	} else {
		iv := AESRandomBytes()
		mode = cryptopals.CBC
		cipher, err = cryptopals.EncryptAESCBC(buf, key, iv)
	}
	return
}

func TestS2C11(t *testing.T) {
	data := ZeroBytes(cryptopals.MinOracleDetectionSize)
	for i := 0; i < 100; i++ {
		cipher, mode, err := scrambleAndEncrypt(data)
		if err != nil {
			t.Error(err)
		}

		detectedMode, err := cryptopals.EncryptionModeOracle(cipher)
		if err != nil {
			t.Error(err)
		}
		if mode != detectedMode {
			t.Errorf("failed to correctly detect mode")
		}
	}

	_, err := cryptopals.EncryptionModeOracle(ZeroBytes(cryptopals.MinOracleDetectionSize - 1))
	if err != cryptopals.OracleBufferTooSmallErr {
		t.Errorf("expected error OracleBufferTooSmallErr, instead got: %v", err)
	}
}
