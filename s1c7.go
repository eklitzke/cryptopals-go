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
	"crypto/aes"
	"fmt"
)

// Encrypt data using AES in ECB mode. The block must be aligned.
func EncryptAESECB(data, key []byte) ([]byte, error) {
	if len(data)%AESBlockSize != 0 {
		return nil, fmt.Errorf("input EncryptAESECB data size %d not aligned to size %d", len(data), AESBlockSize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	out := make([]byte, len(data))
	for i := 0; i < len(data); i += AESBlockSize {
		block.Encrypt(out[i:i+AESBlockSize], data[i:i+AESBlockSize])
	}
	return out, nil
}

// Decrypt data using AES in ECB mode. The block must be aligned.
func DecryptAESECB(data, key []byte) ([]byte, error) {
	if len(data)%AESBlockSize != 0 {
		return nil, fmt.Errorf("input DecryptAESECB data size %d not aligned to size %d", len(data), AESBlockSize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	out := make([]byte, len(data))
	for i := 0; i < len(data); i += AESBlockSize {
		block.Decrypt(out[i:i+AESBlockSize], data[i:i+AESBlockSize])
	}
	return out, nil
}
