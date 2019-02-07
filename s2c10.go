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
)

// Encrypt data using AES in CBC mode, given a key and IV.
func EncryptAESCBC(data, key, iv []byte) (out []byte, err error) {
	scanner, err := NewBlockScanner(data, AESBlockSize)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	enc := NewECBEncrypter(block)
	dst := make([]byte, AESBlockSize)
	for scanner.Scan() {
		chunk := scanner.Bytes()
		chunk, err = FixedXOR(chunk, iv)
		if err != nil {
			return
		}
		enc.CryptBlocks(dst, chunk)

		out = append(out, dst...)
		iv = dst
	}
	return
}

// Decrypt data using AES in CBC mode, given a key and IV.
func DecryptAESCBC(data, key, iv []byte) (out []byte, err error) {
	scanner, err := NewBlockScanner(data, AESBlockSize)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	dec := NewECBDecrypter(block)

	dst := make([]byte, AESBlockSize)
	for scanner.Scan() {
		chunk := scanner.Bytes()
		dec.CryptBlocks(dst, chunk)
		dst, err = FixedXOR(dst, iv)
		if err != nil {
			return nil, err
		}
		out = append(out, dst...)
		iv = chunk
	}
	return
}
