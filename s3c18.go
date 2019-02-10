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

type CTR struct {
	key, stream []byte
}

func NewCTR(key []byte) *CTR {
	return &CTR{
		key:    key,
		stream: make([]byte, AESBlockSize),
	}
}

var zeroStream []byte

func init() {
	zeroStream = make([]byte, AESBlockSize)
}

// Reset the internal stream.
func (c *CTR) Reset() {
	copy(c.stream, zeroStream)
}

func (c *CTR) Encrypt(in []byte) ([]byte, error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, err
	}

	out := make([]byte, len(in))
	tmp := make([]byte, AESBlockSize)

	enc := NewECBEncrypter(block)
	for i := 0; i < len(in); i += AESBlockSize {
		enc.CryptBlocks(tmp, []byte(c.stream))
		block := in[i : i+AESBlockSize]
		for j, b := range block {
			if i+j >= len(in) {
				break
			}
			out[i+j] = b ^ tmp[j]
		}

		// increment the counter
		for j := 8; j < 16; j++ {
			c.stream[j]++
			if c.stream[j] != 0 {
				break
			}
		}
	}
	return out, nil
}

func (c *CTR) Decrypt(in []byte) ([]byte, error) {
	return c.Encrypt(in)
}
