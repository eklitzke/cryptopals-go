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
	"crypto/cipher"
)

// CTR represents a CTR cipher.
type CTR struct {
	block  cipher.Block
	stream []byte
}

// CTROpts represent options used to create a CTR.
type CTROpts struct {
	Key       []byte // initial key bytes
	KeyString string // key bytes as a string
	Nonce     uint64 // initial nonce value
	Ctr       uint64 // initial counter value
}

// NewCTR creates a new CTR.
func NewCTR(opts CTROpts) (*CTR, error) {
	if opts.KeyString != "" {
		opts.Key = []byte(opts.KeyString)
	}

	block, err := aes.NewCipher(opts.Key)
	if err != nil {
		return nil, err
	}

	// allocate stream
	stream := make([]byte, AESBlockSize)

	// set the Nonce bits in stream
	i := 0
	for opts.Nonce != 0 {
		stream[i] = byte(opts.Nonce & 0xff)
		opts.Nonce >>= 8
		i++
	}

	// set the counter bits in stream
	i = 8
	for opts.Ctr != 0 {
		stream[i] = byte(opts.Ctr & 0xff)
		opts.Ctr >>= 8
		i++
	}

	return &CTR{
		block:  block,
		stream: stream,
	}, nil
}

// used by Reset
var zeroStream []byte

// allocate zeroStream
func init() { zeroStream = make([]byte, AESBlockSize) }

// Reset the internal stream.
func (c *CTR) Reset() { copy(c.stream, zeroStream) }

// Encrypt data.
func (c *CTR) Encrypt(in []byte) []byte {
	out := make([]byte, len(in))
	tmp := make([]byte, AESBlockSize)

	for i := 0; i < len(in); i += AESBlockSize {
		// encrypt the bytes in stream
		c.block.Encrypt(tmp, c.stream)

		// xor bytes in the next input block
		block := in[i : i+AESBlockSize]
		for j, b := range block {
			if i+j >= len(in) { // check for partial block
				break
			}
			out[i+j] = b ^ tmp[j] // copy xored byte
		}

		// increment the counter
		for j := AESBlockSize / 2; j < AESBlockSize; j++ {
			c.stream[j]++
			if c.stream[j] != 0 {
				break
			}
		}
	}
	return out
}

// Decrypt (same as encrypt, but provided for clarity).
func (c *CTR) Decrypt(in []byte) []byte { return c.Encrypt(in) }
