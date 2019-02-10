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
	"io/ioutil"
	"strings"
	"testing"
)

type c17crypter struct {
	key []byte
	iv  []byte
}

// decrypt input
func (c c17crypter) decrypt(in []byte) (out []byte, err error) {
	return DecryptAESCBC(in, c.key, c.iv)
}

// encrypt input
func (c c17crypter) encrypt(in []byte) (out []byte, iv []byte, err error) {
	out, err = EncryptAESCBC(in, c.key, c.iv)
	iv = c.iv
	return
}

// IsValid checks if the input is valid based only on the correctness of its
// padding.
func (c c17crypter) IsValid(in []byte) bool {
	out, err := c.decrypt(in)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		return false
	}

	_, err = UnpadPKCS7(out)
	return err == nil
}

// Generate a mask that can be applied using xor to convert x to y.
func (c c17crypter) generateCopyMask(x, y byte) byte {
	var finalMask byte
	var i uint
	for i = 0; i < 8; i++ {
		mask := byte(1 << i)
		if (x & mask) != (y & mask) {
			finalMask |= mask
		}
	}
	return finalMask
}

// force the byte at a given index to take on a particular value
func (c c17crypter) forceIndexToValue(cipher []byte, offset int, target byte) ([]byte, byte, error) {
	// try all the ways to flip the next byte until we get the desired
	// padding byte
	offset -= AESBlockSize
	for j := 0; j < 256; j++ {
		mask := byte(j)
		cipher[offset] ^= mask // flip bits
		if c.IsValid(cipher) {
			if target == 1 {
				// handle edge case for the right-most byte
				cipher[offset-1] ^= 1
				v := c.IsValid(cipher)
				cipher[offset-1] ^= 1
				if !v {
					goto undo
				}
			}
			origByte := mask ^ target
			return cipher, origByte, nil
		}

	undo:
		cipher[offset] ^= mask // undo flip bits
	}

	return nil, 0, fmt.Errorf("failed to force index %d to value %d", offset, target)
}

// solve the last block of the cipher
func (c c17crypter) solveLastBlock(cipher []byte) (out []byte, err error) {
	// if the block is already padded, force it to be unpadded
	extraFlip := false
	if c.IsValid(cipher) {
		cipher[len(cipher)-AESBlockSize-1] ^= 1
		extraFlip = true
	}

	// solve all bytes
	for i := 0; i < 16; i++ {
		// increment all of the preceeding padding bytes
		b := byte(i)
		mask := c.generateCopyMask(b, b+1)
		for j := 0; j < i; j++ {
			offset := len(cipher) - j - AESBlockSize - 1
			cipher[offset] ^= mask
		}

		// force the byte to be our desired padding byte
		var origByte byte
		cipher, origByte, err = c.forceIndexToValue(cipher, len(cipher)-i-1, b+1)
		if err != nil {
			return nil, err
		}

		out = append(out, origByte)
	}

	// undo extra flip
	if extraFlip {
		out[0] ^= 1
	}

	return out, nil
}

// solveC17Puzzle finds the original cleartext solution only given the ciphertext and iv
func (c c17crypter) solvePuzzle(cipher, iv []byte) ([]byte, error) {
	finalSize := len(cipher)

	// prepend the iv to the ciphertext
	cipher = append(iv, cipher...)

	var origBytes []byte
	for len(origBytes) < finalSize {
		// make a copy of the truncated ciphertext
		toCopy := len(cipher) - len(origBytes)
		enc := make([]byte, toCopy)
		copy(enc, cipher[:toCopy])

		// solve the block
		clear, err := c.solveLastBlock(enc)
		if err != nil {
			return nil, err
		}
		origBytes = append(origBytes, clear...)
	}

	ReverseInPlace(origBytes)
	return origBytes, nil
}

func TestS3C17(t *testing.T) {
	b, err := ioutil.ReadFile("challenge-data/17.txt")
	if err != nil {
		t.Error(err)
	}

	c := c17crypter{key: AESRandomBytes(), iv: AESRandomBytes()}

	lines := strings.Split(string(b), "\n")
	lines = lines[:len(lines)-1]

	// decode the puzzle, and pad all of the lines
	for i, line := range lines {
		raw := DecodeBase64String(t, line)

		// pad the input
		padded := PadPKCS7(raw, AESBlockSize)

		// encrypt the cleartext
		cipher, iv, err := c.encrypt(padded)
		if err != nil {
			t.Error(err)
			break
		}

		solved, err := c.solvePuzzle(cipher, iv)
		if err != nil {
			t.Errorf("failed to solve puzzle %d, solvePuzzle encountered error %v\n", i, err)
			break
		}

		if !bytes.Equal(padded, solved) {
			t.Errorf("failed to solve puzzle %d, bytes don't match", i)
			PrintBlocks("ORIG: ", padded)
			PrintBlocks("SOLV: ", solved)
			break
		}
	}
}
