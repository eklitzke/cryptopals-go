package cryptopals

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"strings"
	"testing"
)

type c17crypter struct {
	key []byte
	iv  []byte
}

func (c c17crypter) decrypt(in []byte) (out []byte, err error) {
	return DecryptAESCBC(in, c.key, c.iv)
}

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
		isValid := c.IsValid(cipher)
		if isValid {
			origByte := mask ^ target
			return cipher, origByte, nil
		}
		cipher[offset] ^= mask // undo flip bits
	}

	return nil, 0, fmt.Errorf("failed to force index %d to value %d", offset, target)
}

// solve the last block of the cipher
func (c c17crypter) solveLastBlock(cipher []byte) (out []byte, err error) {
	for i := 0; i < 16; i++ {
		// The block might already be valid, in which case our forcing
		// logic won't work. If that's the case, mutate the byte (and
		// correct the mutation later).
		extraFlip := false
		if c.IsValid(cipher) {
			cipher[len(cipher)-AESBlockSize-i-1] ^= 255
			extraFlip = true
		}

		// one to all of the preceeding padding bytes
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

		// undo the bit flip if we did one earlier
		if extraFlip {
			origByte ^= 255
		}

		out = append(out, origByte)
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
		r := strings.NewReader(line)
		dec := base64.NewDecoder(base64.StdEncoding, r)
		b, err := ioutil.ReadAll(dec)
		if err != nil {
			t.Error(err)
		}

		// pad the input
		padded := PadPKCS7(b, AESBlockSize)

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
			break
		}
	}
}
