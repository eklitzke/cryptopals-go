package cryptopals

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"
	"testing"
)

// Return the list of bit flips needed to make x look like y.
func generateBitFlipsToCopy(x, y byte) []uint {
	var out []uint
	var i uint
	for i = 0; i < 8; i++ {
		mask := byte(1 << i)
		if (x & mask) != (y & mask) {
			out = append(out, i)
		}
	}
	return out
}

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

var errFailedToFindPaddingByte = errors.New("failed to find padding byte")

func (c c17crypter) detectPaddingByte(in []byte) (byte, error) {
	// test each padding bit
	var offset int
	for i := 1; i <= AESBlockSize; i++ {
		// find the offset to flip
		offset = len(in) - i - AESBlockSize - 1

		// flip the bit
		in[offset] = FlipLastBit(in[offset])

		isValid := c.IsValid(in)

		// undo bit flip
		in[offset] = FlipLastBit(in[offset])

		// is it valid?
		if isValid {
			return byte(i), nil
		}
	}
	return 0, errFailedToFindPaddingByte
}

var errFailedToForceIndex = errors.New("failed to force index to value")

// force the byte at a given index to take on a particular value
func (c c17crypter) forceIndexToValue(cipher []byte, offset int, target byte) ([]byte, byte, error) {
	paddingByte := target - 1

	// now try all the ways to flip the next byte until we get the
	// desired padding byte
	for j := 0; j < 256; j++ {
		model := byte(j)
		cipher[offset] ^= model // flip bits
		isValid := c.IsValid(cipher)
		if isValid {
			var origByte byte
			if paddingByte != 0 {
				origByte = paddingByte ^ model
			} else {
				origByte = model ^ target
			}
			return cipher, origByte, nil
		}
		cipher[offset] ^= model // undo flip bits
	}

	return nil, 0, errFailedToForceIndex
}

// solveC17Puzzle finds the original cleartext solution only given the ciphertext and iv
func solveC17Puzzle(c c17crypter, cipher, iv []byte) ([]byte, error) {
	finalSize := len(cipher)

	// prepend the iv
	cipher = append(iv, cipher...)

	// copy the original cipher
	savedCipher := make([]byte, len(cipher))
	copy(savedCipher, cipher)

	// detect the padding byte
	paddingByte, err := c.detectPaddingByte(cipher)
	if err != nil {
		return nil, err
	}

	// the original bytes, which we'll generate in reverse order
	var origBytes []byte
	for i := 0; i < int(paddingByte); i++ {
		origBytes = append(origBytes, paddingByte)
	}

	// finish solving a block
	finishBlock := func(cipher []byte, paddingByte byte) (err error) {
		var offset int
		for paddingByte < 16 {
			// add one to all of the padding bytes
			flips := generateBitFlipsToCopy(paddingByte, paddingByte+1)
			for j := 0; j <= int(paddingByte); j++ {
				offset = len(cipher) - j - AESBlockSize - 1
				for _, flip := range flips {
					cipher[offset] = FlipNthBit(cipher[offset], flip)
				}
			}

			var origByte byte
			cipher, origByte, err = c.forceIndexToValue(cipher, offset, paddingByte+1)
			if err != nil {
				return err
			}

			// the original byte is xor(paddingByte, model)
			origBytes = append(origBytes, origByte)
			paddingByte++
		}
		return nil
	}

	// finish solving the last block
	if err := finishBlock(cipher, paddingByte); err != nil {
		return nil, err
	}

	// solve the remaining blocks
	for len(origBytes) < finalSize {
		toCopy := len(savedCipher) - len(origBytes)
		cipher := make([]byte, toCopy)
		copy(cipher, savedCipher[:toCopy])

		// go to the last byte in the next origBytes
		offset := finalSize - len(origBytes) - 1

		// force the last byte to be one
		var lastByte byte
		cipher, lastByte, err = c.forceIndexToValue(cipher, offset, 1)
		if err != nil {
			return nil, err
		}
		origBytes = append(origBytes, lastByte)
		if err := finishBlock(cipher, 1); err != nil {
			return nil, err
		}
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

		solved, err := solveC17Puzzle(c, cipher, iv)
		if err != nil {
			t.Errorf("failed to solve puzzle %d, solvePuzzle encountered error %v\n", i, err)
			break
		}

		if !bytes.Equal(padded, solved) {
			t.Errorf("failed to solve puzzle %d, bytes don't match", i)
			PrintChunks("ORIG: ", padded)
			PrintChunks("SOLV: ", solved)
			break
		}
	}
}
