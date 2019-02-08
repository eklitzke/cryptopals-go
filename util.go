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
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	mrand "math/rand"
	"testing"
	"time"
)

func init() {
	mrand.Seed(time.Now().UTC().UnixNano())
}

// DecodeBase64File reads a base64 encoded file, and returns the decoded
// representation.
func DecodeBase64File(t *testing.T, fileName string) []byte {
	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		t.Errorf("failed to read file %s: %v", fileName, err)
		return nil
	}
	r := bytes.NewReader(data)
	enc := base64.NewDecoder(base64.StdEncoding, r)
	data, err = ioutil.ReadAll(enc)
	if err != nil {
		t.Errorf("failed to base64 decode file %s: %v", fileName, err)
		return nil
	}
	return data
}

// Generate a buffer with random bytes.
func RandomBytes(size int) []byte {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		panic(fmt.Sprintf("failed to read random bytes: %v", err))
	}
	return buf
}

// Generate a buffer with zero bytes.
func ZeroBytes(size int) []byte {
	return make([]byte, size)
}

// Wrapper for RandomBytes using AESBlockSize
func AESRandomBytes() []byte { return RandomBytes(AESBlockSize) }

// Wrapper for ZeroBytes using AESBlockSize
func AESZeroBytes() []byte { return ZeroBytes(AESBlockSize) }

func PrintChunks(prefix string, x []byte) {
	scanner, err := NewBlockScanner(x, AESBlockSize)
	if err != nil {
		fmt.Printf("error: failed to create scanner: %v\n", err)
		return
	}
	for scanner.Scan() {
		fmt.Printf("%s%v\n", prefix, scanner.Bytes())
	}
}
