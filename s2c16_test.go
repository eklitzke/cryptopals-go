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
	"fmt"
	"net/url"
	"strings"
	"testing"
)

var semiQuote = url.QueryEscape(";")
var equalsQuote = url.QueryEscape("=")

func badURLQuote(s string) string {
	var out string
	for _, c := range s {
		switch c {
		case ';':
			out += semiQuote
		case '=':
			out += equalsQuote
		default:
			out += string(c)
		}
	}
	return out
}

func insertUserData(s string) string {
	const prefix = "comment1=cooking%20MCs;userdata="
	const suffix = ";comment2=%20like%20a%20pound%20of%20bacon"
	return prefix + badURLQuote(s) + suffix
}

type c16crypter struct {
	key []byte
	iv  []byte
}

func (c c16crypter) Encode(s string) ([]byte, error) {
	quoted := PadAESString(insertUserData(s))
	return EncryptAESCBC(quoted, c.key, c.iv)

}

func (c c16crypter) IsAdmin(x []byte) bool {
	out, err := DecryptAESCBC(x, c.key, c.iv)
	if err != nil {
		fmt.Printf("error decrypting: %v\n", err)
		return false
	}
	s := string(out)
	for _, chunk := range strings.Split(s, ";") {
		pieces := strings.SplitN(chunk, "=", 2)
		if len(pieces) < 2 {
			continue
		}
		if pieces[0] == "admin" && pieces[1] == "true" {
			return true
		}
	}
	return false
}

// FlipBit flips the low order bit in a byte.
func FlipBit(b byte) byte {
	const one = byte(1)
	if b&one == one {
		return b & 254
	}
	return b | 1
}

func TestS2C16(t *testing.T) {
	const quotedString = "comment1=cooking%20MCs;userdata=test%3B%3Dtest;comment2=%20like%20a%20pound%20of%20bacon"
	if insertUserData("test;=test") != quotedString {
		t.Error("badURLQuote failed")
	}

	c := c16crypter{
		key: AESRandomBytes(),
		iv:  AESRandomBytes(),
	}
	// ; = 59
	// : = 58 = 59 & 254
	// = = 61
	// < = 60 = 61 & 254
	enc, err := c.Encode(":admin<true")
	if err != nil {
		t.Error(err)
	}
	if c.IsAdmin(enc) {
		t.Error("string should not have been admin")
	}

	// replace the : with ;
	enc[16] = FlipBit(enc[16])

	// replace the < with =
	enc[22] = FlipBit(enc[22])

	if !c.IsAdmin(enc) {
		t.Error("failed to set admin status")
	}
}
