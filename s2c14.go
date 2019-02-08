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
)

type randomPrefixECBCrypter struct {
	key, prefix, suffix []byte
}

func (r randomPrefixECBCrypter) Encrypt(data []byte) ([]byte, error) {
	x := append(r.prefix, data...)
	x = append(x, r.suffix...)
	x = PadAES(x)
	return EncryptAESECB(x, r.key)
}

// Keep encrypting chunks of zeros until the output has three repeated blocks.
// That case will look something like this:
//
// encrypting: [194 39 166 33 205 103 31 169 51 169 2 106 239 26 133 188]
// encrypting: [56 181 46 152 238 143 117 172 76 184 60 30 107 0 0 0]
// encrypting: [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
// encrypting: [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
// encrypting: [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
// encrypting: [82 111 108 108 105 110 39 32 105 110 32 109 121 32 53 46]
// encrypting: ...
// decrypted: [20 152 177 96 190 83 133 11 204 105 240 151 86 194 92 71]
// decrypted: [185 181 241 191 21 157 40 144 6 44 188 64 63 61 168 41]
// decrypted: [177 45 87 153 174 38 248 187 118 82 229 204 111 137 127 131]
// decrypted: [177 45 87 153 174 38 248 187 118 82 229 204 111 137 127 131]
// decrypted: [177 45 87 153 174 38 248 187 118 82 229 204 111 137 127 131]
// decrypted: [69 245 6 240 244 110 43 103 252 180 220 185 114 73 236 20]
// decrypted: ...
//
// We can then use the number of zeros inserted to figure out the size of the
// random prefix.
func DetectECBPrefixSize(r randomPrefixECBCrypter) (int, error) {
	for i := 1; ; i++ {
		buf := make([]byte, i)
		out, err := r.Encrypt(buf)
		if err != nil {
			return -1, err
		}
		scanner, err := NewBlockScanner(out, AESBlockSize)
		if err != nil {
			return -1, err
		}
		var lastChunk []byte
		firstRepeatBlock := 0
		repeats := 1
		maxRepeats := 1
		maxRepeatsBlock := 0
		for j := 0; scanner.Scan(); j++ {
			if bytes.Equal(scanner.Bytes(), lastChunk) {
				repeats++
				if repeats > maxRepeats {
					maxRepeats = repeats
					maxRepeatsBlock = firstRepeatBlock
				}
			} else {
				repeats = 1
				firstRepeatBlock = j
				lastChunk = scanner.Bytes()
			}
		}
		if maxRepeats >= 3 {
			return AESBlockSize*(3+maxRepeatsBlock) - i, nil
		}
	}
}

// Like BreakAESECB, but with a prefix
func BreakAESECBWithPrefix(b randomPrefixECBCrypter) (known []byte, err error) {
	var cipher, c []byte

	var prefixSize int
	prefixSize, err = DetectECBPrefixSize(b)
	if err != nil {
		return
	}

	initialPad := AESBlockSize - prefixSize
	for initialPad < 0 {
		initialPad += AESBlockSize
	}

outer:
	for i := 0; ; i++ {
		shortBlock := make([]byte, initialPad+AESBlockSize-1-(i%AESBlockSize))
		cipher, err = b.Encrypt(shortBlock)
		if err != nil {
			return
		}
		offset := int(len(known) / AESBlockSize)
		start := prefixSize + initialPad + offset*AESBlockSize
		end := start + AESBlockSize
		for j := 0; j < 256; j++ {
			char := byte(j)
			block := append(shortBlock, known...)
			block = append(block, char)
			c, err = b.Encrypt(block)
			if err != nil {
				return
			}
			if bytes.Equal(cipher[start:end], c[start:end]) {
				known = append(known, char)
				continue outer
			}
		}
		break
	}
	known = known[:len(known)-1]
	return
}
