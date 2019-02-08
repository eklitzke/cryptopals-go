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
	"errors"
)

type Encrypter interface {
	Encrypt([]byte) ([]byte, error)
}

type byteAtATimeECBEncrypter struct {
	key    []byte
	suffix []byte
}

func (b byteAtATimeECBEncrypter) Encrypt(data []byte) ([]byte, error) {
	data = append(data, b.suffix...)
	data = PadAES(data)
	return EncryptAESECB(data, b.key)
}

func DetectBlockSize(b Encrypter) (int, error) {
	for i := 2; i < 1000; i += 2 {
		blockSize := int(i / 2)
		buf := make([]byte, i)
		out, err := b.Encrypt(buf)
		if err != nil {
			return -1, err
		}
		if bytes.Equal(out[:blockSize], out[blockSize:blockSize*2]) {
			return blockSize, nil
		}
	}
	return -1, errors.New("failed to detect block size")

}

func BreakAESECB(b byteAtATimeECBEncrypter) (known []byte, err error) {
	var blockSize int
	blockSize, err = DetectBlockSize(b)
	if err != nil {
		return
	}

	buf := PadAES(make([]byte, MinOracleDetectionSize))
	var mode EncryptionMode
	mode, err = EncryptionModeOracle(buf)
	if err != nil {
		return
	}
	if mode != ECB {
		err = errors.New("expected ECB mode")
		return
	}

	var cipher, c []byte

outer:
	for i := 0; ; i++ {
		shortBlock := make([]byte, blockSize-1-(i%blockSize))
		cipher, err = b.Encrypt(shortBlock)
		if err != nil {
			return
		}
		offset := int(len(known) / blockSize)
		start := offset * blockSize
		end := start + blockSize
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
