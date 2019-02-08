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

import "fmt"

// pad a buffer using PKCS#7
func PadPKCS7(data []byte, blockSize int) []byte {
	padded := data
	extra := blockSize - (len(data) % blockSize)
	for i := 0; i < extra; i++ {
		padded = append(padded, byte(extra))
	}
	return padded
}

// pad a buffer using PKCS#7 for AES
func PadAES(data []byte) []byte {
	return PadPKCS7(data, AESBlockSize)
}

// pad a buffer using PKCS#7 for AES
func PadAESString(s string) []byte {
	return PadPKCS7([]byte(s), AESBlockSize)
}

// undo PKCS#7 padding
func UnpadPKCS7(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return data, nil
	}
	lastByte := data[len(data)-1]
	trailingCount := int(lastByte)
	if trailingCount < 0 || trailingCount > AESBlockSize {
		return nil, fmt.Errorf("invalid trailing count %d (byte %d) from buffer %v", trailingCount, lastByte, data)
	}
	for i := 1; i < trailingCount; i++ {
		b := data[len(data)-i-1]
		if b != lastByte {
			return nil, fmt.Errorf("expected %d padding bytes, bad byte %v found with i=%d", trailingCount, b, i)
		}
	}

	return data[:len(data)-int(lastByte)], nil
}
