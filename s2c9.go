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

// pad a buffer using PKCS#7
func PadPKCS7(data []byte, blockSize int) []byte {
	padded := data
	extra := blockSize - (len(data) % blockSize)
	for i := 0; i < extra; i++ {
		padded = append(padded, byte(extra))
	}
	return padded
}

func UnpadPKCS7(data []byte) []byte {
	if len(data) == 0 {
		return data
	}
	lastByte := data[len(data)-1]
	for i := 1; byte(i) < lastByte; i++ {
		if data[len(data)-1-i] != lastByte {
			return data // the data is not padded
		}
	}

	return data[:len(data)-int(lastByte)]
}
