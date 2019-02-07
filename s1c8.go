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

const AESBlockSize = 16

func DetectAESECBMode(ciphers [][]byte) ([]byte, int) {
	var bestCipher []byte
	bestRepeats := 0
	for _, cipher := range ciphers {
		chunkMap := make(map[string]int)
		for i := 0; i < len(cipher); i += AESBlockSize {
			chunk := string(cipher[i : i+AESBlockSize])
			chunkMap[chunk] = chunkMap[chunk] + 1
		}
		for _, v := range chunkMap {
			if v > bestRepeats {
				bestRepeats = v
				bestCipher = cipher
			}
		}
	}
	return bestCipher, bestRepeats
}
