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

import "crypto/sha1"

func CountRepeats(data []byte, blockSize int) (int, error) {
	scanner, err := NewBlockScanner(data, blockSize)
	if err != nil {
		return -1, err
	}
	blockCounts := make(map[[sha1.Size]byte]int)
	for scanner.Scan() {
		block := scanner.Bytes()
		sum := sha1.Sum(block)
		blockCounts[sum] = blockCounts[sum] + 1
	}

	bestRepeats := 0
	for _, v := range blockCounts {
		if v > bestRepeats {
			bestRepeats = v
		}
	}
	return bestRepeats, nil
}

func CountAESRepeats(data []byte) (int, error) {
	return CountRepeats(data, AESBlockSize)
}

func DetectAESECBMode(ciphers [][]byte) ([]byte, int, error) {
	var bestCipher []byte
	bestRepeats := 0
	for _, cipher := range ciphers {
		repeats, err := CountAESRepeats(cipher)
		if err != nil {
			return nil, 0, err
		}
		if repeats > bestRepeats {
			bestCipher = cipher
			bestRepeats = repeats
		}
	}
	return bestCipher, bestRepeats, nil
}
