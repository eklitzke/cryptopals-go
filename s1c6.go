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
	"math"
	"sort"
)

type BreakOpts struct {
	minKey int
	maxKey int
	search int
}

func (b BreakOpts) fillDefaults() BreakOpts {
	opts := b
	if opts.minKey == 0 {
		opts.minKey = 2
	}
	if opts.maxKey == 0 {
		opts.maxKey = 40
	}
	if opts.search == 0 {
		opts.search = 5
	}
	return opts
}

func HammingDistance(x, y []byte) int {
	var diff int
	for i, xc := range x {
		// xor the bits in the two bytes
		xdiff := int(xc ^ y[i])

		// count the number of differing bits
		for j := 1; j <= xdiff; j <<= 1 {
			if xdiff&j != 0 {
				diff++
			}
		}
	}
	return diff
}

func floatHammingDistance(a, b []byte) float64 {
	return float64(HammingDistance(a, b))
}

func bytesToChunks(s []byte, chunkSize int) [][]byte {
	var chunks [][]byte
	for i := 0; i < len(s); i += chunkSize {
		end := i + chunkSize
		if end > len(s) {
			end = len(s)
		}
		chunks = append(chunks, s[i:end])
	}
	return chunks
}

func transposeChunks(s []byte, chunkSize int) [][]byte {
	chunks := make([][]byte, chunkSize)
	for i, b := range s {
		chunks[i%chunkSize] = append(chunks[i%chunkSize], b)
	}
	return chunks
}

func getKeySizeError(s []byte, keySize int) (float64, error) {
	chunks := bytesToChunks(s, keySize)
	chunk1 := chunks[0]
	chunk2 := chunks[1]
	chunk3 := chunks[2]
	if len(chunk3) != len(chunk1) {
		return 0., fmt.Errorf("chunk1 had size %d, chunk3 had size %d", len(chunk1), len(chunk3))
	}
	diff := floatHammingDistance(chunk1, chunk2)
	diff += floatHammingDistance(chunk2, chunk3)
	diff += floatHammingDistance(chunk3, chunk1)
	return diff / float64(keySize), nil

}

type keyCandidate struct {
	keyLen int
	error  float64
}

type byError []keyCandidate

func (s byError) Len() int           { return len(s) }
func (s byError) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
func (s byError) Less(i, j int) bool { return s[i].error < s[j].error }

func BreakRepeatingKeyXOR(s []byte, opts BreakOpts) ([]byte, string, error) {
	opts = opts.fillDefaults()
	var candidates []keyCandidate
	for keySize := opts.minKey; keySize <= opts.maxKey; keySize++ {
		dist, err := getKeySizeError(s, keySize)
		if err != nil {
			return nil, "", err
		}
		candidates = append(candidates, keyCandidate{keyLen: keySize, error: dist})
	}
	sort.Sort(byError(candidates))
	candidates = candidates[:opts.search]
	bestError := math.MaxFloat64
	var bestKey []byte

outer:
	for _, cand := range candidates {
		blocks := transposeChunks(s, cand.keyLen)
		var totalErr float64
		var key []byte
		for _, block := range blocks {
			k, diff, _, solveErr := solveSingleByteXor(block)
			if solveErr != nil {
				continue outer
			}
			key = append(key, k)
			totalErr += diff
		}
		if totalErr < bestError {
			bestError = totalErr
			bestKey = key
		}
	}
	plaintext, err := EncryptRepeatingXOR(s, bestKey)
	if err != nil {
		return nil, "", err
	}
	return bestKey, string(plaintext), err
}
