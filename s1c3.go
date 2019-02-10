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
	"encoding/hex"
	"errors"
	"math"
	"unicode"
)

// English character frequencies, according to
// http://www.sxlist.com/techref/method/compress/etxtfreq.htm
var englishRuneFrequencies = map[rune]float64{
	'a': 0.08167,
	'b': 0.01492,
	'c': 0.02782,
	'd': 0.04253,
	'e': 0.12702,
	'f': 0.02228,
	'g': 0.02015,
	'h': 0.06094,
	'i': 0.06966,
	'j': 0.00153,
	'k': 0.00772,
	'l': 0.04025,
	'm': 0.02406,
	'n': 0.06749,
	'o': 0.07507,
	'p': 0.01929,
	'q': 0.00095,
	'r': 0.05987,
	's': 0.06327,
	't': 0.09056,
	'u': 0.02758,
	'v': 0.00978,
	'w': 0.02360,
	'x': 0.00150,
	'y': 0.01974,
	'z': 0.00074,
}

// get the rune frequencies for a string
func getRuneFrequencies(s string) (out map[rune]float64) {
	out = make(map[rune]float64)
	counts := map[rune]int{}
	for _, r := range s {
		counts[r]++
	}
	l := float64(len(s))
	for r, c := range counts {
		out[r] = float64(c) / l
	}
	return out
}

// get the squared error between the input frequencies and the reference english
// frequencies
func squaredRuneFrequencyError(in map[rune]float64) float64 {
	var diff float64
	for r, freq := range englishRuneFrequencies {
		seen := in[r]
		delta := freq - seen
		diff += delta * delta
	}
	return diff
}

// SingleByteXOR cracks an input cipher string (which is hex-encoded) that has
// been encrypted using a single byte XOR scheme.
func SingleByteXOR(cipher string) (key byte, diff float64, plaintext string, err error) {
	var data []byte
	data, err = hex.DecodeString(cipher)
	if err != nil {
		return
	}
	return solveSingleByteXor(data)
}

func solveSingleByteXor(data []byte) (key byte, diff float64, plaintext string, err error) {
	var found bool
	var bestKey byte
	bestError := math.MaxFloat64

outer:
	for i := 0; i < 256; i++ {
		out := make([]byte, len(data))
		key = byte(i)
		for j, c := range data {
			r := rune(key ^ c)
			if !unicode.IsPrint(r) && !unicode.IsSpace(r) {
				// shortcut if the output produces non-printable
				// characters
				continue outer
			}
			out[j] = byte(key ^ c)
		}
		plain := string(out)
		freqs := getRuneFrequencies(plain)
		error := squaredRuneFrequencyError(freqs)
		if error < bestError {
			bestError = error
			bestKey = key
			plaintext = plain
			found = true
		}
	}
	if !found {
		err = errors.New("no candidates found")
		return
	}
	diff = bestError
	key = bestKey
	return
}
