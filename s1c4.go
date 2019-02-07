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
	"bufio"
	"errors"
	"io"
	"math"
)

// SearchSingleByteXOR searches a list of lines from a reader, and finds the
// line encrypted using a single byte XOR cipher.
func SearchSingleByteXOR(r io.Reader) (string, error) {
	scanner := bufio.NewScanner(r)
	bestError := math.MaxFloat64
	var bestPlain string
	for scanner.Scan() {
		line := scanner.Text()
		_, diff, plain, err := SingleByteXOR(line)
		if err != nil {
			continue
		}
		if diff < bestError {
			bestError = diff
			bestPlain = plain
		}
	}
	if bestPlain == "" {
		return "", errors.New("no solutions found")
	}
	return bestPlain, nil
}
