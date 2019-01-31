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
