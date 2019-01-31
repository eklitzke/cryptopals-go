package cryptopals

import (
	"bufio"
	"errors"
	"io"
	"math"
)

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
