package cryptopals

import (
	"bufio"
	"encoding/hex"
	"os"
	"testing"
)

func TestS1C8(t *testing.T) {
	f, err := os.Open("challenge-data/8.txt")
	if err != nil {
		t.Error(err)
	}
	defer f.Close()

	var ciphers [][]byte

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		bytes, err := hex.DecodeString(scanner.Text())
		if err != nil {
			t.Error(err)
			break
		}
		ciphers = append(ciphers, bytes)
	}

	_, repeats := DetectAESECBMode(ciphers)
	if repeats != 4 {
		t.Errorf("failed to find repeats")
	}
}
