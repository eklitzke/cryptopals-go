package cryptopals_test

import (
	"bufio"
	"encoding/hex"
	"os"
	"testing"

	"github.com/eklitzke/cryptopals"
)

const aesECBModeCipherCount = 4

func TestS1C8(t *testing.T) {
	f, err := os.Open("challenge-data/8.txt")
	if err != nil {
		t.Error(err)
	}
	defer f.Close()

	var ciphers [][]byte // a list of the decoded ciphers
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		bytes, err := hex.DecodeString(scanner.Text())
		if err != nil {
			t.Error(err)
			break
		}
		ciphers = append(ciphers, bytes)
	}

	_, repeats := cryptopals.DetectAESECBMode(ciphers)
	if repeats != aesECBModeCipherCount {
		t.Errorf("failed to find repeats")
	}
}
