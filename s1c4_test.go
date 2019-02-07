package cryptopals_test

import (
	"os"
	"testing"

	"github.com/eklitzke/cryptopals"
)

func TestS1C4(t *testing.T) {
	f, err := os.Open("challenge-data/4.txt")
	if err != nil {
		t.Errorf("failed to open file: %v\n", err)
	}
	defer f.Close()

	const expected = "Now that the party is jumping\n"
	output, err := cryptopals.SearchSingleByteXOR(f)
	if err != nil {
		t.Errorf("error from SearchSingleByteXOR: %v", err)
	}
	if output != expected {
		t.Errorf("Got output %s, expected output %s", expected, output)
	}
}
