package cryptopals

import (
	"os"
	"testing"
)

func TestS1C4(t *testing.T) {
	file, err := os.Open("challenge-data/4.txt")
	if err != nil {
		t.Errorf("failed to open file: %v\n", err)
	}
	const expected = "Now that the party is jumping\n"
	output, err := SearchSingleByteXOR(file)
	if err != nil {
		t.Errorf("error from SearchSingleByteXOR: %v", err)
	}
	if output != expected {
		t.Errorf("Got output %s, expected output %s", expected, output)
	}
}
