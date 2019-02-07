package cryptopals_test

import (
	"strings"
	"testing"

	"github.com/eklitzke/cryptopals"
)

func TestS1C6(t *testing.T) {
	const haml = "this is a test"
	const hamr = "wokka wokka!!!"
	dist := cryptopals.HammingDistance([]byte(haml), []byte(hamr))
	const expectedDist = 37
	if dist != expectedDist {
		t.Errorf("expected hamming distance %d, got %d", expectedDist, dist)
	}

	data, err := cryptopals.DecodeBase64File("challenge-data/6.txt")
	if err != nil {
		t.Error(err)
	}
	_, plain, err := cryptopals.BreakRepeatingKeyXOR(data, cryptopals.BreakOpts{})
	if err != nil {
		t.Error(err)
	}
	if !strings.Contains(plain, "Play that funky music") {
		t.Errorf("bad plaintext: %s\n", plain)
	}
}
