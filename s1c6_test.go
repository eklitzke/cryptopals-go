package cryptopals

import (
	"strings"
	"testing"
)

func TestS1C6(t *testing.T) {
	const haml = "this is a test"
	const hamr = "wokka wokka!!!"
	dist := HammingDistance([]byte(haml), []byte(hamr))
	const expectedDist = 37
	if dist != expectedDist {
		t.Errorf("expected hamming distance %d, got %d", expectedDist, dist)
	}

	data, err := decodeBase64File("challenge-data/6.txt")
	if err != nil {
		t.Error(err)
	}
	_, plain, err := BreakRepeatingKeyXOR(data, breakOpts{})
	if err != nil {
		t.Error(err)
	}
	if !strings.Contains(plain, "Play that funky music") {
		t.Errorf("bad plaintext: %s\n", plain)
	}
}
