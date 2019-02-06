package cryptopals

import (
	"strings"
	"testing"
)

func TestS1C7(t *testing.T) {
	const key = "YELLOW SUBMARINE"

	data, err := decodeBase64File("challenge-data/7.txt")
	if err != nil {
		t.Error(err)
	}
	bytes, err := DecryptAESECB(data, []byte(key))
	if err != nil {
		t.Error(err)
	}
	if !strings.Contains(string(bytes), "Play that funky music") {
		t.Errorf("bad plaintext: %s\n", string(bytes))
	}
}
