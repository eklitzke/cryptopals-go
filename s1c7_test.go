package cryptopals_test

import (
	"strings"
	"testing"

	"github.com/eklitzke/cryptopals"
)

func TestS1C7(t *testing.T) {
	const key = "YELLOW SUBMARINE"

	data, err := cryptopals.DecodeBase64File("challenge-data/7.txt")
	if err != nil {
		t.Error(err)
	}
	bytes, err := cryptopals.DecryptAESECB(data, []byte(key))
	if err != nil {
		t.Error(err)
	}
	if !strings.Contains(string(bytes), "Play that funky music") {
		t.Errorf("bad plaintext: %s\n", string(bytes))
	}
}
