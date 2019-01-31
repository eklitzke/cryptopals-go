package cryptopals

import (
	"encoding/hex"
	"testing"
)

func TestS1C5(t *testing.T) {
	const key = "ICE"
	const input = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	const expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
	output, err := EncryptRepeatingXOR(input, key)
	if err != nil {
		t.Errorf("error from EncryptRepeatingXOR: %v", err)
	}
	hexOut := hex.EncodeToString(output)
	if hexOut != expected {
		t.Errorf("Got output %s, expected output %s", hexOut, expected)
	}
}
