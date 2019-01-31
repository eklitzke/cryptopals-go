package cryptopals

import "testing"

func TestS1C3(t *testing.T) {
	const input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	const expected = "Cooking MC's like a pound of bacon"
	_, output, err := SingleByteXOR(input)
	if err != nil {
		t.Errorf("error from SingleByteXOR: %v", err)
	}
	if output != expected {
		t.Errorf("Got output %s, expected output %s", expected, output)
	}
}
