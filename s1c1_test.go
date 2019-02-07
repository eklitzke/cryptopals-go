package cryptopals_test

import (
	"testing"

	"github.com/eklitzke/cryptopals"
)

func TestS1C1(t *testing.T) {
	const input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	const expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	output, err := cryptopals.HexToBase64(input)
	if err != nil {
		t.Errorf("error from HexToBase64: %v", err)
	}
	if output != expected {
		t.Errorf("Got output %s, expected output %s", expected, output)
	}
}
