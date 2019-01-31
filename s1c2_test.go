package cryptopals

import "testing"

func TestS1C2(t *testing.T) {
	hexl := "1c0111001f010100061a024b53535009181c"
	hexr := "686974207468652062756c6c277320657965"
	expected := "746865206b696420646f6e277420706c6179"
	output, err := FixedXOR(hexl, hexr)
	if err != nil {
		t.Errorf("error from FixedXOR: %v", err)
	}
	if output != expected {
		t.Errorf("Got output %s, expected output %s", expected, output)
	}
}
