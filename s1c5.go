package cryptopals

import "errors"

// EncryptRepeatingXOR encrypts a string against a key by repeatedly XORing the
// text.
func EncryptRepeatingXOR(input, key []byte) (out []byte, err error) {
	keyLen := len(key)
	if len(input) < keyLen {
		err = errors.New("cannot encrypt text shorter than key")
		return
	}

	keyb := []byte(key)
	for i, c := range []byte(input) {
		k := keyb[i%keyLen]
		out = append(out, c^k)
	}
	return
}
