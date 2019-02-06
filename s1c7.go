package cryptopals

import "crypto/aes"

func DecryptAESECB(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	dec := NewECBDecrypter(block)
	dst := make([]byte, len(data))
	dec.CryptBlocks(dst, data)
	return dst, nil
}
