package cryptopals

import (
	"encoding/base64"
	"encoding/hex"
)

// HexToBase64 converts a hex string to its base64 encoded representation.
func HexToBase64(s string) (b64 string, err error) {
	var data []byte
	data, err = hex.DecodeString(s)
	if err != nil {
		return
	}
	b64 = base64.StdEncoding.EncodeToString(data)
	return
}
