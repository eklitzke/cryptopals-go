package cryptopals

const cipherSize = 16

func DetectAESECBMode(ciphers [][]byte) ([]byte, int) {
	var bestCipher []byte
	bestRepeats := 0
	for _, cipher := range ciphers {
		chunkMap := make(map[string]int)
		for i := 0; i < len(cipher); i += cipherSize {
			chunk := string(cipher[i : i+cipherSize])
			chunkMap[chunk] = chunkMap[chunk] + 1
		}
		for _, v := range chunkMap {
			if v > bestRepeats {
				bestRepeats = v
				bestCipher = cipher
			}
		}
	}
	return bestCipher, bestRepeats
}
