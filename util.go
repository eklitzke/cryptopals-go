package cryptopals

import (
	"bufio"
	"encoding/base64"
	"io/ioutil"
	"os"
	"strings"
)

func DecodeBase64File(fileName string) ([]byte, error) {
	f, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var data string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		data += strings.TrimSpace(scanner.Text())
	}

	r := strings.NewReader(data)
	enc := base64.NewDecoder(base64.StdEncoding, r)
	return ioutil.ReadAll(enc)
}
