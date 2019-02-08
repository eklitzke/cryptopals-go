package cryptopals

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"math/rand"
	"strings"
	"testing"
)

type c17crypter struct {
	key   []byte
	iv    []byte
	lines [][]byte
}

func (c c17crypter) encrypt(in []byte) (out []byte, iv []byte, err error) {
	// generate valid padding
	padded := PadPKCS7(in, AESBlockSize)
	fmt.Printf("padded bytes: %v\n", padded)
	PrintChunks("padded: ", padded)

	out, err = EncryptAESCBC(padded, c.key, c.iv)
	PrintChunks("encrypted: ", out)
	iv = c.iv
	return
}

func (c c17crypter) magic(ix int) (out []byte, iv []byte, err error) {
	fmt.Printf("======= magic %d\n", ix)
	fmt.Printf("plain string %s\n", string(c.lines[ix]))
	fmt.Printf("plain bytes: %v\n", c.lines[ix])
	return c.encrypt(c.lines[ix])
}

func (c c17crypter) Magic() (out []byte, iv []byte, err error) {
	return c.magic(rand.Intn(len(c.lines)))
}

func (c c17crypter) IsValid(in []byte) bool {
	out, err := DecryptAESCBC(in, c.key, c.iv)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		return false
	}

	PrintChunks("isvalid: ", out)
	//fmt.Println(string(out))
	_, err = UnpadPKCS7(out)
	//fmt.Printf("err is %v\n", err)
	return err == nil
}

func TestS3C17(t *testing.T) {
	b, err := ioutil.ReadFile("challenge-data/17.txt")
	if err != nil {
		t.Error(err)
	}

	lines := strings.Split(string(b), "\n")
	lines = lines[:len(lines)-1]

	c := c17crypter{
		key:   AESRandomBytes(),
		iv:    AESRandomBytes(),
		lines: make([][]byte, len(lines)),
	}

	//fmt.Println("====== START cleartext")
	for i, line := range lines {
		r := strings.NewReader(line)
		dec := base64.NewDecoder(base64.StdEncoding, r)
		b, err := ioutil.ReadAll(dec)
		if err != nil {
			t.Error(err)
		}
		//fmt.Printf("[%s] %v\n", string(b), b)
		c.lines[i] = b
		//c.encrypt(b)
		//fmt.Println("~~~~~~~~")
	}
	//fmt.Println("===== END cleartext")

	for i := 0; i < 1; i++ {
		out, _, err := c.magic(i)
		if err != nil {
			t.Error(err)
			break
		}

		// test each padding bit
		found := false
		for j := 1; j <= 16; j++ {
			fmt.Printf("j = %d\n", j)

			// find the offset to flip
			offset := len(out) - j - 17

			// flip the bit
			out[offset] = FlipBit(out[offset])

			// is it valid?
			if c.IsValid(out) {
				fmt.Printf("i=%d FOUND padding byte %d\n", i, j)
				found = true
				break
			}

			// if not, undo the bit flip
			out[offset] = FlipBit(out[offset])
		}
		if !found {
			t.Errorf("failed to find padding bit for i=%d", i)
			break
		}
	}
}
