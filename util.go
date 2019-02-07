// Copyright (C) 2019  Evan Klitzke <evan@eklitzke.org>

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

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
