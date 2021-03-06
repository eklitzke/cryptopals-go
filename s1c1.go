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
