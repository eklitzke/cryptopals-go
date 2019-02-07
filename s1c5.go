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
