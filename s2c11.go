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

// EncryptionMode represents an AES encryption mode (ECB, CBC, etc.)
type EncryptionMode int

// List of EncryptionMode values.
const (
	ECB EncryptionMode = iota + 1
	CBC
)

// buffers smaller than this cannot be detected accurately
const MinOracleDetectionSize = 1000

// error used when an oracle buffer is too small
var OracleBufferTooSmallErr = errors.New("oracle buffer is too small")

// Oracle that detects which encryption mode a buffer is likely to be encrypted
// using. This uses a pretty simple heuristic: it tries to detect when there are
// many repeated blocks in the ciphertext.
func EncryptionModeOracle(data []byte) (mode EncryptionMode, err error) {
	if len(data) < MinOracleDetectionSize {
		err = OracleBufferTooSmallErr
		return
	}
	var repeats int
	repeats, err = CountAESRepeats(data)
	if err != nil {
		return
	}
	mode = ECB
	if repeats <= int(len(data)/1000) {
		mode = CBC
	}
	return
}
