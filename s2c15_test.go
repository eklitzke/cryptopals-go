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

import "testing"

func TestS2C15(t *testing.T) {
	dec, err := UnpadPKCS7([]byte("ICE ICE BABY\x04\x04\x04\x04"))
	if err != nil {
		t.Error(err)
	}
	if string(dec) != "ICE ICE BABY" {
		t.Errorf("bad unpad: %s", dec)
	}

	_, err = UnpadPKCS7([]byte("ICE ICE BABY\x05\x05\x05\x05"))
	if err == nil {
		t.Error("expected an error")
	}

	_, err = UnpadPKCS7([]byte("ICE ICE BABY\x01\x02\x03\x04"))
	if err == nil {
		t.Error("expected an error")
	}
}
