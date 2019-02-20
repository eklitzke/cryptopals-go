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
	"testing"

	"github.com/eklitzke/cryptopals/mt19937"
)

func TestC321(t *testing.T) {
	opts := mt19937.Opts32
	m, err := mt19937.NewMT19937(opts)
	if err != nil {
		t.Error(err)
	}
	if w := m.WordSize(); w != 32 {
		t.Errorf("got %d WordSize, but expected 32", w)
	}

	const expect32_1 = 3510057789
	if n := m.Next(); n != expect32_1 {
		t.Errorf("32-bit first generated was %d, expected %d", n, expect32_1)

	}

	const expect32_2 = 731487415
	if n := m.Next(); n != expect32_2 {
		t.Errorf("32-bit second generated was %d, expected %d", n, expect32_2)

	}

	opts = mt19937.Opts64
	m, err = mt19937.NewMT19937(opts)
	if err != nil {
		t.Error(err)
	}
	if w := m.WordSize(); w != 64 {
		t.Errorf("got %d WordSize, but expected 64", w)
	}

	const expect64_1 = 14514284786278117030
	if n := m.Next(); n != expect64_1 {
		t.Errorf("64-bit first generated was %d, expected %d", n, uint64(expect64_1))

	}

	const expect64_2 = 4620546740167642908
	if n := m.Next(); n != expect64_2 {
		t.Errorf("64-bit second generated was %d, expected %d", n, expect64_2)

	}
}
