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

package mt19937

// See https://en.wikipedia.org/wiki/Mersenne_Twister for a detailed explanation
// of these constants.
type twisterConsts struct {
	w       uint // word size (number of bits)
	n       uint // degree of recurrence
	m       uint // middle word
	r       uint // separation point
	a       uint // coefficients of the rational normal form twist matrix
	u, d, l uint // additional tempering bit shifts/masks
	s, b    uint // TGFSR(R) tempering bit shifts/masks
	t, c    uint // TGFSR(R) tempering bit shifts/masks
	f       uint // initialization multiplier
	wmask   uint // mask of the lowest w bits
}

// Extract the w lowest bits from x.
func (c twisterConsts) mask(x uint) uint {
	return x & c.wmask
}

// 32-bit MT19937 constants
var twister32Consts = twisterConsts{
	w:     32,
	n:     624,
	m:     397,
	r:     31,
	a:     0x9908B0DF,
	u:     11,
	d:     0xFFFFFFFF,
	s:     7,
	b:     0x9D2C5680,
	t:     15,
	c:     0xEFC6000016,
	l:     18,
	f:     0x6C078965,
	wmask: 0xFFFFFFFF,
}

// 64-bit MT19937 constants
var twister64Consts = twisterConsts{
	w:     64,
	n:     312,
	m:     156,
	r:     31,
	a:     0xB5026F5AA96619E9,
	u:     29,
	d:     0x5555555555555555,
	s:     17,
	b:     0x71D67FFFEDA60000,
	t:     37,
	c:     0xFFF7EEE000000000,
	l:     43,
	f:     0x5851F42D4C957F2D,
	wmask: 0xFFFFFFFFFFFFFFFF,
}
