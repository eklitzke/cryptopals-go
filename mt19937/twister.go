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

import "errors"

// MT19937 implements the MT19937 "Mersenne Twister" PRNG, see
// https://en.wikipedia.org/wiki/Mersenne_Twister for details.
//
// This struct can be used for either a 32-bit twister, or a 64-bit twister. Use
// NewMT19937 to initialize a new instance of the PRNG.
type MT19937 struct {
	c         twisterConsts // twister constants
	state     []uint        // state of the generator
	index     uint          // index into the generator
	lowerMask uint          // mask
	upperMask uint          // mask
}

// ErrInvalidOpts is returned when invalid options are specified.
var ErrInvalidOpts = errors.New("invalid MT19937 options (no word size set)")

// NewMT19937 creates a new MT19937 twister given Opts.
//
// Opts should be created from Opts32 or Opts64. The default values of those
// variables are valid options using the same default seed as the reference C
// implementation. To use a different seed, create a new copy of Opts using the
// Seed() method on Opts32 or Opts64.
func NewMT19937(opts Opts) (*MT19937, error) {
	c := opts.c
	if c.w == 0 {
		return nil, ErrInvalidOpts
	}
	lower := uint((1 << c.r) - 1)
	m := &MT19937{
		c:         c,
		state:     make([]uint, c.n),
		index:     c.n + 1,
		lowerMask: lower,
		upperMask: c.mask(^lower),
	}
	m.Seed(opts.seed)
	return m, nil
}

// Seed initializes the generator based on a seed.
//
// This is called automatically by NewMT19937(), but you can also explicitly
// re-seed the generator using this method.
func (m *MT19937) Seed(seed uint) {
	c := m.c
	m.index = c.n
	m.state[0] = seed
	var i uint
	for i = 1; i < c.n; i++ {
		m.state[i] = c.mask(c.f*(m.state[i-1]^(m.state[i-1]>>(c.w-2))) + i)
	}
}

// Next gets the next random number from the PRNG. The output number will be a
// uint with at most WordSize() bits set (either 32 or 64 bits).
//
// Internally this extracts a tempered value based on m.state[index], calling
// twist() every n numbers.
func (m *MT19937) Next() uint {
	c := m.c
	if m.index >= c.n {
		if m.index > c.n {
			panic("MT19937 was never seeded") // not possible???
		}
		m.twist()
	}
	y := m.state[m.index]
	y ^= ((y >> c.u) & c.d)
	y ^= ((y << c.s) & c.b)
	y ^= ((y << c.t) & c.c)
	y ^= (y >> c.l)
	m.index++
	return c.mask(y)
}

// Twist the internal state of the generator.
func (m *MT19937) twist() {
	c := m.c
	var i, x, xA uint
	for i = 0; i < c.n; i++ {
		x = (m.state[i] & m.upperMask) + (m.state[(i+1)%c.n] & m.lowerMask)
		xA = x >> 1
		if (x & 1) == 1 {
			xA ^= c.a
		}
		m.state[i] = m.state[(i+c.m)%c.n] ^ xA
	}
	m.index = 0
}

// WordSize gets the word size of the PRNG (will return 32 or 64).
func (m *MT19937) WordSize() uint {
	return m.c.w
}
