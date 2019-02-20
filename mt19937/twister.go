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

type MT19937 struct {
	c          twisterConsts // twister constants
	wbits      uint          // mask for w lowest bits
	state      []uint        // state of the generator
	index      uint          // index into the generator
	lower_mask uint          // mask
	upper_mask uint          // mask
}

var invalidOpts = errors.New("invalid MT19937 options (no word size set)")

var invalidSeed = errors.New("invalid MT19937 seed")

func NewMT19937(opts Opts) (*MT19937, error) {
	if opts.c.w == 0 {
		return nil, invalidOpts
	}
	if opts.Seed == 0 {
		return nil, invalidSeed
	}
	m := &MT19937{
		c:          opts.c,
		state:      make([]uint, opts.c.n),
		index:      opts.c.n + 1,
		lower_mask: uint((1 << opts.c.r) - 1),
		wbits:      1,
	}

	// generate the wbits mask
	var i, lowmask uint
	lowmask = 1
	for i = 1; i < opts.c.w; i++ {
		lowmask <<= 1
		m.wbits |= lowmask
	}

	// set the upper mask
	m.upper_mask = m.getLowBits(^m.lower_mask)

	// seed the twister
	m.Seed(opts.Seed)

	return m, nil
}

// get the w lowest bits from x
func (m *MT19937) getLowBits(x uint) uint {
	return x & m.wbits
}

// initialize the generator from a seed
func (m *MT19937) Seed(seed uint) {
	c := m.c
	m.index = c.n
	m.state[0] = seed
	var i uint
	for i = 1; i < c.n; i++ {
		m.state[i] = m.getLowBits(c.f*(m.state[i-1]^(m.state[i-1]>>(c.w-2))) + i)
	}
}

// Extract a tempered value based on m.state[index], calling twist() every n
// numbers.
func (m *MT19937) extractNumber() uint {
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
	return m.getLowBits(y)
}

func (m *MT19937) twist() {
	c := m.c
	var i uint
	for i = 0; i < c.n; i++ {
		x := uint((m.state[i] & m.upper_mask) + (m.state[(i+1)%c.n] & m.lower_mask))
		xA := x >> 1
		if (x & 1) == 1 {
			xA ^= c.a
		}
		m.state[i] = m.state[(i+c.m)%c.n] ^ xA
	}
	m.index = 0
}

// Next gets the next number from the twister.
func (m *MT19937) Next() uint {
	return m.extractNumber()
}
