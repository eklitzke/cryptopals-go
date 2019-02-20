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

const defaultSeed = 5489 // same as in the reference C code

// Opts holds the constants and seed for a MT19937 PRNG instance.
//
// All members are private, but an Opts with a new seed can be created using the
// Seed() method.
type Opts struct {
	c    twisterConsts // constants
	seed uint          // default seed
}

// Seed creates a new option struct with the given seed.
func (o Opts) Seed(seed uint) Opts {
	return Opts{c: o.c, seed: seed}
}

// WordSize gets the word size for the options.
func (o Opts) WordSize() uint {
	return o.c.w
}

// Options for a 32-bit Mersenne twister.
var Opts32 = Opts{c: twister32Consts, seed: defaultSeed}

// Options for a 64-bit Mersenne twister.
var Opts64 = Opts{c: twister64Consts, seed: defaultSeed}
