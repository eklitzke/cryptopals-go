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

const (
	// default seed, same as in the reference C code
	defaultSeed = 5489
)

// Opts gets the twister options
type Opts struct {
	c    twisterConsts // constants
	Seed uint          // default seed
}

// options for a 32-bit Mersenne twister
var Opts32 = Opts{c: twister32Consts, Seed: defaultSeed}

// options for a 64-bit Mersenne twister
var Opts64 = Opts{c: twister64Consts, Seed: defaultSeed}
