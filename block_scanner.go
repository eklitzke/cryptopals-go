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

import "fmt"

// BlockScanner is a scanner that reads fixed size blocks from an input buffer.
type BlockScanner struct {
	data      []byte // the original buffer
	block     []byte // the last block scanned
	blockSize int    // the block size
	offset    int    // the current offset
}

// Scan implements the Scanner interface.
func (s *BlockScanner) Scan() bool {
	if s.offset >= len(s.data) {
		return false
	}
	s.block = s.data[s.offset : s.offset+s.blockSize]
	s.offset += s.blockSize
	return true
}

// Bytes returns the last block scanned.
func (s *BlockScanner) Bytes() []byte {
	return s.block
}

// NewBlockScanner creates a new BlockScanner.
func NewBlockScanner(data []byte, blockSize int) (*BlockScanner, error) {
	if len(data)%blockSize != 0 {
		return nil, fmt.Errorf("failed to create NewBlockScanner, input size %d not aligned to blockSize %d", len(data), blockSize)
	}
	return &BlockScanner{
		data:      data,
		blockSize: blockSize,
	}, nil
}
