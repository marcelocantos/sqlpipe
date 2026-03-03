// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package sqlpipe

import "github.com/pierrec/lz4/v4"

const compressionThreshold = 64

// putChangeset appends a compressed or uncompressed changeset to buf.
// Format: [u32 total][u8 type][data...] where type 0x00 = raw, 0x01 = LZ4.
func putChangeset(buf []byte, cs Changeset) []byte {
	if len(cs) < compressionThreshold {
		buf = putU32(buf, uint32(len(cs)+1))
		buf = append(buf, 0x00)
		return append(buf, cs...)
	}

	dst := make([]byte, lz4.CompressBlockBound(len(cs)))
	n, err := lz4.CompressBlock(cs, dst, nil)
	if err == nil && n > 0 && n < len(cs) {
		// LZ4: [u32 total][0x01][u32 original_len][compressed_data]
		total := uint32(1 + 4 + n)
		buf = putU32(buf, total)
		buf = append(buf, 0x01)
		buf = putU32(buf, uint32(len(cs)))
		return append(buf, dst[:n]...)
	}

	// Fallback: uncompressed.
	buf = putU32(buf, uint32(len(cs)+1))
	buf = append(buf, 0x00)
	return append(buf, cs...)
}

// readChangeset reads a compressed or uncompressed changeset from r.
func (r *reader) readChangeset() (Changeset, error) {
	length, err := r.readU32()
	if err != nil {
		return nil, err
	}
	if length == 0 {
		return nil, nil
	}
	typ, err := r.readU8()
	if err != nil {
		return nil, err
	}
	payloadLen := length - 1

	switch typ {
	case 0x00: // Uncompressed.
		data, err := r.readBytes(payloadLen)
		if err != nil {
			return nil, err
		}
		return Changeset(data), nil

	case 0x01: // LZ4.
		origLen, err := r.readU32()
		if err != nil {
			return nil, err
		}
		compressedLen := payloadLen - 4
		compressed, err := r.readBytes(compressedLen)
		if err != nil {
			return nil, err
		}
		cs := make([]byte, origLen)
		n, err := lz4.UncompressBlock(compressed, cs)
		if err != nil {
			return nil, errorf(ErrProtocol, "LZ4 decompression failed: %v", err)
		}
		_ = n
		return Changeset(cs), nil

	default:
		return nil, errorf(ErrProtocol, "unknown changeset compression type: 0x%02x", typ)
	}
}

// reader helpers that compress.go needs from deserialize.go.
// readBytes reads exactly n bytes from the reader.
func (r *reader) readBytes(n uint32) ([]byte, error) {
	if err := r.check(int(n)); err != nil {
		return nil, err
	}
	data := make([]byte, n)
	copy(data, r.data[r.pos:r.pos+int(n)])
	r.pos += int(n)
	return data, nil
}

// readU8 is defined in deserialize.go but referenced here for the import.
// We use a forward reference pattern: the reader type is defined in deserialize.go
// and both files contribute methods to it.

