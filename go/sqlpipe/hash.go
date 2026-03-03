// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package sqlpipe

import (
	"encoding/binary"
	"math"
)

const (
	fnv64Offset uint64 = 14695981039346656037
	fnv64Prime  uint64 = 1099511628211
)

func fnv64Byte(h uint64, b byte) uint64 {
	h ^= uint64(b)
	h *= fnv64Prime
	return h
}

func fnv64Bytes(h uint64, data []byte) uint64 {
	for _, b := range data {
		h = fnv64Byte(h, b)
	}
	return h
}

// hashValue feeds a Value into a running FNV-1a hash (type-tagged).
func hashValue(h uint64, v Value) uint64 {
	switch val := v.(type) {
	case nil:
		h = fnv64Byte(h, 0x00)
	case int64:
		h = fnv64Byte(h, 0x01)
		var buf [8]byte
		binary.LittleEndian.PutUint64(buf[:], uint64(val))
		h = fnv64Bytes(h, buf[:])
	case float64:
		h = fnv64Byte(h, 0x02)
		var buf [8]byte
		binary.LittleEndian.PutUint64(buf[:], math.Float64bits(val))
		h = fnv64Bytes(h, buf[:])
	case string:
		h = fnv64Byte(h, 0x03)
		var buf [4]byte
		binary.LittleEndian.PutUint32(buf[:], uint32(len(val)))
		h = fnv64Bytes(h, buf[:])
		h = fnv64Bytes(h, []byte(val))
	case []byte:
		h = fnv64Byte(h, 0x04)
		var buf [4]byte
		binary.LittleEndian.PutUint32(buf[:], uint32(len(val)))
		h = fnv64Bytes(h, buf[:])
		h = fnv64Bytes(h, val)
	default:
		h = fnv64Byte(h, 0x00) // Treat unknown as NULL.
	}
	return h
}

// hashBucketEntry hashes a (rowid, row_hash) pair for bucket accumulation.
func hashBucketEntry(rowid int64, rowHash uint64) uint64 {
	h := fnv64Offset
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], uint64(rowid))
	h = fnv64Bytes(h, buf[:])
	binary.LittleEndian.PutUint64(buf[:], rowHash)
	h = fnv64Bytes(h, buf[:])
	return h
}

// schemaFingerprint computes FNV-1a 32-bit hash of schema SQL.
func schemaFingerprint(sql string) SchemaVersion {
	h := uint32(2166136261) // FNV-1a 32-bit offset.
	for i := 0; i < len(sql); i++ {
		h ^= uint32(sql[i])
		h *= 16777619 // FNV-1a 32-bit prime.
	}
	return SchemaVersion(int32(h))
}
