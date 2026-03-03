// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package sqlpipe

import "encoding/binary"

// Serialize encodes a Message to a length-prefixed byte buffer.
// Format: [4-byte LE length][1-byte tag][payload...]
func Serialize(msg Message) []byte {
	buf := make([]byte, 4, 64) // Reserve 4 bytes for length prefix.

	switch m := msg.(type) {
	case HelloMsg:
		buf = append(buf, byte(TagHello))
		buf = putU32(buf, m.ProtocolVersion)
		buf = putI32(buf, int32(m.SchemaVersion))
		if len(m.OwnedTables) > 0 {
			buf = putU32(buf, uint32(len(m.OwnedTables)))
			for _, t := range m.OwnedTables {
				buf = putString(buf, t)
			}
		}

	case ChangesetMsg:
		buf = append(buf, byte(TagChangeset))
		buf = putI64(buf, int64(m.Seq))
		buf = putChangeset(buf, m.Data)

	case AckMsg:
		buf = append(buf, byte(TagAck))
		buf = putI64(buf, int64(m.Seq))

	case ErrorMsg:
		buf = append(buf, byte(TagError))
		buf = putI32(buf, int32(m.Code))
		buf = putString(buf, m.Detail)
		buf = putI32(buf, int32(m.RemoteSchemaVersion))
		buf = putString(buf, m.RemoteSchemaSQL)

	case BucketHashesMsg:
		buf = append(buf, byte(TagBucketHashes))
		buf = putU32(buf, uint32(len(m.Buckets)))
		for _, b := range m.Buckets {
			buf = putString(buf, b.Table)
			buf = putI64(buf, b.BucketLo)
			buf = putI64(buf, b.BucketHi)
			buf = putU64(buf, b.Hash)
			buf = putI64(buf, b.RowCount)
		}

	case NeedBucketsMsg:
		buf = append(buf, byte(TagNeedBuckets))
		buf = putU32(buf, uint32(len(m.Ranges)))
		for _, r := range m.Ranges {
			buf = putString(buf, r.Table)
			buf = putI64(buf, r.Lo)
			buf = putI64(buf, r.Hi)
		}

	case RowHashesMsg:
		buf = append(buf, byte(TagRowHashes))
		buf = putU32(buf, uint32(len(m.Entries)))
		for _, e := range m.Entries {
			buf = putString(buf, e.Table)
			buf = putI64(buf, e.Lo)
			buf = putI64(buf, e.Hi)
			buf = putU32(buf, uint32(len(e.Runs)))
			for _, run := range e.Runs {
				buf = putI64(buf, run.StartRowid)
				buf = putI64(buf, run.Count)
				for _, h := range run.Hashes {
					buf = putU64(buf, h)
				}
			}
		}

	case DiffReadyMsg:
		buf = append(buf, byte(TagDiffReady))
		buf = putI64(buf, int64(m.Seq))
		buf = putChangeset(buf, m.Patchset)
		buf = putU32(buf, uint32(len(m.Deletes)))
		for _, td := range m.Deletes {
			buf = putString(buf, td.Table)
			buf = putU32(buf, uint32(len(td.Rowids)))
			for _, rid := range td.Rowids {
				buf = putI64(buf, rid)
			}
		}
	}

	// Patch the length prefix: total = tag + payload (excludes the 4 prefix bytes).
	binary.LittleEndian.PutUint32(buf[:4], uint32(len(buf)-4))
	return buf
}

// SerializePeer encodes a PeerMessage to a length-prefixed byte buffer.
// Format: [4B LE length][1B sender_role][1B tag][payload...]
func SerializePeer(msg PeerMessage) []byte {
	inner := Serialize(msg.Payload) // [4B len][tag][payload]
	innerLen := binary.LittleEndian.Uint32(inner[:4])

	total := innerLen + 1 // +1 for sender_role byte.
	buf := make([]byte, 0, 4+1+innerLen)

	var lenBuf [4]byte
	binary.LittleEndian.PutUint32(lenBuf[:], total)
	buf = append(buf, lenBuf[:]...)
	buf = append(buf, byte(msg.SenderRole))
	buf = append(buf, inner[4:]...) // tag + payload (skip inner's length prefix).
	return buf
}

// Little-endian encoding helpers.

func putU32(buf []byte, v uint32) []byte {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	return append(buf, b[:]...)
}

func putI32(buf []byte, v int32) []byte {
	return putU32(buf, uint32(v))
}

func putI64(buf []byte, v int64) []byte {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], uint64(v))
	return append(buf, b[:]...)
}

func putU64(buf []byte, v uint64) []byte {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], v)
	return append(buf, b[:]...)
}

func putString(buf []byte, s string) []byte {
	buf = putU32(buf, uint32(len(s)))
	return append(buf, s...)
}
