// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package sqlpipe

import (
	"encoding/binary"
	"sort"
)

// reader is a bounds-checked binary reader for deserialization.
type reader struct {
	data []byte
	pos  int
}

func (r *reader) check(n int) error {
	if r.pos+n > len(r.data) {
		return errorf(ErrProtocol, "unexpected end of message")
	}
	return nil
}

func (r *reader) atEnd() bool { return r.pos >= len(r.data) }

func (r *reader) readU8() (byte, error) {
	if err := r.check(1); err != nil {
		return 0, err
	}
	v := r.data[r.pos]
	r.pos++
	return v, nil
}

func (r *reader) readU32() (uint32, error) {
	if err := r.check(4); err != nil {
		return 0, err
	}
	v := binary.LittleEndian.Uint32(r.data[r.pos:])
	r.pos += 4
	return v, nil
}

func (r *reader) readI32() (int32, error) {
	v, err := r.readU32()
	return int32(v), err
}

func (r *reader) readI64() (int64, error) {
	if err := r.check(8); err != nil {
		return 0, err
	}
	v := binary.LittleEndian.Uint64(r.data[r.pos:])
	r.pos += 8
	return int64(v), nil
}

func (r *reader) readU64() (uint64, error) {
	if err := r.check(8); err != nil {
		return 0, err
	}
	v := binary.LittleEndian.Uint64(r.data[r.pos:])
	r.pos += 8
	return v, nil
}

func (r *reader) readString() (string, error) {
	length, err := r.readU32()
	if err != nil {
		return "", err
	}
	if length > MaxMessageSize {
		return "", errorf(ErrProtocol, "string length exceeds limit")
	}
	if err := r.check(int(length)); err != nil {
		return "", err
	}
	s := string(r.data[r.pos : r.pos+int(length)])
	r.pos += int(length)
	return s, nil
}

func checkCount(n uint32) error {
	if n > MaxArrayCount {
		return errorf(ErrProtocol, "array count exceeds limit (%d)", n)
	}
	return nil
}

// Deserialize decodes a length-prefixed byte buffer into a Message.
func Deserialize(buf []byte) (Message, error) {
	if len(buf) < 5 {
		return nil, errorf(ErrProtocol, "message too short")
	}
	if len(buf) > int(MaxMessageSize)+4 {
		return nil, errorf(ErrProtocol, "message exceeds maximum size (%d bytes)", len(buf))
	}

	r := &reader{data: buf}

	// Skip 4-byte length prefix (we already have the full buffer).
	if _, err := r.readU32(); err != nil {
		return nil, err
	}

	tagByte, err := r.readU8()
	if err != nil {
		return nil, err
	}
	tag := MessageTag(tagByte)

	switch tag {
	case TagHello:
		return deserializeHello(r)
	case TagChangeset:
		return deserializeChangeset(r)
	case TagAck:
		return deserializeAck(r)
	case TagError:
		return deserializeError(r)
	case TagBucketHashes:
		return deserializeBucketHashes(r)
	case TagNeedBuckets:
		return deserializeNeedBuckets(r)
	case TagRowHashes:
		return deserializeRowHashes(r)
	case TagDiffReady:
		return deserializeDiffReady(r)
	default:
		return nil, errorf(ErrProtocol, "unknown message tag: %d", tag)
	}
}

// DeserializePeer decodes a length-prefixed byte buffer into a PeerMessage.
func DeserializePeer(buf []byte) (PeerMessage, error) {
	if len(buf) < 6 {
		return PeerMessage{}, errorf(ErrProtocol, "peer message too short")
	}

	total := binary.LittleEndian.Uint32(buf[:4])
	role := SenderRole(buf[4])
	if role != RoleAsMaster && role != RoleAsReplica {
		return PeerMessage{}, errorf(ErrProtocol, "invalid sender role: %d", buf[4])
	}

	// Reconstruct inner Message buffer: [4B len][tag+payload].
	msgLen := total - 1
	msgBuf := make([]byte, 4+msgLen)
	binary.LittleEndian.PutUint32(msgBuf[:4], msgLen)
	copy(msgBuf[4:], buf[5:])

	payload, err := Deserialize(msgBuf)
	if err != nil {
		return PeerMessage{}, err
	}
	return PeerMessage{SenderRole: role, Payload: payload}, nil
}

func deserializeHello(r *reader) (HelloMsg, error) {
	pv, err := r.readU32()
	if err != nil {
		return HelloMsg{}, err
	}
	sv, err := r.readI32()
	if err != nil {
		return HelloMsg{}, err
	}
	m := HelloMsg{ProtocolVersion: pv, SchemaVersion: SchemaVersion(sv)}
	if !r.atEnd() {
		count, err := r.readU32()
		if err != nil {
			return HelloMsg{}, err
		}
		if err := checkCount(count); err != nil {
			return HelloMsg{}, err
		}
		m.OwnedTables = make([]string, count)
		for i := uint32(0); i < count; i++ {
			s, err := r.readString()
			if err != nil {
				return HelloMsg{}, err
			}
			m.OwnedTables[i] = s
		}
		sort.Strings(m.OwnedTables)
	}
	return m, nil
}

func deserializeChangeset(r *reader) (ChangesetMsg, error) {
	seq, err := r.readI64()
	if err != nil {
		return ChangesetMsg{}, err
	}
	data, err := r.readChangeset()
	if err != nil {
		return ChangesetMsg{}, err
	}
	return ChangesetMsg{Seq: Seq(seq), Data: data}, nil
}

func deserializeAck(r *reader) (AckMsg, error) {
	seq, err := r.readI64()
	if err != nil {
		return AckMsg{}, err
	}
	return AckMsg{Seq: Seq(seq)}, nil
}

func deserializeError(r *reader) (ErrorMsg, error) {
	code, err := r.readI32()
	if err != nil {
		return ErrorMsg{}, err
	}
	detail, err := r.readString()
	if err != nil {
		return ErrorMsg{}, err
	}
	rsv, err := r.readI32()
	if err != nil {
		return ErrorMsg{}, err
	}
	rsql, err := r.readString()
	if err != nil {
		return ErrorMsg{}, err
	}
	return ErrorMsg{
		Code:                ErrorCode(code),
		Detail:              detail,
		RemoteSchemaVersion: SchemaVersion(rsv),
		RemoteSchemaSQL:     rsql,
	}, nil
}

func deserializeBucketHashes(r *reader) (BucketHashesMsg, error) {
	count, err := r.readU32()
	if err != nil {
		return BucketHashesMsg{}, err
	}
	if err := checkCount(count); err != nil {
		return BucketHashesMsg{}, err
	}
	buckets := make([]BucketHashEntry, count)
	for i := uint32(0); i < count; i++ {
		table, err := r.readString()
		if err != nil {
			return BucketHashesMsg{}, err
		}
		lo, err := r.readI64()
		if err != nil {
			return BucketHashesMsg{}, err
		}
		hi, err := r.readI64()
		if err != nil {
			return BucketHashesMsg{}, err
		}
		hash, err := r.readU64()
		if err != nil {
			return BucketHashesMsg{}, err
		}
		rc, err := r.readI64()
		if err != nil {
			return BucketHashesMsg{}, err
		}
		buckets[i] = BucketHashEntry{
			Table: table, BucketLo: lo, BucketHi: hi, Hash: hash, RowCount: rc,
		}
	}
	return BucketHashesMsg{Buckets: buckets}, nil
}

func deserializeNeedBuckets(r *reader) (NeedBucketsMsg, error) {
	count, err := r.readU32()
	if err != nil {
		return NeedBucketsMsg{}, err
	}
	if err := checkCount(count); err != nil {
		return NeedBucketsMsg{}, err
	}
	ranges := make([]NeedBucketRange, count)
	for i := uint32(0); i < count; i++ {
		table, err := r.readString()
		if err != nil {
			return NeedBucketsMsg{}, err
		}
		lo, err := r.readI64()
		if err != nil {
			return NeedBucketsMsg{}, err
		}
		hi, err := r.readI64()
		if err != nil {
			return NeedBucketsMsg{}, err
		}
		ranges[i] = NeedBucketRange{Table: table, Lo: lo, Hi: hi}
	}
	return NeedBucketsMsg{Ranges: ranges}, nil
}

func deserializeRowHashes(r *reader) (RowHashesMsg, error) {
	entryCount, err := r.readU32()
	if err != nil {
		return RowHashesMsg{}, err
	}
	if err := checkCount(entryCount); err != nil {
		return RowHashesMsg{}, err
	}
	entries := make([]RowHashesEntry, entryCount)
	for i := uint32(0); i < entryCount; i++ {
		table, err := r.readString()
		if err != nil {
			return RowHashesMsg{}, err
		}
		lo, err := r.readI64()
		if err != nil {
			return RowHashesMsg{}, err
		}
		hi, err := r.readI64()
		if err != nil {
			return RowHashesMsg{}, err
		}
		runCount, err := r.readU32()
		if err != nil {
			return RowHashesMsg{}, err
		}
		if err := checkCount(runCount); err != nil {
			return RowHashesMsg{}, err
		}
		runs := make([]RowHashRun, runCount)
		for j := uint32(0); j < runCount; j++ {
			startRowid, err := r.readI64()
			if err != nil {
				return RowHashesMsg{}, err
			}
			count, err := r.readI64()
			if err != nil {
				return RowHashesMsg{}, err
			}
			hashes := make([]uint64, count)
			for k := int64(0); k < count; k++ {
				h, err := r.readU64()
				if err != nil {
					return RowHashesMsg{}, err
				}
				hashes[k] = h
			}
			runs[j] = RowHashRun{StartRowid: startRowid, Count: count, Hashes: hashes}
		}
		entries[i] = RowHashesEntry{Table: table, Lo: lo, Hi: hi, Runs: runs}
	}
	return RowHashesMsg{Entries: entries}, nil
}

func deserializeDiffReady(r *reader) (DiffReadyMsg, error) {
	seq, err := r.readI64()
	if err != nil {
		return DiffReadyMsg{}, err
	}
	patchset, err := r.readChangeset()
	if err != nil {
		return DiffReadyMsg{}, err
	}
	delCount, err := r.readU32()
	if err != nil {
		return DiffReadyMsg{}, err
	}
	if err := checkCount(delCount); err != nil {
		return DiffReadyMsg{}, err
	}
	deletes := make([]TableDeletes, delCount)
	for i := uint32(0); i < delCount; i++ {
		table, err := r.readString()
		if err != nil {
			return DiffReadyMsg{}, err
		}
		ridCount, err := r.readU32()
		if err != nil {
			return DiffReadyMsg{}, err
		}
		if err := checkCount(ridCount); err != nil {
			return DiffReadyMsg{}, err
		}
		rowids := make([]int64, ridCount)
		for j := uint32(0); j < ridCount; j++ {
			rid, err := r.readI64()
			if err != nil {
				return DiffReadyMsg{}, err
			}
			rowids[j] = rid
		}
		deletes[i] = TableDeletes{Table: table, Rowids: rowids}
	}
	return DiffReadyMsg{Seq: Seq(seq), Patchset: patchset, Deletes: deletes}, nil
}

