// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package sqlpipe

import (
	"testing"
)

func TestHelloMsgRoundTrip(t *testing.T) {
	orig := HelloMsg{ProtocolVersion: ProtocolVersion, SchemaVersion: 3}
	buf := Serialize(orig)
	msg, err := Deserialize(buf)
	if err != nil {
		t.Fatal(err)
	}
	m, ok := msg.(HelloMsg)
	if !ok {
		t.Fatalf("expected HelloMsg, got %T", msg)
	}
	if m.ProtocolVersion != ProtocolVersion {
		t.Errorf("protocol_version: got %d, want %d", m.ProtocolVersion, ProtocolVersion)
	}
	if m.SchemaVersion != 3 {
		t.Errorf("schema_version: got %d, want 3", m.SchemaVersion)
	}
	if len(m.OwnedTables) != 0 {
		t.Errorf("owned_tables: got %v, want empty", m.OwnedTables)
	}
}

func TestChangesetMsgRoundTrip(t *testing.T) {
	data := Changeset{0x01, 0x02, 0x03, 0xFF}
	orig := ChangesetMsg{Seq: 7, Data: data}
	buf := Serialize(orig)
	msg, err := Deserialize(buf)
	if err != nil {
		t.Fatal(err)
	}
	m := msg.(ChangesetMsg)
	if m.Seq != 7 {
		t.Errorf("seq: got %d, want 7", m.Seq)
	}
	if !bytesEqual(m.Data, data) {
		t.Errorf("data mismatch")
	}
}

func TestChangesetMsgRoundTripLZ4(t *testing.T) {
	data := make(Changeset, 256)
	for i := range data {
		data[i] = byte(i % 7)
	}
	orig := ChangesetMsg{Seq: 99, Data: data}
	buf := Serialize(orig)
	msg, err := Deserialize(buf)
	if err != nil {
		t.Fatal(err)
	}
	m := msg.(ChangesetMsg)
	if m.Seq != 99 {
		t.Errorf("seq: got %d, want 99", m.Seq)
	}
	if !bytesEqual(m.Data, data) {
		t.Errorf("data mismatch")
	}
	// Serialized form should be smaller than uncompressed.
	if len(buf) >= 274 {
		t.Errorf("expected LZ4 compression, buf size = %d", len(buf))
	}
}

func TestAckMsgRoundTrip(t *testing.T) {
	orig := AckMsg{Seq: 55}
	buf := Serialize(orig)
	msg, err := Deserialize(buf)
	if err != nil {
		t.Fatal(err)
	}
	m := msg.(AckMsg)
	if m.Seq != 55 {
		t.Errorf("seq: got %d, want 55", m.Seq)
	}
}

func TestErrorMsgRoundTrip(t *testing.T) {
	orig := ErrorMsg{
		Code:                ErrSchemaMismatch,
		Detail:              "schema differs",
		RemoteSchemaVersion: 42,
		RemoteSchemaSQL:     "CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT);",
	}
	buf := Serialize(orig)
	msg, err := Deserialize(buf)
	if err != nil {
		t.Fatal(err)
	}
	m := msg.(ErrorMsg)
	if m.Code != ErrSchemaMismatch {
		t.Errorf("code: got %d, want %d", m.Code, ErrSchemaMismatch)
	}
	if m.Detail != "schema differs" {
		t.Errorf("detail: got %q", m.Detail)
	}
	if m.RemoteSchemaVersion != 42 {
		t.Errorf("remote_schema_version: got %d, want 42", m.RemoteSchemaVersion)
	}
	if m.RemoteSchemaSQL != "CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT);" {
		t.Errorf("remote_schema_sql: got %q", m.RemoteSchemaSQL)
	}
}

func TestErrorMsgRoundTripDefaults(t *testing.T) {
	orig := ErrorMsg{Code: ErrProtocol, Detail: "bad version"}
	buf := Serialize(orig)
	msg, err := Deserialize(buf)
	if err != nil {
		t.Fatal(err)
	}
	m := msg.(ErrorMsg)
	if m.Code != ErrProtocol {
		t.Errorf("code: got %d", m.Code)
	}
	if m.RemoteSchemaVersion != 0 {
		t.Errorf("remote_schema_version: got %d, want 0", m.RemoteSchemaVersion)
	}
	if m.RemoteSchemaSQL != "" {
		t.Errorf("remote_schema_sql: got %q, want empty", m.RemoteSchemaSQL)
	}
}

func TestBucketHashesMsgRoundTrip(t *testing.T) {
	orig := BucketHashesMsg{Buckets: []BucketHashEntry{
		{Table: "t1", BucketLo: 0, BucketHi: 1023, Hash: 0xABCDEF0123456789, RowCount: 100},
		{Table: "t1", BucketLo: 1024, BucketHi: 2047, Hash: 0x1122334455667788, RowCount: 50},
	}}
	buf := Serialize(orig)
	msg, err := Deserialize(buf)
	if err != nil {
		t.Fatal(err)
	}
	m := msg.(BucketHashesMsg)
	if len(m.Buckets) != 2 {
		t.Fatalf("buckets: got %d, want 2", len(m.Buckets))
	}
	b := m.Buckets[0]
	if b.Table != "t1" || b.BucketLo != 0 || b.BucketHi != 1023 || b.Hash != 0xABCDEF0123456789 || b.RowCount != 100 {
		t.Errorf("bucket[0] mismatch: %+v", b)
	}
	if m.Buckets[1].BucketLo != 1024 {
		t.Errorf("bucket[1].lo: got %d", m.Buckets[1].BucketLo)
	}
}

func TestNeedBucketsMsgRoundTrip(t *testing.T) {
	orig := NeedBucketsMsg{Ranges: []NeedBucketRange{
		{Table: "users", Lo: 0, Hi: 1023},
		{Table: "orders", Lo: 1024, Hi: 2047},
	}}
	buf := Serialize(orig)
	msg, err := Deserialize(buf)
	if err != nil {
		t.Fatal(err)
	}
	m := msg.(NeedBucketsMsg)
	if len(m.Ranges) != 2 {
		t.Fatalf("ranges: got %d, want 2", len(m.Ranges))
	}
	if m.Ranges[0].Table != "users" || m.Ranges[0].Lo != 0 || m.Ranges[0].Hi != 1023 {
		t.Errorf("range[0] mismatch: %+v", m.Ranges[0])
	}
	if m.Ranges[1].Table != "orders" {
		t.Errorf("range[1].table: got %q", m.Ranges[1].Table)
	}
}

func TestRowHashesMsgRoundTrip(t *testing.T) {
	orig := RowHashesMsg{Entries: []RowHashesEntry{{
		Table: "t1", Lo: 0, Hi: 1023,
		Runs: []RowHashRun{
			{StartRowid: 1, Count: 3, Hashes: []uint64{0xAA, 0xBB, 0xCC}},
			{StartRowid: 10, Count: 2, Hashes: []uint64{0xDD, 0xEE}},
		},
	}}}
	buf := Serialize(orig)
	msg, err := Deserialize(buf)
	if err != nil {
		t.Fatal(err)
	}
	m := msg.(RowHashesMsg)
	if len(m.Entries) != 1 {
		t.Fatalf("entries: got %d, want 1", len(m.Entries))
	}
	e := m.Entries[0]
	if e.Table != "t1" || e.Lo != 0 || e.Hi != 1023 {
		t.Errorf("entry mismatch: %+v", e)
	}
	if len(e.Runs) != 2 {
		t.Fatalf("runs: got %d, want 2", len(e.Runs))
	}
	if e.Runs[0].StartRowid != 1 || e.Runs[0].Count != 3 || len(e.Runs[0].Hashes) != 3 {
		t.Errorf("run[0] mismatch: %+v", e.Runs[0])
	}
	if e.Runs[0].Hashes[0] != 0xAA {
		t.Errorf("run[0].hashes[0]: got %x, want 0xAA", e.Runs[0].Hashes[0])
	}
	if e.Runs[1].StartRowid != 10 || e.Runs[1].Count != 2 {
		t.Errorf("run[1] mismatch: %+v", e.Runs[1])
	}
}

func TestDiffReadyMsgRoundTrip(t *testing.T) {
	orig := DiffReadyMsg{
		Seq:      42,
		Patchset: Changeset{0x01, 0x02, 0x03},
		Deletes: []TableDeletes{
			{Table: "t1", Rowids: []int64{1, 2, 3}},
			{Table: "t2", Rowids: []int64{10, 20}},
		},
	}
	buf := Serialize(orig)
	msg, err := Deserialize(buf)
	if err != nil {
		t.Fatal(err)
	}
	m := msg.(DiffReadyMsg)
	if m.Seq != 42 {
		t.Errorf("seq: got %d, want 42", m.Seq)
	}
	if !bytesEqual(m.Patchset, Changeset{0x01, 0x02, 0x03}) {
		t.Errorf("patchset mismatch")
	}
	if len(m.Deletes) != 2 {
		t.Fatalf("deletes: got %d, want 2", len(m.Deletes))
	}
	if m.Deletes[0].Table != "t1" || !int64sEqual(m.Deletes[0].Rowids, []int64{1, 2, 3}) {
		t.Errorf("deletes[0] mismatch: %+v", m.Deletes[0])
	}
	if m.Deletes[1].Table != "t2" || !int64sEqual(m.Deletes[1].Rowids, []int64{10, 20}) {
		t.Errorf("deletes[1] mismatch: %+v", m.Deletes[1])
	}
}

func TestDiffReadyMsgEmptyRoundTrip(t *testing.T) {
	orig := DiffReadyMsg{Seq: 5}
	buf := Serialize(orig)
	msg, err := Deserialize(buf)
	if err != nil {
		t.Fatal(err)
	}
	m := msg.(DiffReadyMsg)
	if m.Seq != 5 {
		t.Errorf("seq: got %d, want 5", m.Seq)
	}
	if len(m.Patchset) != 0 {
		t.Errorf("patchset: got %v, want empty", m.Patchset)
	}
	if len(m.Deletes) != 0 {
		t.Errorf("deletes: got %v, want empty", m.Deletes)
	}
}

func TestDeserializeRejectsTruncated(t *testing.T) {
	buf := []byte{0x00, 0x00}
	_, err := Deserialize(buf)
	if err == nil {
		t.Fatal("expected error for truncated buffer")
	}
}

func TestHelloMsgWithOwnedTables(t *testing.T) {
	orig := HelloMsg{
		ProtocolVersion: ProtocolVersion,
		SchemaVersion:   42,
		OwnedTables:     []string{"drafts", "local_prefs", "settings"},
	}
	buf := Serialize(orig)
	msg, err := Deserialize(buf)
	if err != nil {
		t.Fatal(err)
	}
	m := msg.(HelloMsg)
	if m.ProtocolVersion != ProtocolVersion {
		t.Errorf("protocol_version: got %d", m.ProtocolVersion)
	}
	if m.SchemaVersion != 42 {
		t.Errorf("schema_version: got %d", m.SchemaVersion)
	}
	if len(m.OwnedTables) != 3 {
		t.Fatalf("owned_tables: got %d, want 3", len(m.OwnedTables))
	}
	want := []string{"drafts", "local_prefs", "settings"}
	for i, w := range want {
		if m.OwnedTables[i] != w {
			t.Errorf("owned_tables[%d]: got %q, want %q", i, m.OwnedTables[i], w)
		}
	}
}

func TestHelloMsgWithoutOwnedTables(t *testing.T) {
	orig := HelloMsg{ProtocolVersion: ProtocolVersion, SchemaVersion: 7}
	buf := Serialize(orig)
	msg, err := Deserialize(buf)
	if err != nil {
		t.Fatal(err)
	}
	m := msg.(HelloMsg)
	if len(m.OwnedTables) != 0 {
		t.Errorf("owned_tables: got %v, want empty", m.OwnedTables)
	}
}

func TestPeerMessageRoundTripAsMaster(t *testing.T) {
	orig := PeerMessage{
		SenderRole: RoleAsMaster,
		Payload:    ChangesetMsg{Seq: 42, Data: Changeset{0x01, 0x02, 0x03}},
	}
	buf := SerializePeer(orig)
	decoded, err := DeserializePeer(buf)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.SenderRole != RoleAsMaster {
		t.Errorf("sender_role: got %d, want AsMaster", decoded.SenderRole)
	}
	cs := decoded.Payload.(ChangesetMsg)
	if cs.Seq != 42 {
		t.Errorf("seq: got %d, want 42", cs.Seq)
	}
	if !bytesEqual(cs.Data, Changeset{0x01, 0x02, 0x03}) {
		t.Errorf("data mismatch")
	}
}

func TestPeerMessageRoundTripAsReplica(t *testing.T) {
	orig := PeerMessage{
		SenderRole: RoleAsReplica,
		Payload:    AckMsg{Seq: 99},
	}
	buf := SerializePeer(orig)
	decoded, err := DeserializePeer(buf)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.SenderRole != RoleAsReplica {
		t.Errorf("sender_role: got %d, want AsReplica", decoded.SenderRole)
	}
	ack := decoded.Payload.(AckMsg)
	if ack.Seq != 99 {
		t.Errorf("seq: got %d, want 99", ack.Seq)
	}
}

func TestDeserializeRejectsOversized(t *testing.T) {
	buf := make([]byte, int(MaxMessageSize)+5+1)
	length := MaxMessageSize + 1
	buf[0] = byte(length)
	buf[1] = byte(length >> 8)
	buf[2] = byte(length >> 16)
	buf[3] = byte(length >> 24)
	buf[4] = byte(TagHello)
	_, err := Deserialize(buf)
	if err == nil {
		t.Fatal("expected error for oversized message")
	}
}

func TestDeserializeRejectsAbsurdArrayCount(t *testing.T) {
	buf := make([]byte, 4)
	buf = append(buf, byte(TagBucketHashes))
	buf = append(buf, 0xFF, 0xFF, 0xFF, 0xFF) // count = 0xFFFFFFFF
	total := uint32(len(buf) - 4)
	buf[0] = byte(total)
	buf[1] = byte(total >> 8)
	buf[2] = byte(total >> 16)
	buf[3] = byte(total >> 24)
	_, err := Deserialize(buf)
	if err == nil {
		t.Fatal("expected error for absurd array count")
	}
}

// Helpers.

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func int64sEqual(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
