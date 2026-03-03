// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package sqlpipe

// MessageTag identifies message types on the wire.
type MessageTag uint8

const (
	TagHello        MessageTag = 0x01
	TagChangeset    MessageTag = 0x03
	TagAck          MessageTag = 0x08
	TagError        MessageTag = 0x09
	TagBucketHashes MessageTag = 0x0A
	TagNeedBuckets  MessageTag = 0x0B
	TagRowHashes    MessageTag = 0x0C
	TagDiffReady    MessageTag = 0x0D
)

// Message is the interface satisfied by all protocol messages.
type Message interface {
	messageTag() MessageTag
}

// HelloMsg is sent by both sides during handshake to exchange schema state.
type HelloMsg struct {
	ProtocolVersion uint32
	SchemaVersion   SchemaVersion
	OwnedTables     []string // Sorted. Tables the sender wants to own (Peer mode).
}

func (HelloMsg) messageTag() MessageTag { return TagHello }

// ChangesetMsg carries a single changeset (one Flush worth of changes).
type ChangesetMsg struct {
	Seq  Seq
	Data Changeset
}

func (ChangesetMsg) messageTag() MessageTag { return TagChangeset }

// AckMsg acknowledges that the replica applied a changeset.
type AckMsg struct {
	Seq Seq
}

func (AckMsg) messageTag() MessageTag { return TagAck }

// ErrorMsg is a protocol-level error.
type ErrorMsg struct {
	Code                ErrorCode
	Detail              string
	RemoteSchemaVersion SchemaVersion // SchemaMismatch only.
	RemoteSchemaSQL     string        // SchemaMismatch only.
}

func (ErrorMsg) messageTag() MessageTag { return TagError }

// BucketHashEntry is one bucket's hash in a BucketHashesMsg.
type BucketHashEntry struct {
	Table    string
	BucketLo int64  // Inclusive rowid lower bound.
	BucketHi int64  // Inclusive rowid upper bound.
	Hash     uint64 // XOR of fnv1a(rowid||row_hash) per row.
	RowCount int64
}

// BucketHashesMsg is sent by replica with per-table bucket hashes.
type BucketHashesMsg struct {
	Buckets []BucketHashEntry
}

func (BucketHashesMsg) messageTag() MessageTag { return TagBucketHashes }

// NeedBucketRange identifies a bucket range the master needs detail for.
type NeedBucketRange struct {
	Table string
	Lo    int64
	Hi    int64
}

// NeedBucketsMsg lists the buckets that differ and need row-level detail.
type NeedBucketsMsg struct {
	Ranges []NeedBucketRange
}

func (NeedBucketsMsg) messageTag() MessageTag { return TagNeedBuckets }

// RowHashRun is a contiguous run of rowids with their hashes.
type RowHashRun struct {
	StartRowid int64
	Count      int64
	Hashes     []uint64
}

// RowHashesEntry holds row hashes for one bucket.
type RowHashesEntry struct {
	Table string
	Lo    int64
	Hi    int64
	Runs  []RowHashRun
}

// RowHashesMsg is sent by replica with per-row hashes for requested buckets.
type RowHashesMsg struct {
	Entries []RowHashesEntry
}

func (RowHashesMsg) messageTag() MessageTag { return TagRowHashes }

// TableDeletes is a per-table list of rowids to delete.
type TableDeletes struct {
	Table  string
	Rowids []int64
}

// DiffReadyMsg carries the computed diff (INSERT patchset + per-table deletes).
type DiffReadyMsg struct {
	Seq      Seq
	Patchset Changeset
	Deletes  []TableDeletes
}

func (DiffReadyMsg) messageTag() MessageTag { return TagDiffReady }

// PeerMessage wraps a Message with a directional tag for peer-to-peer routing.
type PeerMessage struct {
	SenderRole SenderRole
	Payload    Message
}

// HandleResult is the return type for Replica.HandleMessage.
type HandleResult struct {
	Messages      []Message
	Changes       []ChangeEvent
	Subscriptions []QueryResult
}

// PeerHandleResult is the return type for Peer.HandleMessage.
type PeerHandleResult struct {
	Messages []PeerMessage
	Changes  []ChangeEvent
}

// Config structs.

// MasterConfig configures a Master.
type MasterConfig struct {
	TableFilter      *TableFilter            // nil = track all tables.
	SeqKey           string                  // Meta-table key (default "seq").
	BucketSize       int64                   // Rows per bucket (default 1024).
	OnProgress       ProgressCallback        // nil = no reporting.
	OnSchemaMismatch SchemaMismatchCallback  // nil = default behaviour.
	OnLog            LogCallback             // nil = discard log output.
}

// ReplicaConfig configures a Replica.
type ReplicaConfig struct {
	OnConflict       ConflictCallback        // nil = ConflictAbort.
	TableFilter      *TableFilter            // nil = all tables.
	SeqKey           string                  // Meta-table key (default "seq").
	BucketSize       int64                   // Rows per bucket (default 1024).
	OnProgress       ProgressCallback        // nil = no reporting.
	OnSchemaMismatch SchemaMismatchCallback  // nil = default behaviour.
	OnLog            LogCallback             // nil = discard log output.
}

// PeerConfig configures a Peer.
type PeerConfig struct {
	OwnedTables      map[string]bool         // Tables this peer owns.
	TableFilter      *TableFilter            // nil = all tables.
	ApproveOwnership ApproveOwnershipCallback // Non-nil = server side.
	OnConflict       ConflictCallback
	OnProgress       ProgressCallback
	OnSchemaMismatch SchemaMismatchCallback
	OnLog            LogCallback             // nil = discard log output.
}
