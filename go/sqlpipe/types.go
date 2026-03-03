// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package sqlpipe

const (
	Version      = "0.6.0"
	VersionMajor = 0
	VersionMinor = 6
	VersionPatch = 0
)

// Seq is a monotonically increasing sequence number for changesets.
type Seq int64

// SchemaVersion is an FNV-1a fingerprint of the sorted CREATE TABLE SQL.
type SchemaVersion int32

// Changeset holds a raw SQLite changeset blob.
type Changeset []byte

// SubscriptionID is an opaque handle for a query subscription.
type SubscriptionID uint64

// Value represents a SQLite column value.
// Concrete types: nil (NULL), int64, float64, string, []byte (BLOB).
type Value any

// OpType identifies a row-level operation.
type OpType uint8

const (
	OpInsert OpType = 1
	OpUpdate OpType = 2
	OpDelete OpType = 3
)

// ConflictAction is the resolution action returned by a ConflictCallback.
type ConflictAction uint8

const (
	ConflictOmit    ConflictAction = iota // Skip; conflicting row left as-is.
	ConflictReplace                       // Overwrite the conflicting row.
	ConflictAbort                         // Abort entire changeset application.
)

// ConflictType identifies the kind of conflict during changeset application.
type ConflictType uint8

const (
	ConflictData       ConflictType = iota // Different values for same row.
	ConflictNotFound                       // Row to update/delete not found.
	ConflictConflict                       // Row with same PK already exists.
	ConflictConstraint                     // UNIQUE/NOT NULL/CHECK violated.
	ConflictForeignKey                     // Foreign key constraint violated.
)

// DiffPhase identifies the current phase of the diff sync protocol.
type DiffPhase uint8

const (
	DiffComputingBuckets  DiffPhase = iota // Computing bucket hashes.
	DiffComparingBuckets                   // Comparing bucket hashes (master).
	DiffComputingRowHash                   // Computing per-row hashes.
	DiffBuildingPatchset                   // Building INSERT patchset (master).
	DiffApplyingPatchset                   // Applying patchset + deletes (replica).
)

// SenderRole identifies direction in peer-to-peer messages.
type SenderRole uint8

const (
	RoleAsMaster  SenderRole = 0 // Sender acting as master.
	RoleAsReplica SenderRole = 1 // Sender acting as replica.
)

// ReplicaState represents the Replica connection lifecycle.
type ReplicaState uint8

const (
	ReplicaInit        ReplicaState = iota // Created but Hello() not yet called.
	ReplicaHandshake                       // Hello sent, awaiting master's response.
	ReplicaDiffBuckets                     // Sent bucket hashes, awaiting NeedBucketsMsg.
	ReplicaDiffRows                        // Sent row hashes, awaiting DiffReadyMsg.
	ReplicaLive                            // Streaming; ready for real-time changesets.
	ReplicaError                           // A protocol or application error occurred.
)

// PeerState represents the Peer lifecycle.
type PeerState uint8

const (
	PeerInit        PeerState = iota // Created, not yet started.
	PeerNegotiating                  // Ownership negotiation in progress.
	PeerDiffing                      // Diff sync in progress.
	PeerLive                         // Both directions are live.
	PeerError                        // A protocol or application error occurred.
)

// ChangeEvent is a single row-level change extracted from a changeset.
type ChangeEvent struct {
	Table     string
	Op        OpType
	PKFlags   []bool  // true for PK columns.
	OldValues []Value // Populated for UPDATE, DELETE.
	NewValues []Value // Populated for INSERT, UPDATE.
}

// QueryResult is the full result set of a subscribed query.
type QueryResult struct {
	ID      SubscriptionID
	Columns []string
	Rows    [][]Value
}

// DiffProgress reports progress during diff sync.
type DiffProgress struct {
	Phase      DiffPhase
	Table      string // Current table (empty if N/A).
	ItemsDone  int64  // Items processed so far.
	ItemsTotal int64  // Total items (0 if unknown).
}

// TableFilter restricts which tables are tracked.
// A nil *TableFilter means "all tables". A non-nil value restricts to the set.
type TableFilter struct {
	Tables map[string]bool
}

// ConflictCallback is called for conflict resolution on the replica side.
type ConflictCallback func(ConflictType, ChangeEvent) ConflictAction

// LogLevel identifies the severity of a log message.
type LogLevel uint8

const (
	LogDebug LogLevel = iota
	LogInfo
	LogWarn
	LogError
)

// LogCallback is called for library log output.
type LogCallback func(LogLevel, string)

// ProgressCallback is called for diff sync progress reporting.
type ProgressCallback func(DiffProgress)

// SchemaMismatchCallback is called when a schema mismatch is detected.
// Return true to retry after altering the local DB; false for default behaviour.
type SchemaMismatchCallback func(remoteSV, localSV SchemaVersion, remoteSchemaSQL string) bool

// ApproveOwnershipCallback validates a client's ownership request (server-side).
// Return true to approve, false to reject.
type ApproveOwnershipCallback func(requestedTables map[string]bool) bool

// Protocol constants.
const (
	ProtocolVersion = 5
	DefaultBucketSize int64  = 1024
	MaxMessageSize    uint32 = 64 * 1024 * 1024
	MaxArrayCount     uint32 = 10_000_000
)
