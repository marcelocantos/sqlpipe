// Copyright 2026 The sqlpipe Authors
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <set>
#include <span>
#include <sqlite3.h>
#include <stdexcept>
#include <string>
#include <variant>
#include <vector>

// ── types.h ─────────────────────────────────────────────────────
namespace sqlpipe {

/// Monotonically increasing sequence number for changesets.
using Seq = std::int64_t;

/// Schema version tracked by PRAGMA schema_version.
using SchemaVersion = std::int32_t;

/// A byte buffer holding a raw SQLite changeset blob.
using Changeset = std::vector<std::uint8_t>;

/// Column value. Uses std::variant to represent SQLite types.
using Value = std::variant<
    std::monostate,            // NULL
    std::int64_t,              // INTEGER
    double,                    // REAL
    std::string,               // TEXT
    std::vector<std::uint8_t>  // BLOB
>;

/// The type of row operation.
enum class OpType : std::uint8_t {
    Insert = 1,
    Update = 2,
    Delete = 3,
};

/// A single row-level change extracted from a changeset.
struct ChangeEvent {
    std::string        table;
    OpType             op;
    std::vector<bool>  pk_flags;    // true for PK columns
    std::vector<Value> old_values;  // populated for UPDATE, DELETE
    std::vector<Value> new_values;  // populated for INSERT, UPDATE
};

/// Conflict resolution action returned by ConflictCallback.
enum class ConflictAction : std::uint8_t {
    Omit,      ///< Skip this change; the conflicting row is left as-is.
    Replace,   ///< Overwrite the conflicting row with the incoming change.
    Abort,     ///< Abort the entire changeset application.
};

/// Conflict type reported during changeset application.
enum class ConflictType : std::uint8_t {
    Data,        ///< A directly conflicting change (different values for same row).
    NotFound,    ///< The row to update/delete was not found on the replica.
    Conflict,    ///< A row with the same PK already exists (on INSERT).
    Constraint,  ///< A constraint (UNIQUE, NOT NULL, CHECK) would be violated.
    ForeignKey,  ///< A foreign key constraint would be violated.
};

/// Callback for conflict resolution on the replica side.
using ConflictCallback = std::function<ConflictAction(
    ConflictType type, const ChangeEvent& event)>;

} // namespace sqlpipe

// ── error.h ─────────────────────────────────────────────────────
namespace sqlpipe {

/// Error codes returned by sqlpipe operations.
enum class ErrorCode : int {
    Ok = 0,
    SqliteError,      ///< An underlying SQLite call failed.
    ProtocolError,    ///< Malformed or unexpected message.
    SequenceGap,      ///< Received a sequence number that doesn't follow.
    SchemaMismatch,   ///< Master and replica schemas differ.
    InvalidState,       ///< Operation not valid in the current state.
    ResyncRequired,     ///< Log doesn't cover the gap; full resync needed.
    OwnershipRejected,  ///< Peer ownership request was rejected by the server.
};

/// Exception thrown by sqlpipe operations.
class Error : public std::runtime_error {
public:
    Error(ErrorCode code, const std::string& msg)
        : std::runtime_error(msg), code_(code) {}

    ErrorCode code() const noexcept { return code_; }

private:
    ErrorCode code_;
};

} // namespace sqlpipe

// ── protocol.h ──────────────────────────────────────────────────
namespace sqlpipe {

inline constexpr std::uint32_t kProtocolVersion = 1;

// ── Message types ───────────────────────────────────────────────────

/// Sent by both sides during handshake to exchange state.
struct HelloMsg {
    std::uint32_t protocol_version;  ///< Must match kProtocolVersion.
    Seq           seq;               ///< Sender's current sequence number.
    SchemaVersion schema_version;    ///< Sender's schema fingerprint.
    std::set<std::string> owned_tables;  ///< Tables the sender wants to own (Peer mode).
};

/// Sent by master to announce a catchup sequence of changesets.
struct CatchupBeginMsg {
    Seq from_seq;  ///< First sequence number in the catchup range (inclusive).
    Seq to_seq;    ///< Last sequence number in the catchup range (inclusive).
};

/// A single changeset (one flush() worth of changes).
struct ChangesetMsg {
    Seq       seq;   ///< Sequence number assigned by the master.
    Changeset data;  ///< Raw SQLite changeset blob.
};

/// Marks the end of a catchup sequence. Replica transitions to Live.
struct CatchupEndMsg {};

/// Initiates a full resync. Replica drops and recreates all tables.
struct ResyncBeginMsg {
    SchemaVersion schema_version;  ///< Master's schema fingerprint.
    std::string   schema_sql;      ///< CREATE TABLE statements to apply.
};

/// Carries all rows for one table during a full resync.
struct ResyncTableMsg {
    std::string table_name;  ///< Name of the table being synced.
    Changeset   data;        ///< Changeset containing all rows as INSERTs.
};

/// Marks the end of a full resync. Replica transitions to Live.
struct ResyncEndMsg {
    Seq seq;  ///< Master's current sequence number.
};

/// Acknowledgement sent by the replica after applying a changeset.
struct AckMsg {
    Seq seq;  ///< The sequence number that was applied.
};

/// Protocol-level error. Receiving side should transition to Error state.
struct ErrorMsg {
    ErrorCode   code;    ///< Machine-readable error category.
    std::string detail;  ///< Human-readable description.
};

using Message = std::variant<
    HelloMsg,
    CatchupBeginMsg,
    ChangesetMsg,
    CatchupEndMsg,
    ResyncBeginMsg,
    ResyncTableMsg,
    ResyncEndMsg,
    AckMsg,
    ErrorMsg
>;

// ── Wire format tags ────────────────────────────────────────────────

enum class MessageTag : std::uint8_t {
    Hello        = 0x01,
    CatchupBegin = 0x02,
    Changeset    = 0x03,
    CatchupEnd   = 0x04,
    ResyncBegin  = 0x05,
    ResyncTable  = 0x06,
    ResyncEnd    = 0x07,
    Ack          = 0x08,
    Error        = 0x09,
};

// ── Serialization ───────────────────────────────────────────────────

/// Serialize a Message to a length-prefixed byte buffer.
/// Format: [4-byte total_length LE][1-byte tag][payload...]
std::vector<std::uint8_t> serialize(const Message& msg);

/// Deserialize a byte buffer (including the 4-byte length prefix) into a Message.
Message deserialize(std::span<const std::uint8_t> buf);

} // namespace sqlpipe

// ── master.h ────────────────────────────────────────────────────
namespace sqlpipe {

struct MasterConfig {
    /// Maximum number of changesets to retain in the log for catchup.
    /// Older entries are pruned. 0 = unlimited.
    std::size_t max_log_entries = 10000;

    /// If set, only track these tables. nullopt = track all.
    /// An empty set means track nothing.
    std::optional<std::set<std::string>> table_filter;

    /// Meta-table key for storing the sequence number.
    std::string seq_key = "seq";
};

/// The sending side of the replication protocol.
///
/// Does NOT own the sqlite3* handle. Caller must keep it open for
/// the Master's lifetime.
class Master {
public:
    explicit Master(sqlite3* db, MasterConfig config = {});
    ~Master();

    Master(const Master&) = delete;
    Master& operator=(const Master&) = delete;
    Master(Master&&) noexcept;
    Master& operator=(Master&&) noexcept;

    /// Call after committing a write transaction. Extracts the changeset,
    /// assigns a sequence number, stores it in the log, and returns the
    /// messages to send to connected replicas.
    /// Returns empty if nothing changed.
    std::vector<Message> flush();

    /// Process an incoming message from a replica.
    std::vector<Message> handle_message(const Message& msg);

    Seq current_seq() const;
    SchemaVersion schema_version() const;

    /// Generate the full resync message sequence.
    std::vector<Message> generate_resync();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace sqlpipe

// ── replica.h ───────────────────────────────────────────────────
namespace sqlpipe {

struct ReplicaConfig {
    /// Called when a conflict occurs during changeset application.
    /// Default (nullptr): ConflictAction::Abort.
    ConflictCallback on_conflict = nullptr;

    /// If set, only manage these tables during resync (drop/recreate).
    /// nullopt = all tracked tables (default). Empty set = nothing.
    std::optional<std::set<std::string>> table_filter;

    /// Meta-table key for storing the sequence number.
    std::string seq_key = "seq";
};

/// Return type for Replica::handle_message.
struct HandleResult {
    std::vector<Message>     messages;  ///< Protocol responses to send back.
    std::vector<ChangeEvent> changes;   ///< Row-level changes applied this call.
};

/// The receiving side of the replication protocol.
///
/// Does NOT own the sqlite3* handle. Caller must keep it open for
/// the Replica's lifetime.
class Replica {
public:
    explicit Replica(sqlite3* db, ReplicaConfig config = {});
    ~Replica();

    Replica(const Replica&) = delete;
    Replica& operator=(const Replica&) = delete;
    Replica(Replica&&) noexcept;
    Replica& operator=(Replica&&) noexcept;

    /// Generate the initial HelloMsg to send to the master.
    Message hello() const;

    /// Process an incoming message from the master.
    HandleResult handle_message(const Message& msg);

    Seq current_seq() const;
    SchemaVersion schema_version() const;

    /// Replica connection lifecycle state.
    enum class State : std::uint8_t {
        Init,       ///< Created but hello() not yet called.
        Handshake,  ///< hello() sent, awaiting master's response.
        Catchup,    ///< Receiving missed changesets from the log.
        Resync,     ///< Receiving a full database snapshot.
        Live,       ///< Streaming; ready for real-time changesets.
        Error,      ///< A protocol or application error occurred.
    };

    State state() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace sqlpipe

// ── peer.h ──────────────────────────────────────────────────────
namespace sqlpipe {

/// Server-side callback to approve or reject a client's ownership request.
/// Receives the set of tables the client wants to own.
/// Returns true to approve, false to reject.
using ApproveOwnershipCallback = std::function<bool(
    const std::set<std::string>& requested_tables)>;

struct PeerConfig {
    /// Tables this peer wants to own (client-side: sent in hello).
    /// Ignored on the server side (computed as complement of client's).
    std::set<std::string> owned_tables;

    /// Server-side ownership validation callback.
    /// Non-null indicates this peer is the server.
    /// nullptr = auto-approve any request.
    ApproveOwnershipCallback approve_ownership = nullptr;

    /// Conflict callback for the internal Replica.
    ConflictCallback on_conflict = nullptr;

    /// Max log entries for the internal Master.
    std::size_t max_log_entries = 10000;
};

/// Identifies whether the sender was acting as master or replica.
enum class SenderRole : std::uint8_t {
    AsMaster  = 0,  ///< Sender is acting as master (replicating owned tables).
    AsReplica = 1,  ///< Sender is acting as replica (acks/hellos for other side).
};

/// A protocol message with a directional tag for peer-to-peer routing.
struct PeerMessage {
    SenderRole sender_role;
    Message    payload;
};

/// Return type for Peer::handle_message.
struct PeerHandleResult {
    std::vector<PeerMessage>  messages;  ///< Protocol responses to send back.
    std::vector<ChangeEvent>  changes;   ///< Row-level changes applied.
};

/// Bidirectional replication peer.
///
/// Wraps a Master (for owned tables) and a Replica (for the remote peer's
/// tables) behind a symmetric API.
///
/// Does NOT own the sqlite3* handle.
class Peer {
public:
    explicit Peer(sqlite3* db, PeerConfig config = {});
    ~Peer();

    Peer(const Peer&) = delete;
    Peer& operator=(const Peer&) = delete;
    Peer(Peer&&) noexcept;
    Peer& operator=(Peer&&) noexcept;

    /// Initiate the handshake (client only).
    /// Returns PeerMessages to send to the remote peer.
    std::vector<PeerMessage> start();

    /// Flush local changes on owned tables.
    /// Returns PeerMessages to send to the remote peer.
    std::vector<PeerMessage> flush();

    /// Process an incoming PeerMessage from the remote peer.
    PeerHandleResult handle_message(const PeerMessage& msg);

    /// Peer lifecycle state.
    enum class State : std::uint8_t {
        Init,        ///< Created, not yet started.
        Negotiating, ///< Ownership negotiation in progress.
        Syncing,     ///< Handshake/catchup/resync in progress.
        Live,        ///< Both directions are live.
        Error,       ///< A protocol or application error occurred.
    };

    State state() const;

    /// The tables this peer owns (mastering).
    const std::set<std::string>& owned_tables() const;

    /// The tables the remote peer owns (replicating).
    const std::set<std::string>& remote_tables() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

/// Serialize a PeerMessage to a length-prefixed byte buffer.
/// Format: [4B LE length][1B sender_role][1B tag][payload...]
std::vector<std::uint8_t> serialize(const PeerMessage& msg);

/// Deserialize a byte buffer into a PeerMessage.
PeerMessage deserialize_peer(std::span<const std::uint8_t> buf);

} // namespace sqlpipe
