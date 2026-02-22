// Copyright 2026 The sqlpipe Authors
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstdint>
#include <functional>
#include <memory>
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

/// Callback for replica change events.
/// Called once per row change, after application. Return false to stop iteration.
using ChangeCallback = std::function<bool(const ChangeEvent&)>;

/// Conflict resolution action.
enum class ConflictAction : std::uint8_t {
    Omit,
    Replace,
    Abort,
};

/// Conflict type reported during changeset application.
enum class ConflictType : std::uint8_t {
    Data,
    NotFound,
    Conflict,
    Constraint,
    ForeignKey,
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
    SqliteError,
    ProtocolError,
    SequenceGap,
    SchemaMismatch,
    InvalidState,
    ResyncRequired,
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

struct HelloMsg {
    std::uint32_t protocol_version;
    Seq           seq;
    SchemaVersion schema_version;
};

struct CatchupBeginMsg {
    Seq from_seq;  // inclusive
    Seq to_seq;    // inclusive
};

struct ChangesetMsg {
    Seq       seq;
    Changeset data;
};

struct CatchupEndMsg {};

struct ResyncBeginMsg {
    SchemaVersion schema_version;
    std::string   schema_sql;
};

struct ResyncTableMsg {
    std::string table_name;
    Changeset   data;
};

struct ResyncEndMsg {
    Seq seq;
};

struct AckMsg {
    Seq seq;
};

struct ErrorMsg {
    ErrorCode   code;
    std::string detail;
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
    /// Called for each row-level change after a changeset is applied.
    ChangeCallback on_change = nullptr;

    /// Called when a conflict occurs during changeset application.
    /// Default (nullptr): ConflictAction::Abort.
    ConflictCallback on_conflict = nullptr;

    /// Notifications for resync lifecycle.
    std::function<void()> on_resync_begin = nullptr;
    std::function<void()> on_resync_end   = nullptr;
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
    std::vector<Message> handle_message(const Message& msg);

    Seq current_seq() const;
    SchemaVersion schema_version() const;

    enum class State : std::uint8_t {
        Init,
        Handshake,
        Catchup,
        Resync,
        Live,
        Error,
    };

    State state() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace sqlpipe
