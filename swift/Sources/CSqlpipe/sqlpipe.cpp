// Copyright 2026 The sqlpipe Authors
// SPDX-License-Identifier: Apache-2.0
#include "sqlpipe.h"
#include <sqlift.h>

#include <algorithm>
#include <cassert>
#include <cstring>
#include <deque>
#include <map>
#include <format>
#include <lz4.h>
#include <unordered_map>
#include <unordered_set>

// ── Logging macro ───────────────────────────────────────────────
#define SQLPIPE_LOG(cb, level, ...) \
    do { if (cb) (cb)(level, std::format(__VA_ARGS__)); } while(0)

// ── sqlite_util.h ───────────────────────────────────────────────
namespace sqlpipe::detail {

/// RAII wrapper for sqlite3_stmt*.
class StmtGuard {
public:
    StmtGuard() = default;
    explicit StmtGuard(sqlite3_stmt* s) : stmt_(s) {}
    ~StmtGuard() { if (stmt_) sqlite3_finalize(stmt_); }

    StmtGuard(const StmtGuard&) = delete;
    StmtGuard& operator=(const StmtGuard&) = delete;
    StmtGuard(StmtGuard&& o) noexcept : stmt_(o.stmt_) { o.stmt_ = nullptr; }
    StmtGuard& operator=(StmtGuard&& o) noexcept {
        if (this != &o) {
            if (stmt_) sqlite3_finalize(stmt_);
            stmt_ = o.stmt_;
            o.stmt_ = nullptr;
        }
        return *this;
    }

    sqlite3_stmt* get() const { return stmt_; }

    sqlite3_stmt* release() {
        auto* s = stmt_;
        stmt_ = nullptr;
        return s;
    }

private:
    sqlite3_stmt* stmt_ = nullptr;
};

/// Execute SQL or throw.
inline void exec(sqlite3* db, const char* sql) {
    char* err = nullptr;
    int rc = sqlite3_exec(db, sql, nullptr, nullptr, &err);
    if (rc != SQLITE_OK) {
        std::string msg = err ? err : "unknown error";
        sqlite3_free(err);
        throw Error(ErrorCode::SqliteError, msg);
    }
}

/// Prepare a statement or throw.
inline StmtGuard prepare(sqlite3* db, const char* sql) {
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        throw Error(ErrorCode::SqliteError, sqlite3_errmsg(db));
    }
    return StmtGuard(stmt);
}

/// Step a statement expecting SQLITE_DONE, or throw.
inline void step_done(sqlite3* db, sqlite3_stmt* stmt) {
    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        throw Error(ErrorCode::SqliteError, sqlite3_errmsg(db));
    }
}

} // namespace sqlpipe::detail

// ── session_guard.h ─────────────────────────────────────────────
namespace sqlpipe::detail {

/// RAII wrapper for sqlite3_session*.
class SessionGuard {
public:
    SessionGuard() = default;
    explicit SessionGuard(sqlite3_session* s) : session_(s) {}
    ~SessionGuard() { if (session_) sqlite3session_delete(session_); }

    SessionGuard(const SessionGuard&) = delete;
    SessionGuard& operator=(const SessionGuard&) = delete;
    SessionGuard(SessionGuard&& o) noexcept : session_(o.session_) { o.session_ = nullptr; }
    SessionGuard& operator=(SessionGuard&& o) noexcept {
        if (this != &o) {
            if (session_) sqlite3session_delete(session_);
            session_ = o.session_;
            o.session_ = nullptr;
        }
        return *this;
    }

    sqlite3_session* get() const { return session_; }

    sqlite3_session* release() {
        auto* s = session_;
        session_ = nullptr;
        return s;
    }

private:
    sqlite3_session* session_ = nullptr;
};

} // namespace sqlpipe::detail

// ── meta.h ──────────────────────────────────────────────────────
namespace sqlpipe::detail {

/// Create _sqlpipe_meta table if it doesn't exist.
void ensure_meta_table(sqlite3* db);

/// Read the current sequence number from _sqlpipe_meta.
Seq read_seq(sqlite3* db, const std::string& key = "seq");

/// Write the sequence number to _sqlpipe_meta.
void write_seq(sqlite3* db, Seq seq, const std::string& key = "seq");

/// Compute a fingerprint of the user table definitions (excludes internal tables).
/// Uses FNV-1a over the sorted CREATE TABLE SQL.
/// If filter is non-null, only include tables in the filter.
SchemaVersion compute_schema_fingerprint(
    sqlite3* db, const std::set<std::string>* filter = nullptr);

/// Get all user table names (excludes _sqlpipe_* and sqlite_* tables).
/// Only includes tables with explicit PRIMARY KEYs.
/// Rejects WITHOUT ROWID tables.
/// If filter is non-null, only include tables in the filter.
std::vector<std::string> get_tracked_tables(
    sqlite3* db, const std::set<std::string>* filter = nullptr,
    const LogCallback* on_log = nullptr);

/// Get the CREATE TABLE SQL for all tracked user tables.
/// If filter is non-null, only include tables in the filter.
std::string get_schema_sql(
    sqlite3* db, const std::set<std::string>* filter = nullptr);

/// Get the CREATE TABLE SQL for a single table.
std::string get_table_create_sql(sqlite3* db, const std::string& table);

/// Migrate the local schema to match the remote schema using sqlift.
/// Returns true if migration succeeded, false on error.
bool auto_migrate_schema(sqlite3* db, const std::string& remote_schema_sql,
                         const LogCallback& on_log);

/// Check if a table uses WITHOUT ROWID.
bool is_without_rowid(sqlite3* db, const std::string& table);

} // namespace sqlpipe::detail

// ── hash.h ──────────────────────────────────────────────────────
namespace sqlpipe::detail {

/// 64-bit FNV-1a hash of a row's column values (type-tagged).
std::uint64_t hash_row(sqlite3_stmt* stmt, int ncols);

/// Hash a (rowid, row_hash) pair for bucket accumulation.
std::uint64_t hash_bucket_entry(std::int64_t rowid, std::uint64_t row_hash);

struct RowHashInfo {
    std::int64_t  rowid;
    std::uint64_t hash;
};

/// Compute per-row hashes for rows in [lo, hi] rowid range.
std::vector<RowHashInfo> compute_row_hashes(
    sqlite3* db, const std::string& table,
    std::int64_t lo, std::int64_t hi);

struct BucketInfo {
    std::int64_t  lo, hi;
    std::uint64_t hash;
    std::int64_t  count;
};

/// Compute bucket hashes for a single table.
std::vector<BucketInfo> compute_table_buckets(
    sqlite3* db, const std::string& table, std::int64_t bucket_size);

/// Compute bucket hashes for all tracked tables, respecting filter.
std::vector<BucketHashEntry> compute_all_buckets(
    sqlite3* db, const std::set<std::string>* filter,
    std::int64_t bucket_size);

/// Build an INSERT patchset for specific rowids in a table.
Changeset build_insert_patchset(
    sqlite3* db, const std::string& table,
    const std::vector<std::int64_t>& rowids);

/// Combine multiple patchsets into one via sqlite3changegroup.
Changeset combine_patchsets(const std::vector<Changeset>& parts);

} // namespace sqlpipe::detail

// ── changeset_iter.h ────────────────────────────────────────────
namespace sqlpipe::detail {

/// Convert a sqlite3_value* to our Value variant.
Value to_value(sqlite3_value* val);

/// Convert an SQLite op code (SQLITE_INSERT/UPDATE/DELETE) to OpType.
OpType sqlite_op_to_optype(int sqlite_op);

/// Collect all row-level changes from a changeset into a vector.
std::vector<ChangeEvent> collect_events(const Changeset& data);

/// Build a ChangeEvent from a changeset iterator at its current position.
ChangeEvent extract_event(sqlite3_changeset_iter* iter);

} // namespace sqlpipe::detail

// ── protocol.cpp ────────────────────────────────────────────────
namespace sqlpipe {

namespace {

// ── Little-endian encoding helpers ──────────────────────────────────

void put_u8(std::vector<std::uint8_t>& buf, std::uint8_t v) {
    buf.push_back(v);
}

void put_u32(std::vector<std::uint8_t>& buf, std::uint32_t v) {
    buf.push_back(static_cast<std::uint8_t>(v));
    buf.push_back(static_cast<std::uint8_t>(v >> 8));
    buf.push_back(static_cast<std::uint8_t>(v >> 16));
    buf.push_back(static_cast<std::uint8_t>(v >> 24));
}

void put_i32(std::vector<std::uint8_t>& buf, std::int32_t v) {
    put_u32(buf, static_cast<std::uint32_t>(v));
}

void put_i64(std::vector<std::uint8_t>& buf, std::int64_t v) {
    auto u = static_cast<std::uint64_t>(v);
    for (int i = 0; i < 8; ++i) {
        buf.push_back(static_cast<std::uint8_t>(u >> (i * 8)));
    }
}

void put_u64(std::vector<std::uint8_t>& buf, std::uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        buf.push_back(static_cast<std::uint8_t>(v >> (i * 8)));
    }
}

void put_bytes(std::vector<std::uint8_t>& buf,
               const void* data, std::uint32_t len) {
    put_u32(buf, len);
    auto* p = static_cast<const std::uint8_t*>(data);
    buf.insert(buf.end(), p, p + len);
}

void put_string(std::vector<std::uint8_t>& buf, const std::string& s) {
    put_bytes(buf, s.data(), static_cast<std::uint32_t>(s.size()));
}

void put_changeset(std::vector<std::uint8_t>& buf, const Changeset& cs) {
    constexpr std::size_t kCompressionThreshold = 64;
    if (cs.size() < kCompressionThreshold) {
        // Uncompressed: [u32 total] [0x00] [raw_data]
        put_u32(buf, static_cast<std::uint32_t>(cs.size() + 1));
        put_u8(buf, 0x00);
        buf.insert(buf.end(), cs.begin(), cs.end());
    } else {
        int src_size = static_cast<int>(cs.size());
        int max_dst = LZ4_compressBound(src_size);
        std::vector<std::uint8_t> tmp(max_dst);
        int compressed_size = LZ4_compress_default(
            reinterpret_cast<const char*>(cs.data()),
            reinterpret_cast<char*>(tmp.data()),
            src_size, max_dst);
        if (compressed_size > 0 &&
            compressed_size < static_cast<int>(cs.size())) {
            // LZ4: [u32 total] [0x01] [u32 original_len] [compressed_data]
            put_u32(buf, static_cast<std::uint32_t>(1 + 4 + compressed_size));
            put_u8(buf, 0x01);
            put_u32(buf, static_cast<std::uint32_t>(cs.size()));
            buf.insert(buf.end(), tmp.begin(),
                       tmp.begin() + compressed_size);
        } else {
            // Fallback: uncompressed
            put_u32(buf, static_cast<std::uint32_t>(cs.size() + 1));
            put_u8(buf, 0x00);
            buf.insert(buf.end(), cs.begin(), cs.end());
        }
    }
}

// ── Reader for deserialization ──────────────────────────────────────

class Reader {
public:
    Reader(std::span<const std::uint8_t> buf)
        : data_(buf.data()), size_(buf.size()), pos_(0) {}

    std::uint8_t read_u8() {
        check(1);
        return data_[pos_++];
    }

    std::uint32_t read_u32() {
        check(4);
        std::uint32_t v = 0;
        for (int i = 0; i < 4; ++i)
            v |= static_cast<std::uint32_t>(data_[pos_++]) << (i * 8);
        return v;
    }

    std::int32_t read_i32() {
        return static_cast<std::int32_t>(read_u32());
    }

    std::int64_t read_i64() {
        check(8);
        std::uint64_t v = 0;
        for (int i = 0; i < 8; ++i)
            v |= static_cast<std::uint64_t>(data_[pos_++]) << (i * 8);
        return static_cast<std::int64_t>(v);
    }

    std::uint64_t read_u64() {
        check(8);
        std::uint64_t v = 0;
        for (int i = 0; i < 8; ++i)
            v |= static_cast<std::uint64_t>(data_[pos_++]) << (i * 8);
        return v;
    }

    std::string read_string() {
        auto len = read_u32();
        if (len > kMaxMessageSize) {
            throw Error(ErrorCode::ProtocolError,
                        "string length exceeds limit");
        }
        check(len);
        std::string s(reinterpret_cast<const char*>(data_ + pos_), len);
        pos_ += len;
        return s;
    }

    Changeset read_changeset() {
        auto len = read_u32();
        if (len == 0) return {};
        check(len);
        auto type = read_u8();
        auto payload_len = len - 1;
        if (type == 0x00) {
            // Uncompressed
            Changeset cs(data_ + pos_, data_ + pos_ + payload_len);
            pos_ += payload_len;
            return cs;
        } else if (type == 0x01) {
            // LZ4
            auto original_len = read_u32();
            auto compressed_len = payload_len - 4;
            check(compressed_len);
            Changeset cs(original_len);
            int result = LZ4_decompress_safe(
                reinterpret_cast<const char*>(data_ + pos_),
                reinterpret_cast<char*>(cs.data()),
                static_cast<int>(compressed_len),
                static_cast<int>(original_len));
            if (result < 0) {
                throw Error(ErrorCode::ProtocolError,
                            "LZ4 decompression failed");
            }
            pos_ += compressed_len;
            return cs;
        } else {
            throw Error(ErrorCode::ProtocolError,
                        "unknown changeset compression type");
        }
    }

    bool at_end() const { return pos_ >= size_; }

private:
    void check(std::size_t n) {
        if (pos_ + n > size_) {
            throw Error(ErrorCode::ProtocolError, "unexpected end of message");
        }
    }

    const std::uint8_t* data_;
    std::size_t size_;
    std::size_t pos_;
};

} // namespace

// ── serialize ───────────────────────────────────────────────────────

std::vector<std::uint8_t> serialize(const Message& msg) {
    std::vector<std::uint8_t> buf;
    // Reserve space for the 4-byte length prefix.
    buf.resize(4);

    std::visit([&](const auto& m) {
        using T = std::decay_t<decltype(m)>;

        if constexpr (std::is_same_v<T, HelloMsg>) {
            put_u8(buf, static_cast<std::uint8_t>(MessageTag::Hello));
            put_u32(buf, m.protocol_version);
            put_i32(buf, m.schema_version);
            put_u32(buf, static_cast<std::uint32_t>(m.owned_tables.size()));
            for (const auto& t : m.owned_tables) {
                put_string(buf, t);
            }
            put_i64(buf, m.last_seq);
        }
        else if constexpr (std::is_same_v<T, ChangesetMsg>) {
            put_u8(buf, static_cast<std::uint8_t>(MessageTag::Changeset));
            put_i64(buf, m.seq);
            put_changeset(buf, m.data);
        }
        else if constexpr (std::is_same_v<T, AckMsg>) {
            put_u8(buf, static_cast<std::uint8_t>(MessageTag::Ack));
            put_i64(buf, m.seq);
        }
        else if constexpr (std::is_same_v<T, ErrorMsg>) {
            put_u8(buf, static_cast<std::uint8_t>(MessageTag::Error));
            put_i32(buf, static_cast<std::int32_t>(m.code));
            put_string(buf, m.detail);
            put_i32(buf, m.remote_schema_version);
            put_string(buf, m.remote_schema_sql);
        }
        else if constexpr (std::is_same_v<T, BucketHashesMsg>) {
            put_u8(buf, static_cast<std::uint8_t>(MessageTag::BucketHashes));
            put_i64(buf, m.last_seq);
            put_u32(buf, m.protocol_version);
            put_i32(buf, m.schema_version);
            put_u32(buf, static_cast<std::uint32_t>(m.buckets.size()));
            for (const auto& b : m.buckets) {
                put_string(buf, b.table);
                put_i64(buf, b.bucket_lo);
                put_i64(buf, b.bucket_hi);
                put_u64(buf, b.hash);
                put_i64(buf, b.row_count);
            }
        }
        else if constexpr (std::is_same_v<T, NeedBucketsMsg>) {
            put_u8(buf, static_cast<std::uint8_t>(MessageTag::NeedBuckets));
            put_u32(buf, static_cast<std::uint32_t>(m.ranges.size()));
            for (const auto& r : m.ranges) {
                put_string(buf, r.table);
                put_i64(buf, r.lo);
                put_i64(buf, r.hi);
            }
        }
        else if constexpr (std::is_same_v<T, RowHashesMsg>) {
            put_u8(buf, static_cast<std::uint8_t>(MessageTag::RowHashes));
            put_u32(buf, static_cast<std::uint32_t>(m.entries.size()));
            for (const auto& e : m.entries) {
                put_string(buf, e.table);
                put_i64(buf, e.lo);
                put_i64(buf, e.hi);
                put_u32(buf, static_cast<std::uint32_t>(e.runs.size()));
                for (const auto& run : e.runs) {
                    put_i64(buf, run.start_rowid);
                    put_i64(buf, run.count);
                    for (std::int64_t i = 0; i < run.count; ++i) {
                        put_u64(buf, run.hashes[static_cast<std::size_t>(i)]);
                    }
                }
            }
        }
        else if constexpr (std::is_same_v<T, DiffReadyMsg>) {
            put_u8(buf, static_cast<std::uint8_t>(MessageTag::DiffReady));
            put_i64(buf, m.seq);
            put_changeset(buf, m.patchset);
            put_u32(buf, static_cast<std::uint32_t>(m.deletes.size()));
            for (const auto& td : m.deletes) {
                put_string(buf, td.table);
                put_u32(buf, static_cast<std::uint32_t>(td.rowids.size()));
                for (auto rid : td.rowids) {
                    put_i64(buf, rid);
                }
            }
        }
    }, msg);

    // Patch the length prefix: total_length = tag + payload (excludes the 4 prefix bytes).
    std::uint32_t total = static_cast<std::uint32_t>(buf.size() - 4);
    buf[0] = static_cast<std::uint8_t>(total);
    buf[1] = static_cast<std::uint8_t>(total >> 8);
    buf[2] = static_cast<std::uint8_t>(total >> 16);
    buf[3] = static_cast<std::uint8_t>(total >> 24);

    return buf;
}

// ── deserialize ─────────────────────────────────────────────────────

Message deserialize(std::span<const std::uint8_t> buf) {
    if (buf.size() < 5) {
        throw Error(ErrorCode::ProtocolError, "message too short");
    }
    if (buf.size() > kMaxMessageSize + 4) {
        throw Error(ErrorCode::ProtocolError,
                    "message exceeds maximum size (" +
                    std::to_string(buf.size()) + " bytes)");
    }

    Reader r(buf);
    auto total_len = r.read_u32();
    (void)total_len;  // already have the full buffer

    auto tag = static_cast<MessageTag>(r.read_u8());

    auto check_count = [](std::uint32_t n) {
        if (n > kMaxArrayCount) {
            throw Error(ErrorCode::ProtocolError,
                        "array count exceeds limit (" +
                        std::to_string(n) + ")");
        }
    };

    switch (tag) {
    case MessageTag::Hello: {
        HelloMsg m;
        m.protocol_version = r.read_u32();
        m.schema_version = r.read_i32();
        {
            auto count = r.read_u32();
            check_count(count);
            for (std::uint32_t i = 0; i < count; ++i) {
                m.owned_tables.insert(r.read_string());
            }
        }
        m.last_seq = r.read_i64();
        return m;
    }
    case MessageTag::Changeset: {
        ChangesetMsg m;
        m.seq = r.read_i64();
        m.data = r.read_changeset();
        return m;
    }
    case MessageTag::Ack: {
        AckMsg m;
        m.seq = r.read_i64();
        return m;
    }
    case MessageTag::Error: {
        ErrorMsg m;
        m.code = static_cast<ErrorCode>(r.read_i32());
        m.detail = r.read_string();
        m.remote_schema_version = r.read_i32();
        m.remote_schema_sql = r.read_string();
        return m;
    }
    case MessageTag::BucketHashes: {
        BucketHashesMsg m;
        m.last_seq = r.read_i64();
        m.protocol_version = r.read_u32();
        m.schema_version = r.read_i32();
        auto count = r.read_u32();
        check_count(count);
        m.buckets.resize(count);
        for (std::uint32_t i = 0; i < count; ++i) {
            m.buckets[i].table = r.read_string();
            m.buckets[i].bucket_lo = r.read_i64();
            m.buckets[i].bucket_hi = r.read_i64();
            m.buckets[i].hash = r.read_u64();
            m.buckets[i].row_count = r.read_i64();
        }
        return m;
    }
    case MessageTag::NeedBuckets: {
        NeedBucketsMsg m;
        auto count = r.read_u32();
        check_count(count);
        m.ranges.resize(count);
        for (std::uint32_t i = 0; i < count; ++i) {
            m.ranges[i].table = r.read_string();
            m.ranges[i].lo = r.read_i64();
            m.ranges[i].hi = r.read_i64();
        }
        return m;
    }
    case MessageTag::RowHashes: {
        RowHashesMsg m;
        auto entry_count = r.read_u32();
        check_count(entry_count);
        m.entries.resize(entry_count);
        for (std::uint32_t i = 0; i < entry_count; ++i) {
            m.entries[i].table = r.read_string();
            m.entries[i].lo = r.read_i64();
            m.entries[i].hi = r.read_i64();
            auto run_count = r.read_u32();
            check_count(run_count);
            m.entries[i].runs.resize(run_count);
            for (std::uint32_t j = 0; j < run_count; ++j) {
                m.entries[i].runs[j].start_rowid = r.read_i64();
                m.entries[i].runs[j].count = r.read_i64();
                m.entries[i].runs[j].hashes.resize(
                    static_cast<std::size_t>(m.entries[i].runs[j].count));
                for (std::int64_t k = 0; k < m.entries[i].runs[j].count; ++k) {
                    m.entries[i].runs[j].hashes[static_cast<std::size_t>(k)] =
                        r.read_u64();
                }
            }
        }
        return m;
    }
    case MessageTag::DiffReady: {
        DiffReadyMsg m;
        m.seq = r.read_i64();
        m.patchset = r.read_changeset();
        auto del_count = r.read_u32();
        check_count(del_count);
        m.deletes.resize(del_count);
        for (std::uint32_t i = 0; i < del_count; ++i) {
            m.deletes[i].table = r.read_string();
            auto rid_count = r.read_u32();
            check_count(rid_count);
            m.deletes[i].rowids.resize(rid_count);
            for (std::uint32_t j = 0; j < rid_count; ++j) {
                m.deletes[i].rowids[j] = r.read_i64();
            }
        }
        return m;
    }
    default:
        throw Error(ErrorCode::ProtocolError,
                    "unknown message tag: " +
                    std::to_string(static_cast<int>(tag)));
    }
}

} // namespace sqlpipe

// ── meta.cpp ────────────────────────────────────────────────────

namespace sqlpipe::detail {

void ensure_meta_table(sqlite3* db) {
    exec(db,
        "CREATE TABLE IF NOT EXISTS _sqlpipe_meta ("
        "  key   TEXT PRIMARY KEY,"
        "  value TEXT NOT NULL"
        ")");

    // Seed seq=0 if not present.
    exec(db,
        "INSERT OR IGNORE INTO _sqlpipe_meta (key, value) "
        "VALUES ('seq', '0')");
}

Seq read_seq(sqlite3* db, const std::string& key) {
    auto stmt = prepare(db,
        "SELECT value FROM _sqlpipe_meta WHERE key=?");
    sqlite3_bind_text(stmt.get(), 1, key.c_str(),
                      static_cast<int>(key.size()), SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt.get());
    if (rc == SQLITE_ROW) {
        return sqlite3_column_int64(stmt.get(), 0);
    }
    return 0;
}

void write_seq(sqlite3* db, Seq seq, const std::string& key) {
    auto stmt = prepare(db,
        "INSERT OR REPLACE INTO _sqlpipe_meta (key, value) VALUES (?, ?)");
    sqlite3_bind_text(stmt.get(), 1, key.c_str(),
                      static_cast<int>(key.size()), SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt.get(), 2, seq);
    step_done(db, stmt.get());
}

SchemaVersion compute_schema_fingerprint(
        sqlite3* db, const std::set<std::string>* filter) {
    auto sql = get_schema_sql(db, filter);

    int err_type;
    char* err_msg = nullptr;

    char* json = sqlift_parse(sql.c_str(), &err_type, &err_msg);
    if (!json) {
        std::string msg = err_msg ? err_msg : "unknown error";
        sqlift_free(err_msg);
        throw Error(ErrorCode::SqliteError,
                    "sqlift_parse failed: " + msg);
    }

    char* hex = sqlift_schema_hash(json, &err_type, &err_msg);
    sqlift_free(json);
    if (!hex) {
        std::string msg = err_msg ? err_msg : "unknown error";
        sqlift_free(err_msg);
        throw Error(ErrorCode::SqliteError,
                    "sqlift_schema_hash failed: " + msg);
    }

    // FNV-1a 32-bit of the structural hash.
    std::uint32_t hash = 2166136261u;
    for (const char* p = hex; *p; ++p) {
        hash ^= static_cast<std::uint8_t>(*p);
        hash *= 16777619u;
    }
    sqlift_free(hex);
    return static_cast<SchemaVersion>(hash);
}

bool is_without_rowid(sqlite3* db, const std::string& table) {
    // A WITHOUT ROWID table will fail when you try to select rowid.
    std::string sql = "SELECT rowid FROM \"" + table + "\" LIMIT 0";
    sqlite3_stmt* raw = nullptr;
    int rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &raw, nullptr);
    if (raw) sqlite3_finalize(raw);
    return rc != SQLITE_OK;
}

std::vector<std::string> get_tracked_tables(
        sqlite3* db, const std::set<std::string>* filter,
        const LogCallback* on_log) {
    auto stmt = prepare(db,
        "SELECT name FROM sqlite_master "
        "WHERE type='table' "
        "  AND name NOT LIKE '_sqlpipe_%' "
        "  AND name NOT LIKE '_sqlift_%' "
        "  AND name NOT LIKE 'sqlite_%' "
        "ORDER BY name");

    std::vector<std::string> tables;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        std::string name(reinterpret_cast<const char*>(
            sqlite3_column_text(stmt.get(), 0)));

        // Skip tables not in the filter (if provided).
        if (filter && filter->find(name) == filter->end()) {
            continue;
        }

        // Check if table has an explicit PK.
        std::string pragma = "PRAGMA table_info('" + name + "')";
        auto pk_stmt = prepare(db, pragma.c_str());
        bool has_pk = false;
        while (sqlite3_step(pk_stmt.get()) == SQLITE_ROW) {
            if (sqlite3_column_int(pk_stmt.get(), 5) > 0) {  // pk column
                has_pk = true;
                break;
            }
        }

        if (!has_pk) {
            SQLPIPE_LOG(on_log ? *on_log : LogCallback{}, LogLevel::Warn,
                       "table '{}' has no explicit PRIMARY KEY, skipping", name);
            continue;
        }

        // Reject WITHOUT ROWID tables.
        if (is_without_rowid(db, name)) {
            throw Error(ErrorCode::WithoutRowidTable,
                        "table '" + name + "' uses WITHOUT ROWID (not supported)");
        }

        tables.push_back(std::move(name));
    }

    return tables;
}

std::string get_schema_sql(
        sqlite3* db, const std::set<std::string>* filter) {
    auto tables = get_tracked_tables(db, filter);
    std::string sql;
    for (const auto& t : tables) {
        if (!sql.empty()) sql += ";\n";
        sql += get_table_create_sql(db, t);
    }
    if (!sql.empty()) sql += ";";
    return sql;
}

bool auto_migrate_schema(sqlite3* db, const std::string& remote_schema_sql,
                         const LogCallback& on_log) {
    int err_type = 0;
    char* err_msg = nullptr;

    // Parse the remote (desired) schema.
    char* desired_json = sqlift_parse(remote_schema_sql.c_str(),
                                      &err_type, &err_msg);
    if (!desired_json) {
        SQLPIPE_LOG(on_log, LogLevel::Error,
                    "auto_migrate: failed to parse remote schema: {}",
                    err_msg ? err_msg : "unknown");
        sqlift_free(err_msg);
        return false;
    }

    // Get the local user-table schema (excludes _sqlpipe_meta and other
    // internal tables), then parse it with sqlift.
    auto local_sql = get_schema_sql(db);
    char* current_json = sqlift_parse(
        local_sql.empty() ? "" : local_sql.c_str(),
        &err_type, &err_msg);
    if (!current_json) {
        SQLPIPE_LOG(on_log, LogLevel::Error,
                    "auto_migrate: failed to parse local schema: {}",
                    err_msg ? err_msg : "unknown");
        sqlift_free(err_msg);
        sqlift_free(desired_json);
        return false;
    }

    // Diff current → desired.
    char* plan_json = sqlift_diff(current_json, desired_json,
                                  &err_type, &err_msg);
    sqlift_free(current_json);
    sqlift_free(desired_json);
    if (!plan_json) {
        SQLPIPE_LOG(on_log, LogLevel::Error,
                    "auto_migrate: failed to diff schemas: {}",
                    err_msg ? err_msg : "unknown");
        sqlift_free(err_msg);
        return false;
    }

    // Apply the migration plan (allow destructive — master is authoritative).
    sqlift_db* sdb = sqlift_db_wrap(db);
    int rc = sqlift_apply(sdb, plan_json, /*allow_destructive=*/1,
                          &err_type, &err_msg);
    sqlift_free(plan_json);
    sqlift_db_close(sdb);

    if (rc != 0) {
        SQLPIPE_LOG(on_log, LogLevel::Error,
                    "auto_migrate: failed to apply migration: {}",
                    err_msg ? err_msg : "unknown");
        sqlift_free(err_msg);
        return false;
    }

    SQLPIPE_LOG(on_log, LogLevel::Info,
                "auto_migrate: schema migrated to match master");
    return true;
}

std::string get_table_create_sql(sqlite3* db, const std::string& table) {
    auto stmt = prepare(db,
        "SELECT sql FROM sqlite_master WHERE type='table' AND name=?");
    sqlite3_bind_text(stmt.get(), 1, table.c_str(),
                      static_cast<int>(table.size()), SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt.get());
    if (rc == SQLITE_ROW) {
        return reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
    }
    throw Error(ErrorCode::SqliteError,
                "table '" + table + "' not found in sqlite_master");
}

} // namespace sqlpipe::detail

// ── hash.cpp ────────────────────────────────────────────────────

namespace sqlpipe::detail {

namespace {
constexpr std::uint64_t kFnv64Offset = 14695981039346656037ULL;
constexpr std::uint64_t kFnv64Prime  = 1099511628211ULL;

inline void fnv64_byte(std::uint64_t& hash, std::uint8_t b) {
    hash ^= b;
    hash *= kFnv64Prime;
}

inline void fnv64_bytes(std::uint64_t& hash,
                        const void* data, std::size_t len) {
    auto* p = static_cast<const std::uint8_t*>(data);
    for (std::size_t i = 0; i < len; ++i) {
        fnv64_byte(hash, p[i]);
    }
}
} // namespace

/// Feed a Value into a running FNV-1a hash (type-tagged, same encoding as hash_row).
inline void hash_value(std::uint64_t& hash, const Value& v) {
    std::visit([&](const auto& val) {
        using T = std::decay_t<decltype(val)>;
        if constexpr (std::is_same_v<T, std::monostate>) {
            fnv64_byte(hash, 0x00);
        } else if constexpr (std::is_same_v<T, std::int64_t>) {
            fnv64_byte(hash, 0x01);
            auto u = static_cast<std::uint64_t>(val);
            std::uint8_t bytes[8];
            for (int j = 0; j < 8; ++j)
                bytes[j] = static_cast<std::uint8_t>(u >> (j * 8));
            fnv64_bytes(hash, bytes, 8);
        } else if constexpr (std::is_same_v<T, double>) {
            fnv64_byte(hash, 0x02);
            std::uint8_t bytes[8];
            std::memcpy(bytes, &val, 8);
            fnv64_bytes(hash, bytes, 8);
        } else if constexpr (std::is_same_v<T, std::string>) {
            fnv64_byte(hash, 0x03);
            std::uint32_t ulen = static_cast<std::uint32_t>(val.size());
            std::uint8_t lenbytes[4];
            for (int j = 0; j < 4; ++j)
                lenbytes[j] = static_cast<std::uint8_t>(ulen >> (j * 8));
            fnv64_bytes(hash, lenbytes, 4);
            fnv64_bytes(hash, val.data(), val.size());
        } else if constexpr (std::is_same_v<T, std::vector<std::uint8_t>>) {
            fnv64_byte(hash, 0x04);
            std::uint32_t ulen = static_cast<std::uint32_t>(val.size());
            std::uint8_t lenbytes[4];
            for (int j = 0; j < 4; ++j)
                lenbytes[j] = static_cast<std::uint8_t>(ulen >> (j * 8));
            fnv64_bytes(hash, lenbytes, 4);
            fnv64_bytes(hash, val.data(), val.size());
        }
    }, v);
}

std::uint64_t hash_row(sqlite3_stmt* stmt, int ncols) {
    std::uint64_t hash = kFnv64Offset;

    for (int i = 0; i < ncols; ++i) {
        int type = sqlite3_column_type(stmt, i);
        switch (type) {
        case SQLITE_NULL:
            fnv64_byte(hash, 0x00);
            break;
        case SQLITE_INTEGER: {
            fnv64_byte(hash, 0x01);
            auto val = sqlite3_column_int64(stmt, i);
            auto u = static_cast<std::uint64_t>(val);
            std::uint8_t bytes[8];
            for (int j = 0; j < 8; ++j)
                bytes[j] = static_cast<std::uint8_t>(u >> (j * 8));
            fnv64_bytes(hash, bytes, 8);
            break;
        }
        case SQLITE_FLOAT: {
            fnv64_byte(hash, 0x02);
            double val = sqlite3_column_double(stmt, i);
            std::uint8_t bytes[8];
            std::memcpy(bytes, &val, 8);
            fnv64_bytes(hash, bytes, 8);
            break;
        }
        case SQLITE_TEXT: {
            fnv64_byte(hash, 0x03);
            int len = sqlite3_column_bytes(stmt, i);
            std::uint32_t ulen = static_cast<std::uint32_t>(len);
            std::uint8_t lenbytes[4];
            for (int j = 0; j < 4; ++j)
                lenbytes[j] = static_cast<std::uint8_t>(ulen >> (j * 8));
            fnv64_bytes(hash, lenbytes, 4);
            fnv64_bytes(hash, sqlite3_column_text(stmt, i),
                        static_cast<std::size_t>(len));
            break;
        }
        case SQLITE_BLOB: {
            fnv64_byte(hash, 0x04);
            int len = sqlite3_column_bytes(stmt, i);
            std::uint32_t ulen = static_cast<std::uint32_t>(len);
            std::uint8_t lenbytes[4];
            for (int j = 0; j < 4; ++j)
                lenbytes[j] = static_cast<std::uint8_t>(ulen >> (j * 8));
            fnv64_bytes(hash, lenbytes, 4);
            fnv64_bytes(hash, sqlite3_column_blob(stmt, i),
                        static_cast<std::size_t>(len));
            break;
        }
        default:
            fnv64_byte(hash, 0x00);
            break;
        }
    }
    return hash;
}

std::uint64_t hash_bucket_entry(std::int64_t rowid, std::uint64_t row_hash) {
    std::uint64_t hash = kFnv64Offset;
    auto u = static_cast<std::uint64_t>(rowid);
    std::uint8_t bytes[8];
    for (int i = 0; i < 8; ++i)
        bytes[i] = static_cast<std::uint8_t>(u >> (i * 8));
    fnv64_bytes(hash, bytes, 8);
    for (int i = 0; i < 8; ++i)
        bytes[i] = static_cast<std::uint8_t>(row_hash >> (i * 8));
    fnv64_bytes(hash, bytes, 8);
    return hash;
}

std::vector<RowHashInfo> compute_row_hashes(
        sqlite3* db, const std::string& table,
        std::int64_t lo, std::int64_t hi) {
    std::string sql = "SELECT rowid, * FROM \"" + table +
                      "\" WHERE rowid >= ? AND rowid <= ? ORDER BY rowid";
    auto stmt = prepare(db, sql.c_str());
    sqlite3_bind_int64(stmt.get(), 1, lo);
    sqlite3_bind_int64(stmt.get(), 2, hi);

    int ncols = sqlite3_column_count(stmt.get());

    std::vector<RowHashInfo> result;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        std::int64_t rowid = sqlite3_column_int64(stmt.get(), 0);
        // Hash columns 1..ncols-1 (skip the rowid column at position 0).
        std::uint64_t h = kFnv64Offset;
        for (int c = 1; c < ncols; ++c) {
            int type = sqlite3_column_type(stmt.get(), c);
            switch (type) {
            case SQLITE_NULL:
                fnv64_byte(h, 0x00);
                break;
            case SQLITE_INTEGER: {
                fnv64_byte(h, 0x01);
                auto val = sqlite3_column_int64(stmt.get(), c);
                auto u = static_cast<std::uint64_t>(val);
                std::uint8_t bytes[8];
                for (int j = 0; j < 8; ++j)
                    bytes[j] = static_cast<std::uint8_t>(u >> (j * 8));
                fnv64_bytes(h, bytes, 8);
                break;
            }
            case SQLITE_FLOAT: {
                fnv64_byte(h, 0x02);
                double val = sqlite3_column_double(stmt.get(), c);
                std::uint8_t bytes[8];
                std::memcpy(bytes, &val, 8);
                fnv64_bytes(h, bytes, 8);
                break;
            }
            case SQLITE_TEXT: {
                fnv64_byte(h, 0x03);
                int len = sqlite3_column_bytes(stmt.get(), c);
                std::uint32_t ulen = static_cast<std::uint32_t>(len);
                std::uint8_t lenbytes[4];
                for (int j = 0; j < 4; ++j)
                    lenbytes[j] = static_cast<std::uint8_t>(ulen >> (j * 8));
                fnv64_bytes(h, lenbytes, 4);
                fnv64_bytes(h, sqlite3_column_text(stmt.get(), c),
                            static_cast<std::size_t>(len));
                break;
            }
            case SQLITE_BLOB: {
                fnv64_byte(h, 0x04);
                int len = sqlite3_column_bytes(stmt.get(), c);
                std::uint32_t ulen = static_cast<std::uint32_t>(len);
                std::uint8_t lenbytes[4];
                for (int j = 0; j < 4; ++j)
                    lenbytes[j] = static_cast<std::uint8_t>(ulen >> (j * 8));
                fnv64_bytes(h, lenbytes, 4);
                fnv64_bytes(h, sqlite3_column_blob(stmt.get(), c),
                            static_cast<std::size_t>(len));
                break;
            }
            default:
                fnv64_byte(h, 0x00);
                break;
            }
        }
        result.push_back({rowid, h});
    }
    return result;
}

std::vector<BucketInfo> compute_table_buckets(
        sqlite3* db, const std::string& table, std::int64_t bucket_size) {
    // Get min and max rowid.
    std::string minmax_sql = "SELECT MIN(rowid), MAX(rowid) FROM \"" + table + "\"";
    auto stmt = prepare(db, minmax_sql.c_str());
    if (sqlite3_step(stmt.get()) != SQLITE_ROW ||
        sqlite3_column_type(stmt.get(), 0) == SQLITE_NULL) {
        return {};  // empty table
    }
    std::int64_t min_rid = sqlite3_column_int64(stmt.get(), 0);
    std::int64_t max_rid = sqlite3_column_int64(stmt.get(), 1);

    std::int64_t lo_bucket = min_rid / bucket_size;
    if (min_rid < 0) lo_bucket = (min_rid - bucket_size + 1) / bucket_size;
    std::int64_t hi_bucket = max_rid / bucket_size;
    if (max_rid < 0) hi_bucket = (max_rid - bucket_size + 1) / bucket_size;

    std::vector<BucketInfo> buckets;
    for (std::int64_t k = lo_bucket; k <= hi_bucket; ++k) {
        std::int64_t blo = k * bucket_size;
        std::int64_t bhi = blo + bucket_size - 1;

        auto rows = compute_row_hashes(db, table, blo, bhi);
        if (rows.empty()) continue;

        std::uint64_t bucket_hash = 0;
        for (const auto& row : rows) {
            bucket_hash ^= hash_bucket_entry(row.rowid, row.hash);
        }
        buckets.push_back({blo, bhi, bucket_hash,
                           static_cast<std::int64_t>(rows.size())});
    }
    return buckets;
}

std::vector<BucketHashEntry> compute_all_buckets(
        sqlite3* db, const std::set<std::string>* filter,
        std::int64_t bucket_size) {
    auto tables = get_tracked_tables(db, filter);
    std::vector<BucketHashEntry> result;
    for (const auto& table : tables) {
        auto buckets = compute_table_buckets(db, table, bucket_size);
        for (auto& b : buckets) {
            result.push_back(BucketHashEntry{
                table, b.lo, b.hi, b.hash, b.count});
        }
    }
    return result;
}

Changeset build_insert_patchset(
        sqlite3* db, const std::string& table,
        const std::vector<std::int64_t>& rowids) {
    if (rowids.empty()) return {};

    auto create_sql = get_table_create_sql(db, table);

    exec(db, "ATTACH ':memory:' AS _sqlpipe_stage");

    // Create table in _sqlpipe_stage.
    std::string prefixed = create_sql;
    auto pos = prefixed.find("CREATE TABLE ");
    if (pos != std::string::npos) {
        prefixed.insert(pos + 13, "_sqlpipe_stage.");
    }
    exec(db, prefixed.c_str());

    // Create session on _sqlpipe_stage.
    sqlite3_session* raw = nullptr;
    int rc = sqlite3session_create(db, "_sqlpipe_stage", &raw);
    if (rc != SQLITE_OK) {
        exec(db, "DETACH _sqlpipe_stage");
        throw Error(ErrorCode::SqliteError,
                    std::string("session_create: ") + sqlite3_errmsg(db));
    }
    SessionGuard session(raw);

    rc = sqlite3session_attach(raw, table.c_str());
    if (rc != SQLITE_OK) {
        exec(db, "DETACH _sqlpipe_stage");
        throw Error(ErrorCode::SqliteError,
                    std::string("session_attach: ") + sqlite3_errmsg(db));
    }

    // Insert target rows from main into _sqlpipe_stage.
    // Build the IN clause or use individual inserts.
    for (auto rid : rowids) {
        std::string ins_sql =
            "INSERT INTO _sqlpipe_stage.\"" + table +
            "\" SELECT * FROM main.\"" + table + "\" WHERE rowid = ?";
        auto ins_stmt = prepare(db, ins_sql.c_str());
        sqlite3_bind_int64(ins_stmt.get(), 1, rid);
        step_done(db, ins_stmt.get());
    }

    // Extract patchset.
    int n = 0;
    void* p = nullptr;
    rc = sqlite3session_patchset(raw, &n, &p);
    if (rc != SQLITE_OK) {
        exec(db, "DETACH _sqlpipe_stage");
        throw Error(ErrorCode::SqliteError,
                    std::string("session_patchset: ") + sqlite3_errmsg(db));
    }

    Changeset cs;
    if (n > 0 && p) {
        cs.assign(static_cast<std::uint8_t*>(p),
                  static_cast<std::uint8_t*>(p) + n);
    }
    sqlite3_free(p);

    // Cleanup.
    session = SessionGuard{};  // delete before detach
    exec(db, ("DROP TABLE _sqlpipe_stage.\"" + table + "\"").c_str());
    exec(db, "DETACH _sqlpipe_stage");

    return cs;
}

Changeset combine_patchsets(const std::vector<Changeset>& parts) {
    if (parts.empty()) return {};
    if (parts.size() == 1) return parts[0];

    sqlite3_changegroup* grp = nullptr;
    int rc = sqlite3changegroup_new(&grp);
    if (rc != SQLITE_OK) {
        throw Error(ErrorCode::SqliteError, "sqlite3changegroup_new failed");
    }

    for (const auto& cs : parts) {
        if (cs.empty()) continue;
        rc = sqlite3changegroup_add(grp,
            static_cast<int>(cs.size()),
            const_cast<void*>(static_cast<const void*>(cs.data())));
        if (rc != SQLITE_OK) {
            sqlite3changegroup_delete(grp);
            throw Error(ErrorCode::SqliteError, "sqlite3changegroup_add failed");
        }
    }

    int n = 0;
    void* p = nullptr;
    rc = sqlite3changegroup_output(grp, &n, &p);
    sqlite3changegroup_delete(grp);

    if (rc != SQLITE_OK) {
        sqlite3_free(p);
        throw Error(ErrorCode::SqliteError, "sqlite3changegroup_output failed");
    }

    Changeset result;
    if (n > 0 && p) {
        result.assign(static_cast<std::uint8_t*>(p),
                      static_cast<std::uint8_t*>(p) + n);
    }
    sqlite3_free(p);
    return result;
}

} // namespace sqlpipe::detail

// ── changeset_iter.cpp ──────────────────────────────────────────

namespace sqlpipe::detail {

Value to_value(sqlite3_value* val) {
    if (!val) return std::monostate{};

    switch (sqlite3_value_type(val)) {
    case SQLITE_NULL:
        return std::monostate{};
    case SQLITE_INTEGER:
        return sqlite3_value_int64(val);
    case SQLITE_FLOAT:
        return sqlite3_value_double(val);
    case SQLITE_TEXT: {
        auto* text = reinterpret_cast<const char*>(sqlite3_value_text(val));
        int len = sqlite3_value_bytes(val);
        return std::string(text, static_cast<std::size_t>(len));
    }
    case SQLITE_BLOB: {
        auto* data = static_cast<const std::uint8_t*>(sqlite3_value_blob(val));
        int len = sqlite3_value_bytes(val);
        return std::vector<std::uint8_t>(data, data + len);
    }
    default:
        return std::monostate{};
    }
}

OpType sqlite_op_to_optype(int sqlite_op) {
    switch (sqlite_op) {
    case SQLITE_INSERT: return OpType::Insert;
    case SQLITE_UPDATE: return OpType::Update;
    case SQLITE_DELETE: return OpType::Delete;
    default:
        throw Error(ErrorCode::ProtocolError,
                    "unknown sqlite operation: " + std::to_string(sqlite_op));
    }
}

ChangeEvent extract_event(sqlite3_changeset_iter* iter) {
    const char* table = nullptr;
    int ncol = 0, op = 0, indirect = 0;
    sqlite3changeset_op(iter, &table, &ncol, &op, &indirect);

    unsigned char* pk_raw = nullptr;
    int pk_ncol = 0;
    sqlite3changeset_pk(iter, &pk_raw, &pk_ncol);

    ChangeEvent event;
    event.table = table ? table : "";
    event.op = sqlite_op_to_optype(op);

    event.pk_flags.resize(static_cast<std::size_t>(ncol));
    for (int i = 0; i < ncol; ++i) {
        event.pk_flags[static_cast<std::size_t>(i)] = (pk_raw[i] != 0);
    }

    if (op == SQLITE_UPDATE || op == SQLITE_DELETE) {
        event.old_values.resize(static_cast<std::size_t>(ncol));
        for (int i = 0; i < ncol; ++i) {
            sqlite3_value* val = nullptr;
            sqlite3changeset_old(iter, i, &val);
            event.old_values[static_cast<std::size_t>(i)] = to_value(val);
        }
    }

    if (op == SQLITE_INSERT || op == SQLITE_UPDATE) {
        event.new_values.resize(static_cast<std::size_t>(ncol));
        for (int i = 0; i < ncol; ++i) {
            sqlite3_value* val = nullptr;
            sqlite3changeset_new(iter, i, &val);
            event.new_values[static_cast<std::size_t>(i)] = to_value(val);
        }
    }

    return event;
}

std::vector<ChangeEvent> collect_events(const Changeset& data) {
    std::vector<ChangeEvent> events;
    if (data.empty()) return events;

    sqlite3_changeset_iter* iter = nullptr;
    int rc = sqlite3changeset_start(
        &iter,
        static_cast<int>(data.size()),
        const_cast<void*>(static_cast<const void*>(data.data())));
    if (rc != SQLITE_OK) {
        throw Error(ErrorCode::SqliteError, "sqlite3changeset_start failed");
    }

    while (sqlite3changeset_next(iter) == SQLITE_ROW) {
        events.push_back(extract_event(iter));
    }

    sqlite3changeset_finalize(iter);
    return events;
}

} // namespace sqlpipe::detail

// ── master.cpp ──────────────────────────────────────────────────
namespace sqlpipe {

struct Master::Impl {
    sqlite3*                 db;
    MasterConfig             config;
    detail::SessionGuard     session;
    std::vector<std::string> tracked_tables;
    Seq                      seq = 0;
    SchemaVersion            cached_sv = 0;

    // Changeset queue for replay on reconnect.
    struct QueuedChangeset {
        Seq       seq;
        Changeset data;
    };
    std::deque<QueuedChangeset> changeset_queue;

    void enqueue_changeset(Seq s, const Changeset& data) {
        if (config.changeset_queue_size == 0) return;
        changeset_queue.push_back({s, data});
        while (changeset_queue.size() > config.changeset_queue_size) {
            changeset_queue.pop_front();
        }
    }

    // Diff handshake state.
    enum class HSState : std::uint8_t {
        Idle,
        WaitBucketHashes,
        WaitRowHashes,
        Live,
    };
    HSState hs_state = HSState::Idle;

    // Stored between rounds: the ranges we asked for row hashes.
    std::vector<NeedBucketRange> pending_ranges;

    const std::set<std::string>* filter() const {
        return config.table_filter ? &*config.table_filter : nullptr;
    }

    void report(DiffPhase phase, const std::string& table,
                std::int64_t done, std::int64_t total) {
        if (config.on_progress) {
            config.on_progress(DiffProgress{phase, table, done, total});
        }
    }

    bool flush_pending = false;
    bool in_auto_flush = false;

    static int commit_hook_cb(void* ctx) {
        auto* self = static_cast<Impl*>(ctx);
        if (!self->in_auto_flush) {
            self->flush_pending = true;
        }
        return 0;
    }

    void auto_flush() {
        in_auto_flush = true;

        // Check for schema changes.
        auto sv = detail::compute_schema_fingerprint(db, filter());
        if (sv != cached_sv) {
            cached_sv = sv;
            scan_tables();
            recreate_session();
        }

        auto cs = extract_changeset();
        if (!cs.empty()) {
            recreate_session();
            seq++;
            detail::write_seq(db, seq, config.seq_key);

            SQLPIPE_LOG(config.on_log, LogLevel::Debug,
                        "auto-flushed changeset seq={} ({} bytes)", seq, cs.size());

            enqueue_changeset(seq, cs);

            std::vector<Message> msgs = {
                Message{ChangesetMsg{seq, std::move(cs)}}};
            config.on_flush(msgs);
        }

        in_auto_flush = false;
    }

    void init() {
        detail::ensure_meta_table(db);
        seq = detail::read_seq(db, config.seq_key);
        cached_sv = detail::compute_schema_fingerprint(db, filter());
        scan_tables();
        recreate_session();

        if (config.on_flush) {
            sqlite3_commit_hook(db, &Impl::commit_hook_cb, this);
        }

        SQLPIPE_LOG(config.on_log, LogLevel::Info, "master initialized at seq={}", seq);
    }

    void scan_tables() {
        tracked_tables = detail::get_tracked_tables(db, filter(),
            config.on_log ? &config.on_log : nullptr);
        SQLPIPE_LOG(config.on_log, LogLevel::Info, "tracking {} tables", tracked_tables.size());
    }

    void recreate_session() {
        session = detail::SessionGuard{};  // delete old

        sqlite3_session* raw = nullptr;
        int rc = sqlite3session_create(db, "main", &raw);
        if (rc != SQLITE_OK) {
            throw Error(ErrorCode::SqliteError,
                        std::string("sqlite3session_create: ") + sqlite3_errmsg(db));
        }
        session = detail::SessionGuard(raw);

        for (const auto& t : tracked_tables) {
            rc = sqlite3session_attach(raw, t.c_str());
            if (rc != SQLITE_OK) {
                throw Error(ErrorCode::SqliteError,
                            std::string("sqlite3session_attach: ") + sqlite3_errmsg(db));
            }
        }
    }

    Changeset extract_changeset() {
        int n = 0;
        void* p = nullptr;
        int rc = sqlite3session_changeset(session.get(), &n, &p);
        if (rc != SQLITE_OK) {
            throw Error(ErrorCode::SqliteError,
                        std::string("sqlite3session_changeset: ") + sqlite3_errmsg(db));
        }

        Changeset cs;
        if (n > 0 && p) {
            cs.assign(static_cast<std::uint8_t*>(p),
                      static_cast<std::uint8_t*>(p) + n);
        }
        sqlite3_free(p);
        return cs;
    }

    std::vector<Message> handle_hello(const HelloMsg& hello) {
        if (hello.protocol_version != kProtocolVersion) {
            return {Message{ErrorMsg{ErrorCode::ProtocolError,
                "unsupported protocol version: " +
                std::to_string(hello.protocol_version)}}};
        }

        auto my_sv = detail::compute_schema_fingerprint(db, filter());

        // Schema mismatch → invoke callback or error.
        if (hello.schema_version != my_sv) {
            if (config.on_schema_mismatch &&
                config.on_schema_mismatch(hello.schema_version, my_sv, "")) {
                // Callback may have modified the schema. Recompute.
                cached_sv = detail::compute_schema_fingerprint(db, filter());
                scan_tables();
                recreate_session();
                my_sv = cached_sv;
            }
            if (hello.schema_version != my_sv) {
                SQLPIPE_LOG(config.on_log, LogLevel::Info,
                            "schema mismatch (replica={}, master={})",
                            hello.schema_version, my_sv);
                return {Message{ErrorMsg{ErrorCode::SchemaMismatch,
                    "schema mismatch: replica=" +
                    std::to_string(hello.schema_version) +
                    " master=" + std::to_string(my_sv),
                    my_sv,
                    detail::get_schema_sql(db, filter())}}};
            }
        }

        // Fast reconnect: if replica's seq matches ours and both > 0,
        // skip diff sync entirely.
        if (hello.last_seq > 0 && hello.last_seq == seq) {
            hs_state = HSState::Live;
            SQLPIPE_LOG(config.on_log, LogLevel::Info,
                        "hello ok, seq match ({}), skipping diff sync", seq);
            return {Message{HelloMsg{kProtocolVersion, my_sv, {}, seq}}};
        }

        // Queue replay: if replica's seq is behind but still within our
        // changeset queue, replay the queued changesets instead of
        // running full diff sync. Send HelloMsg with last_seq matching
        // the replica's seq so it triggers fast reconnect to Live,
        // then the queued changesets apply in Live state.
        if (hello.last_seq > 0 && !changeset_queue.empty() &&
            hello.last_seq >= changeset_queue.front().seq - 1) {
            // Find the first changeset after the replica's seq.
            std::vector<Message> result;
            result.push_back(Message{
                HelloMsg{kProtocolVersion, my_sv, {}, hello.last_seq}});
            std::size_t replayed = 0;
            for (const auto& qc : changeset_queue) {
                if (qc.seq > hello.last_seq) {
                    result.push_back(Message{
                        ChangesetMsg{qc.seq, qc.data}});
                    ++replayed;
                }
            }
            if (replayed > 0) {
                hs_state = HSState::Live;
                SQLPIPE_LOG(config.on_log, LogLevel::Info,
                            "queue replay: {} changesets (seq {}→{})",
                            replayed, hello.last_seq + 1, seq);
                return result;
            }
        }

        hs_state = HSState::WaitBucketHashes;
        SQLPIPE_LOG(config.on_log, LogLevel::Info, "hello ok, waiting for bucket hashes");
        return {Message{HelloMsg{kProtocolVersion, my_sv, {}, -1}}};
    }

    std::vector<Message> handle_bucket_hashes(const BucketHashesMsg& msg) {
        // Accept BucketHashes in any state — enables convergence loop
        // where the replica can initiate diff sync at any time, including
        // re-convergence checks while already Live.
        //
        // Clear any pending state from a previous round. If the replica
        // calls converge() while a previous round is in flight, this
        // ensures the master starts fresh rather than mixing rounds.
        pending_ranges.clear();

        // Protocol version check (if provided).
        if (msg.protocol_version != 0 &&
            msg.protocol_version != kProtocolVersion) {
            return {Message{ErrorMsg{ErrorCode::ProtocolError,
                "unsupported protocol version: " +
                std::to_string(msg.protocol_version)}}};
        }

        // Schema check (if provided).
        if (msg.schema_version != 0) {
            auto my_sv = detail::compute_schema_fingerprint(db, filter());
            if (msg.schema_version != my_sv) {
                if (config.on_schema_mismatch &&
                    config.on_schema_mismatch(msg.schema_version, my_sv, "")) {
                    cached_sv = detail::compute_schema_fingerprint(db, filter());
                    scan_tables();
                    recreate_session();
                    my_sv = cached_sv;
                }
                if (msg.schema_version != my_sv) {
                    SQLPIPE_LOG(config.on_log, LogLevel::Info,
                                "schema mismatch (replica={}, master={})",
                                msg.schema_version, my_sv);
                    return {Message{ErrorMsg{ErrorCode::SchemaMismatch,
                        "schema mismatch: replica=" +
                        std::to_string(msg.schema_version) +
                        " master=" + std::to_string(my_sv),
                        my_sv,
                        detail::get_schema_sql(db, filter())}}};
                }
            }
        }

        // Fast path: if the replica's seq is behind but within the
        // changeset queue, replay from the queue instead of diffing.
        if (msg.last_seq > 0 && msg.last_seq < seq &&
            !changeset_queue.empty() &&
            msg.last_seq >= changeset_queue.front().seq - 1) {
            std::vector<Message> result;
            std::size_t replayed = 0;
            for (const auto& qc : changeset_queue) {
                if (qc.seq > msg.last_seq) {
                    result.push_back(Message{
                        ChangesetMsg{qc.seq, qc.data}});
                    ++replayed;
                }
            }
            if (replayed > 0) {
                // Send an empty DiffReady first to transition the replica
                // from DiffBuckets to Live, then the queued changesets.
                std::vector<Message> out;
                out.push_back(Message{
                    NeedBucketsMsg{}});
                out.push_back(Message{
                    DiffReadyMsg{msg.last_seq, {}, {}}});
                out.insert(out.end(), result.begin(), result.end());
                hs_state = HSState::Live;
                SQLPIPE_LOG(config.on_log, LogLevel::Info,
                            "converge: queue replay {} changesets (seq {}→{})",
                            replayed, msg.last_seq + 1, seq);
                return out;
            }
        }

        // Compute our own bucket hashes.
        report(DiffPhase::ComputingBuckets, {},
               0, static_cast<std::int64_t>(tracked_tables.size()));
        auto my_buckets = detail::compute_all_buckets(
            db, filter(), config.bucket_size);
        report(DiffPhase::ComputingBuckets, {},
               static_cast<std::int64_t>(tracked_tables.size()),
               static_cast<std::int64_t>(tracked_tables.size()));

        // Build lookup: (table, lo) → hash for our buckets.
        struct BucketKey {
            std::string table;
            std::int64_t lo;
            bool operator==(const BucketKey& o) const {
                return table == o.table && lo == o.lo;
            }
        };
        struct BucketKeyHash {
            std::size_t operator()(const BucketKey& k) const {
                return std::hash<std::string>{}(k.table) ^
                       (std::hash<std::int64_t>{}(k.lo) << 1);
            }
        };
        std::unordered_map<BucketKey, std::uint64_t, BucketKeyHash>
            my_bucket_map;
        std::unordered_set<BucketKey, BucketKeyHash> my_bucket_keys;
        for (const auto& b : my_buckets) {
            BucketKey key{b.table, b.bucket_lo};
            my_bucket_map[key] = b.hash;
            my_bucket_keys.insert(key);
        }

        // Build lookup for replica's buckets.
        std::unordered_map<BucketKey, std::uint64_t, BucketKeyHash>
            their_bucket_map;
        std::unordered_set<BucketKey, BucketKeyHash> their_bucket_keys;
        for (const auto& b : msg.buckets) {
            BucketKey key{b.table, b.bucket_lo};
            their_bucket_map[key] = b.hash;
            their_bucket_keys.insert(key);
        }

        // Find mismatched buckets.
        NeedBucketsMsg need;

        // Buckets on master or replica (union of both key sets).
        std::unordered_set<BucketKey, BucketKeyHash> all_keys;
        all_keys.insert(my_bucket_keys.begin(), my_bucket_keys.end());
        all_keys.insert(their_bucket_keys.begin(), their_bucket_keys.end());

        for (const auto& key : all_keys) {
            auto my_it = my_bucket_map.find(key);
            auto their_it = their_bucket_map.find(key);

            bool differs = false;
            if (my_it == my_bucket_map.end() ||
                their_it == their_bucket_map.end()) {
                differs = true;  // one side has it, the other doesn't
            } else if (my_it->second != their_it->second) {
                differs = true;  // both have it, hashes differ
            }

            if (differs) {
                // Find the hi bound from whichever side has it.
                std::int64_t hi = key.lo + config.bucket_size - 1;
                need.ranges.push_back(
                    NeedBucketRange{key.table, key.lo, hi});
            }
        }

        report(DiffPhase::ComparingBuckets, {},
               static_cast<std::int64_t>(need.ranges.size()),
               static_cast<std::int64_t>(all_keys.size()));

        // Sort ranges for deterministic order.
        std::sort(need.ranges.begin(), need.ranges.end(),
            [](const NeedBucketRange& a, const NeedBucketRange& b) {
                if (a.table != b.table) return a.table < b.table;
                return a.lo < b.lo;
            });

        if (need.ranges.empty()) {
            // All buckets match. Skip row-hash exchange.
            hs_state = HSState::Live;
            SQLPIPE_LOG(config.on_log, LogLevel::Info, "all buckets match, entering live at seq={}", seq);
            return {Message{NeedBucketsMsg{}},
                    Message{DiffReadyMsg{seq, {}, {}}}};
        }

        pending_ranges = need.ranges;
        hs_state = HSState::WaitRowHashes;
        SQLPIPE_LOG(config.on_log, LogLevel::Info, "{} mismatched bucket ranges", need.ranges.size());
        return {Message{std::move(need)}};
    }

    std::vector<Message> handle_row_hashes(const RowHashesMsg& msg) {
        // Accept RowHashes when we have pending ranges (from a prior
        // BucketHashes comparison). This enables convergence loop
        // without strict state gating.
        if (pending_ranges.empty()) {
            return {Message{ErrorMsg{ErrorCode::InvalidState,
                "RowHashesMsg without pending ranges"}}};
        }

        // Build map of replica's rows: table → (rowid → hash).
        std::map<std::string,
                 std::map<std::int64_t, std::uint64_t>> replica_rows;
        for (const auto& entry : msg.entries) {
            auto& tbl_map = replica_rows[entry.table];
            for (const auto& run : entry.runs) {
                for (std::int64_t i = 0; i < run.count; ++i) {
                    tbl_map[run.start_rowid + i] =
                        run.hashes[static_cast<std::size_t>(i)];
                }
            }
        }

        // Compute diff per table and build patchset + deletes.
        std::vector<Changeset> patchsets;
        std::vector<TableDeletes> deletes;

        // Group pending_ranges by table.
        std::map<std::string, std::vector<std::pair<std::int64_t, std::int64_t>>>
            table_ranges;
        for (const auto& r : pending_ranges) {
            table_ranges[r.table].push_back({r.lo, r.hi});
        }

        std::int64_t tables_done = 0;
        auto tables_total = static_cast<std::int64_t>(table_ranges.size());

        for (const auto& [table, ranges] : table_ranges) {
            report(DiffPhase::ComputingRowHashes, table,
                   tables_done, tables_total);

            std::vector<std::int64_t> insert_rowids;
            std::vector<std::int64_t> update_rowids;
            std::vector<std::int64_t> delete_rowids;

            auto replica_it = replica_rows.find(table);

            for (const auto& [lo, hi] : ranges) {
                // Compute master's row hashes for this range.
                auto master_rows = detail::compute_row_hashes(db, table, lo, hi);

                // Build replica's row hash map for this range.
                std::map<std::int64_t, std::uint64_t> rep_range;
                if (replica_it != replica_rows.end()) {
                    auto& tbl_map = replica_it->second;
                    for (auto it = tbl_map.lower_bound(lo);
                         it != tbl_map.end() && it->first <= hi; ++it) {
                        rep_range[it->first] = it->second;
                    }
                }

                // Build master's row hash map for this range.
                std::map<std::int64_t, std::uint64_t> mas_range;
                for (const auto& row : master_rows) {
                    mas_range[row.rowid] = row.hash;
                }

                // Diff.
                for (const auto& [rid, mhash] : mas_range) {
                    auto rep_it = rep_range.find(rid);
                    if (rep_it == rep_range.end()) {
                        insert_rowids.push_back(rid);
                    } else if (rep_it->second != mhash) {
                        update_rowids.push_back(rid);
                    }
                }
                for (const auto& [rid, _] : rep_range) {
                    if (mas_range.find(rid) == mas_range.end()) {
                        delete_rowids.push_back(rid);
                    }
                }
            }

            // Build INSERT patchset for insert + update rowids.
            std::vector<std::int64_t> upsert_rowids;
            upsert_rowids.reserve(insert_rowids.size() + update_rowids.size());
            upsert_rowids.insert(upsert_rowids.end(),
                                 insert_rowids.begin(), insert_rowids.end());
            upsert_rowids.insert(upsert_rowids.end(),
                                 update_rowids.begin(), update_rowids.end());

            if (!upsert_rowids.empty()) {
                report(DiffPhase::BuildingPatchset, table,
                       static_cast<std::int64_t>(upsert_rowids.size()), 0);
                auto ps = detail::build_insert_patchset(db, table, upsert_rowids);
                if (!ps.empty()) {
                    patchsets.push_back(std::move(ps));
                }
            }

            if (!delete_rowids.empty()) {
                std::sort(delete_rowids.begin(), delete_rowids.end());
                deletes.push_back(TableDeletes{table, std::move(delete_rowids)});
            }

            ++tables_done;
        }

        // Combine all per-table patchsets.
        Changeset combined = detail::combine_patchsets(patchsets);

        hs_state = HSState::Live;
        pending_ranges.clear();
        SQLPIPE_LOG(config.on_log, LogLevel::Info, "diff computed, entering live at seq={}", seq);

        return {Message{DiffReadyMsg{seq, std::move(combined), std::move(deletes)}}};
    }
};

// ── Public API ──────────────────────────────────────────────────────

Master::Master(sqlite3* db, MasterConfig config)
    : impl_(std::make_unique<Impl>()) {
    impl_->db = db;
    impl_->config = config;
    impl_->init();
}

Master::~Master() {
    if (impl_ && impl_->config.on_flush) {
        sqlite3_commit_hook(impl_->db, nullptr, nullptr);
    }
}
Master::Master(Master&&) noexcept = default;
Master& Master::operator=(Master&&) noexcept = default;

void Master::exec(const std::string& sql) {
    detail::exec(impl_->db, sql.c_str());
    if (impl_->config.on_flush && impl_->flush_pending) {
        impl_->auto_flush();
    }
}

std::vector<Message> Master::flush() {
    // If DDL ran since last flush, the tracked table set may have changed.
    auto sv = detail::compute_schema_fingerprint(impl_->db, impl_->filter());
    if (sv != impl_->cached_sv) {
        impl_->cached_sv = sv;
        impl_->scan_tables();
        impl_->recreate_session();
    }

    auto cs = impl_->extract_changeset();
    if (cs.empty()) return {};

    impl_->recreate_session();

    impl_->seq++;
    detail::write_seq(impl_->db, impl_->seq, impl_->config.seq_key);

    SQLPIPE_LOG(impl_->config.on_log, LogLevel::Debug, "flushed changeset seq={} ({} bytes)", impl_->seq, cs.size());

    impl_->enqueue_changeset(impl_->seq, cs);

    return {Message{ChangesetMsg{impl_->seq, std::move(cs)}}};
}

std::vector<Message> Master::handle_message(const Message& msg) {
    return std::visit([&](const auto& m) -> std::vector<Message> {
        using T = std::decay_t<decltype(m)>;

        if constexpr (std::is_same_v<T, HelloMsg>) {
            return impl_->handle_hello(m);
        }
        else if constexpr (std::is_same_v<T, BucketHashesMsg>) {
            return impl_->handle_bucket_hashes(m);
        }
        else if constexpr (std::is_same_v<T, RowHashesMsg>) {
            return impl_->handle_row_hashes(m);
        }
        else if constexpr (std::is_same_v<T, AckMsg>) {
            SQLPIPE_LOG(impl_->config.on_log, LogLevel::Debug, "replica acked seq={}", m.seq);
            return {};
        }
        else {
            return {Message{ErrorMsg{ErrorCode::InvalidState,
                "unexpected message from replica"}}};
        }
    }, msg);
}

Seq Master::current_seq() const { return impl_->seq; }

SchemaVersion Master::schema_version() const {
    return detail::compute_schema_fingerprint(impl_->db, impl_->filter());
}

} // namespace sqlpipe

// ── relational_algebra.cpp ─────────────────────────────────────

#include <liteparser.h>

namespace sqlpipe::detail {

// ── Schema map ─────────────────────────────────────────────────

/// Column metadata for RA analysis.
struct ColumnInfo {
    std::string name;
    int         index;  // 0-based position in table
};

/// Per-table schema: column name → index.
using TableSchema = std::vector<ColumnInfo>;

/// Database schema: table name → columns.
using SchemaMap = std::unordered_map<std::string, TableSchema>;

/// Build a schema map from the database.
SchemaMap build_schema_map(sqlite3* db) {
    SchemaMap schema;
    auto stmt = prepare(db,
        "SELECT name FROM sqlite_master WHERE type='table' "
        "AND name NOT LIKE '_sqlpipe_%' AND name NOT LIKE 'sqlite_%'");
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        std::string table(reinterpret_cast<const char*>(
            sqlite3_column_text(stmt.get(), 0)));
        std::string pragma = "PRAGMA table_info('" + table + "')";
        auto col_stmt = prepare(db, pragma.c_str());
        TableSchema cols;
        while (sqlite3_step(col_stmt.get()) == SQLITE_ROW) {
            int idx = sqlite3_column_int(col_stmt.get(), 0);
            const char* name = reinterpret_cast<const char*>(
                sqlite3_column_text(col_stmt.get(), 1));
            cols.push_back({name ? name : "", idx});
        }
        schema[table] = std::move(cols);
    }
    return schema;
}

/// Look up a column's index in a table. Returns -1 if not found.
int column_index(const SchemaMap& schema, const std::string& table,
                 const std::string& column) {
    auto it = schema.find(table);
    if (it == schema.end()) return -1;
    for (const auto& ci : it->second) {
        if (ci.name == column) return ci.index;
    }
    return -1;
}

// ── Relational algebra nodes ───────────────────────────────────

struct RANode {
    enum Kind { Scan, Filter, Project, Join, Aggregate, SetOp };
    Kind kind;

    virtual ~RANode() = default;

    /// Collect all table names referenced by this subtree.
    virtual void collect_tables(std::set<std::string>& out) const = 0;
};

using RAPtr = std::unique_ptr<RANode>;

/// Comparison operator for predicate checks.
enum class CheckOp : std::uint8_t {
    Eq,         // column = value
    Ne,         // column != value
    Lt,         // column < value
    Le,         // column <= value
    Gt,         // column > value
    Ge,         // column >= value
    IsNull,     // column IS NULL
    IsNotNull,  // column IS NOT NULL
    InList,     // column IN (v1, v2, ...)
};

/// A resolved predicate: table.column <op> literal value(s).
struct ResolvedPredicate {
    std::string        table;
    std::string        column;
    int                column_index;  // position in table schema (-1 if unknown)
    CheckOp            op = CheckOp::Eq;
    Value              value;    // for Eq/Ne/Lt/Le/Gt/Ge
    std::vector<Value> values;   // for InList
    bool               negated = false;  // emit Not after the check
};

/// A resolved column reference: (table, column_index).
struct ColumnRef {
    std::string table;
    int         column_index;
    bool operator<(const ColumnRef& o) const {
        if (table != o.table) return table < o.table;
        return column_index < o.column_index;
    }
    bool operator==(const ColumnRef& o) const {
        return table == o.table && column_index == o.column_index;
    }
};

/// Set of column references read by an RA subtree.
using ColumnRefSet = std::set<ColumnRef>;

struct RAScan : RANode {
    std::string table;
    RAScan(std::string t) : table(std::move(t)) { kind = Scan; }
    void collect_tables(std::set<std::string>& out) const override {
        out.insert(table);
    }
};

struct RAFilter : RANode {
    RAPtr child;
    /// Equality predicates extractable from this filter.
    std::vector<ResolvedPredicate> predicates;
    /// True if the filter contains terms we couldn't analyze.
    /// When true, we can still use extracted predicates but must
    /// conservatively assume non-analyzed terms could match anything.
    bool has_opaque_terms = false;
    /// All column references in the filter expression (including
    /// columns in predicates and opaque terms).
    ColumnRefSet columns_read;

    RAFilter(RAPtr c) : child(std::move(c)) { kind = Filter; }
    void collect_tables(std::set<std::string>& out) const override {
        child->collect_tables(out);
    }
};

struct RAProject : RANode {
    RAPtr child;
    /// Column references in the SELECT list.
    ColumnRefSet columns_read;

    RAProject(RAPtr c) : child(std::move(c)) { kind = Project; }
    void collect_tables(std::set<std::string>& out) const override {
        child->collect_tables(out);
    }
};

/// A column equivalence from an equijoin ON clause:
/// left_table.left_column = right_table.right_column.
struct JoinEquality {
    std::string left_table;
    std::string left_column;
    int         left_index;    // column position (-1 if unknown)
    std::string right_table;
    std::string right_column;
    int         right_index;   // column position (-1 if unknown)
};

struct RAJoin : RANode {
    RAPtr left, right;
    /// Equijoin conditions extracted from the ON clause.
    std::vector<JoinEquality> equalities;
    /// All column references in ON expressions.
    ColumnRefSet columns_read;

    RAJoin(RAPtr l, RAPtr r) : left(std::move(l)), right(std::move(r)) {
        kind = Join;
    }
    void collect_tables(std::set<std::string>& out) const override {
        left->collect_tables(out);
        right->collect_tables(out);
    }
};

struct RAAggregate : RANode {
    RAPtr child;
    /// Column references in GROUP BY / aggregate expressions.
    ColumnRefSet columns_read;

    RAAggregate(RAPtr c) : child(std::move(c)) { kind = Aggregate; }
    void collect_tables(std::set<std::string>& out) const override {
        child->collect_tables(out);
    }
};

struct RASetOp : RANode {
    RAPtr left, right;
    RASetOp(RAPtr l, RAPtr r) : left(std::move(l)), right(std::move(r)) {
        kind = SetOp;
    }
    void collect_tables(std::set<std::string>& out) const override {
        left->collect_tables(out);
        right->collect_tables(out);
    }
};

// ── Alias resolution scope ─────────────────────────────────────

/// Maps alias → real table name within a FROM clause scope.
using AliasMap = std::unordered_map<std::string, std::string>;

/// Resolve a possibly-aliased table reference to the real table name.
std::string resolve_table(const AliasMap& aliases, const std::string& name) {
    auto it = aliases.find(name);
    return (it != aliases.end()) ? it->second : name;
}

/// Resolve an unqualified column name to a table. Returns empty string
/// if ambiguous or not found.
std::string resolve_unqualified_column(
        const SchemaMap& schema, const AliasMap& aliases,
        const std::string& column) {
    std::string found;
    // Check all tables in scope (values of alias map + any direct table refs).
    std::set<std::string> tables_in_scope;
    for (const auto& [alias, table] : aliases) {
        tables_in_scope.insert(table);
    }
    for (const auto& table : tables_in_scope) {
        auto it = schema.find(table);
        if (it == schema.end()) continue;
        for (const auto& ci : it->second) {
            if (ci.name == column) {
                if (!found.empty() && found != table) return {};  // ambiguous
                found = table;
            }
        }
    }
    return found;
}

// ── AST → RA transform ────────────────────────────────────────

/// Convert a liteparser expression literal to a sqlpipe::Value.
Value lp_literal_to_value(const LpNode* node) {
    switch (node->kind) {
        case LP_EXPR_LITERAL_INT:
            return static_cast<std::int64_t>(
                std::strtoll(node->u.literal.value, nullptr, 10));
        case LP_EXPR_LITERAL_FLOAT:
            return std::strtod(node->u.literal.value, nullptr);
        case LP_EXPR_LITERAL_STRING:
            return std::string(node->u.literal.value);
        case LP_EXPR_LITERAL_NULL:
            return std::monostate{};
        case LP_EXPR_LITERAL_BLOB: {
            // Blob literals: X'hex...'
            const char* hex = node->u.literal.value;
            std::vector<std::uint8_t> blob;
            size_t len = std::strlen(hex);
            blob.reserve(len / 2);
            for (size_t i = 0; i + 1 < len; i += 2) {
                char buf[3] = {hex[i], hex[i+1], 0};
                blob.push_back(
                    static_cast<std::uint8_t>(std::strtoul(buf, nullptr, 16)));
            }
            return blob;
        }
        case LP_EXPR_LITERAL_BOOL:
            return static_cast<std::int64_t>(
                node->u.literal.value[0] == '1' ||
                node->u.literal.value[0] == 't' ||
                node->u.literal.value[0] == 'T' ? 1 : 0);
        default:
            return std::monostate{};
    }
}

/// Check if a liteparser node is a literal value.
bool is_literal(const LpNode* node) {
    return node && (
        node->kind == LP_EXPR_LITERAL_INT ||
        node->kind == LP_EXPR_LITERAL_FLOAT ||
        node->kind == LP_EXPR_LITERAL_STRING ||
        node->kind == LP_EXPR_LITERAL_NULL ||
        node->kind == LP_EXPR_LITERAL_BLOB ||
        node->kind == LP_EXPR_LITERAL_BOOL);
}

/// Check if a liteparser node is a column reference.
bool is_column_ref(const LpNode* node) {
    return node && node->kind == LP_EXPR_COLUMN_REF;
}

/// Extract equality predicates from a WHERE expression.
/// Walks AND-connected terms looking for `column = literal` patterns.
/// Walk an AST expression and collect all column references.
void collect_expr_columns(const LpNode* expr, const SchemaMap& schema,
                          const AliasMap& aliases, ColumnRefSet& out) {
    if (!expr) return;
    switch (expr->kind) {
        case LP_EXPR_COLUMN_REF: {
            std::string table, col;
            col = expr->u.column_ref.column;
            if (expr->u.column_ref.table) {
                table = resolve_table(aliases,
                    std::string(expr->u.column_ref.table));
            } else {
                table = resolve_unqualified_column(schema, aliases, col);
            }
            if (!table.empty()) {
                int idx = column_index(schema, table, col);
                if (idx >= 0) out.insert({table, idx});
            }
            break;
        }
        case LP_EXPR_STAR: {
            // SELECT * or table.* — all columns of the referenced table(s).
            if (expr->u.star.table) {
                std::string table = resolve_table(aliases,
                    std::string(expr->u.star.table));
                auto it = schema.find(table);
                if (it != schema.end()) {
                    for (const auto& ci : it->second) {
                        out.insert({table, ci.index});
                    }
                }
            } else {
                // Bare * — all columns of all tables in scope.
                for (const auto& [alias, table] : aliases) {
                    auto it = schema.find(table);
                    if (it != schema.end()) {
                        for (const auto& ci : it->second) {
                            out.insert({table, ci.index});
                        }
                    }
                }
            }
            break;
        }
        case LP_EXPR_BINARY_OP:
            collect_expr_columns(expr->u.binary.left, schema, aliases, out);
            collect_expr_columns(expr->u.binary.right, schema, aliases, out);
            break;
        case LP_EXPR_UNARY_OP:
            collect_expr_columns(expr->u.unary.operand, schema, aliases, out);
            break;
        case LP_EXPR_FUNCTION:
            for (int i = 0; i < expr->u.function.args.count; ++i) {
                collect_expr_columns(
                    expr->u.function.args.items[i], schema, aliases, out);
            }
            break;
        case LP_EXPR_CAST:
            collect_expr_columns(expr->u.cast.expr, schema, aliases, out);
            break;
        case LP_EXPR_BETWEEN:
            collect_expr_columns(expr->u.between.expr, schema, aliases, out);
            collect_expr_columns(expr->u.between.low, schema, aliases, out);
            collect_expr_columns(expr->u.between.high, schema, aliases, out);
            break;
        case LP_EXPR_IN:
            collect_expr_columns(expr->u.in.expr, schema, aliases, out);
            for (int i = 0; i < expr->u.in.values.count; ++i) {
                collect_expr_columns(
                    expr->u.in.values.items[i], schema, aliases, out);
            }
            break;
        case LP_EXPR_CASE:
            collect_expr_columns(expr->u.case_.operand, schema, aliases, out);
            for (int i = 0; i < expr->u.case_.when_exprs.count; ++i) {
                collect_expr_columns(
                    expr->u.case_.when_exprs.items[i], schema, aliases, out);
            }
            collect_expr_columns(expr->u.case_.else_expr, schema, aliases, out);
            break;
        case LP_EXPR_COLLATE:
            collect_expr_columns(expr->u.collate.expr, schema, aliases, out);
            break;
        case LP_EXPR_SUBQUERY:
            // Subquery — conservatively don't descend. The subquery's
            // dependencies are handled when/if we analyze it separately.
            break;
        case LP_EXPR_EXISTS:
            break;
        default:
            break;
    }
}

/// Resolve a column reference to (table, column, column_index).
/// Returns false if resolution fails.
bool resolve_column(const LpNode* col_node, const SchemaMap& schema,
                    const AliasMap& aliases, std::string& table_out,
                    std::string& col_out, int& idx_out) {
    if (!is_column_ref(col_node)) return false;
    col_out = col_node->u.column_ref.column;
    if (col_node->u.column_ref.table) {
        table_out = resolve_table(aliases,
            std::string(col_node->u.column_ref.table));
    } else {
        table_out = resolve_unqualified_column(schema, aliases, col_out);
    }
    if (table_out.empty()) return false;
    idx_out = column_index(schema, table_out, col_out);
    return true;
}

/// Map liteparser binary op to CheckOp. Returns nullopt for non-comparison ops.
std::optional<CheckOp> binop_to_checkop(LpBinOp op) {
    switch (op) {
        case LP_OP_EQ:  return CheckOp::Eq;
        case LP_OP_NE:  return CheckOp::Ne;
        case LP_OP_LT:  return CheckOp::Lt;
        case LP_OP_LE:  return CheckOp::Le;
        case LP_OP_GT:  return CheckOp::Gt;
        case LP_OP_GE:  return CheckOp::Ge;
        case LP_OP_IS:  return CheckOp::Eq;  // IS is like = for non-NULL
        case LP_OP_ISNOT: return CheckOp::Ne;
        default:        return std::nullopt;
    }
}

/// Flip a comparison op (for normalizing literal on left).
CheckOp flip_checkop(CheckOp op) {
    switch (op) {
        case CheckOp::Lt: return CheckOp::Gt;
        case CheckOp::Le: return CheckOp::Ge;
        case CheckOp::Gt: return CheckOp::Lt;
        case CheckOp::Ge: return CheckOp::Le;
        default: return op;  // Eq, Ne are symmetric
    }
}

void extract_predicates(
        const LpNode* expr,
        const SchemaMap& schema,
        const AliasMap& aliases,
        std::vector<ResolvedPredicate>& out,
        bool& has_opaque) {
    if (!expr) return;

    // AND → recurse into branches.
    if (expr->kind == LP_EXPR_BINARY_OP && expr->u.binary.op == LP_OP_AND) {
        extract_predicates(
            expr->u.binary.left, schema, aliases, out, has_opaque);
        extract_predicates(
            expr->u.binary.right, schema, aliases, out, has_opaque);
        return;
    }

    // OR → try to merge equalities on the same column into InList.
    // e.g., x = 1 OR x = 2 OR x = 3 → InList(x, {1, 2, 3}).
    // Nested ORs are flattened: OR(OR(a=1, a=2), a=3) → {1, 2, 3}.
    if (expr->kind == LP_EXPR_BINARY_OP && expr->u.binary.op == LP_OP_OR) {
        // Collect all equality leaves from the OR tree.
        struct EqLeaf { std::string table; std::string col; int idx; Value val; };
        std::vector<EqLeaf> leaves;
        bool all_eq = true;

        std::function<void(const LpNode*)> collect_or = [&](const LpNode* n) {
            if (!n) { all_eq = false; return; }
            if (n->kind == LP_EXPR_BINARY_OP && n->u.binary.op == LP_OP_OR) {
                collect_or(n->u.binary.left);
                collect_or(n->u.binary.right);
                return;
            }
            // Must be column = literal.
            if (n->kind == LP_EXPR_BINARY_OP &&
                (n->u.binary.op == LP_OP_EQ || n->u.binary.op == LP_OP_IS)) {
                const LpNode* lhs = n->u.binary.left;
                const LpNode* rhs = n->u.binary.right;
                if (is_literal(lhs) && is_column_ref(rhs)) std::swap(lhs, rhs);
                if (is_column_ref(lhs) && is_literal(rhs) &&
                    rhs->kind != LP_EXPR_LITERAL_NULL) {
                    std::string table, col;
                    int idx;
                    if (resolve_column(lhs, schema, aliases, table, col, idx)) {
                        leaves.push_back({table, col, idx,
                                          lp_literal_to_value(rhs)});
                        return;
                    }
                }
            }
            all_eq = false;
        };
        collect_or(expr);

        if (all_eq && !leaves.empty()) {
            // Check all leaves reference the same (table, column).
            bool same_col = true;
            for (size_t i = 1; i < leaves.size(); ++i) {
                if (leaves[i].table != leaves[0].table ||
                    leaves[i].col != leaves[0].col) {
                    same_col = false;
                    break;
                }
            }
            if (same_col) {
                std::vector<Value> vals;
                vals.reserve(leaves.size());
                for (auto& l : leaves) vals.push_back(std::move(l.val));
                out.push_back({leaves[0].table, leaves[0].col, leaves[0].idx,
                               CheckOp::InList, {}, std::move(vals)});
                return;
            }
        }
        // OR branches we can't merge → opaque.
        has_opaque = true;
        return;
    }

    // Comparison operators: =, !=, <, <=, >, >=, IS, IS NOT.
    if (expr->kind == LP_EXPR_BINARY_OP) {
        auto check_op = binop_to_checkop(expr->u.binary.op);
        if (check_op) {
            const LpNode* lhs = expr->u.binary.left;
            const LpNode* rhs = expr->u.binary.right;

            // IS NULL / IS NOT NULL: must check before general comparison
            // because is_literal() matches LP_EXPR_LITERAL_NULL, and
            // we need IsNull/IsNotNull opcodes (not Eq/Ne which return
            // NULL under three-valued logic).
            if (expr->u.binary.op == LP_OP_IS ||
                expr->u.binary.op == LP_OP_ISNOT) {
                // Normalize: column on left.
                if (rhs && rhs->kind == LP_EXPR_LITERAL_NULL &&
                    is_column_ref(lhs)) {
                    std::string table, col;
                    int idx;
                    if (resolve_column(lhs, schema, aliases, table, col, idx)) {
                        auto op = (expr->u.binary.op == LP_OP_IS)
                            ? CheckOp::IsNull : CheckOp::IsNotNull;
                        out.push_back({table, col, idx, op, {}, {}});
                        return;
                    }
                }
                if (lhs && lhs->kind == LP_EXPR_LITERAL_NULL &&
                    is_column_ref(rhs)) {
                    std::string table, col;
                    int idx;
                    if (resolve_column(rhs, schema, aliases, table, col, idx)) {
                        auto op = (expr->u.binary.op == LP_OP_IS)
                            ? CheckOp::IsNull : CheckOp::IsNotNull;
                        out.push_back({table, col, idx, op, {}, {}});
                        return;
                    }
                }
            }

            // General comparison: column <op> literal.
            // Normalize: column on left, literal on right.
            bool flipped = false;
            if (is_literal(lhs) && is_column_ref(rhs)) {
                std::swap(lhs, rhs);
                flipped = true;
            }

            if (is_column_ref(lhs) && is_literal(rhs) &&
                rhs->kind != LP_EXPR_LITERAL_NULL) {
                // Skip NULL literals here — they're handled above as IS/IS NOT.
                std::string table, col;
                int idx;
                if (resolve_column(lhs, schema, aliases, table, col, idx)) {
                    auto op = flipped ? flip_checkop(*check_op) : *check_op;
                    out.push_back({table, col, idx, op,
                                   lp_literal_to_value(rhs), {}});
                    return;
                }
            }
        }
    }

    // IN / NOT IN list: column [NOT] IN (val1, val2, ...).
    if (expr->kind == LP_EXPR_IN) {
        const LpNode* col_expr = expr->u.in.expr;
        // Only handle literal value lists (not subqueries).
        if (is_column_ref(col_expr) && !expr->u.in.select &&
            expr->u.in.values.count > 0) {
            std::string table, col;
            int idx;
            if (resolve_column(col_expr, schema, aliases, table, col, idx)) {
                // Check all values are literals.
                std::vector<Value> vals;
                bool all_literal = true;
                for (int i = 0; i < expr->u.in.values.count; ++i) {
                    if (is_literal(expr->u.in.values.items[i])) {
                        vals.push_back(
                            lp_literal_to_value(expr->u.in.values.items[i]));
                    } else {
                        all_literal = false;
                        break;
                    }
                }
                if (all_literal) {
                    out.push_back({table, col, idx, CheckOp::InList,
                                   {}, std::move(vals), expr->u.in.is_not != 0});
                    return;
                }
            }
        }
    }

    // BETWEEN: column BETWEEN low AND high → column >= low AND column <= high.
    // NOT BETWEEN: treated as opaque (requires OR composition in the program).
    if (expr->kind == LP_EXPR_BETWEEN && !expr->u.between.is_not) {
        const LpNode* col_expr = expr->u.between.expr;
        if (is_column_ref(col_expr) &&
            is_literal(expr->u.between.low) &&
            is_literal(expr->u.between.high)) {
            std::string table, col;
            int idx;
            if (resolve_column(col_expr, schema, aliases, table, col, idx)) {
                out.push_back({table, col, idx, CheckOp::Ge,
                               lp_literal_to_value(expr->u.between.low), {}});
                out.push_back({table, col, idx, CheckOp::Le,
                               lp_literal_to_value(expr->u.between.high), {}});
                return;
            }
        }
    }

    // ISNULL / NOTNULL unary expressions.
    // These appear as expr kind LP_EXPR_UNARY_OP with various forms.
    // liteparser may represent `x IS NULL` as a binary IS op (handled above).
    // For explicit `x ISNULL` / `x NOTNULL`, check unary forms if needed.

    // Any term we couldn't extract is opaque.
    has_opaque = true;
}

/// Extract column=column equalities from a JOIN ON expression.
void extract_join_equalities(
        const LpNode* expr,
        const SchemaMap& schema,
        const AliasMap& aliases,
        std::vector<JoinEquality>& out) {
    if (!expr) return;

    if (expr->kind == LP_EXPR_BINARY_OP && expr->u.binary.op == LP_OP_AND) {
        extract_join_equalities(
            expr->u.binary.left, schema, aliases, out);
        extract_join_equalities(
            expr->u.binary.right, schema, aliases, out);
        return;
    }

    if (expr->kind == LP_EXPR_BINARY_OP && expr->u.binary.op == LP_OP_EQ) {
        const LpNode* lhs = expr->u.binary.left;
        const LpNode* rhs = expr->u.binary.right;

        // Both sides must be column references for an equijoin.
        if (is_column_ref(lhs) && is_column_ref(rhs)) {
            std::string lt, lc, rt, rc;
            lc = lhs->u.column_ref.column;
            rc = rhs->u.column_ref.column;

            if (lhs->u.column_ref.table) {
                lt = resolve_table(aliases,
                    std::string(lhs->u.column_ref.table));
            } else {
                lt = resolve_unqualified_column(schema, aliases, lc);
            }
            if (rhs->u.column_ref.table) {
                rt = resolve_table(aliases,
                    std::string(rhs->u.column_ref.table));
            } else {
                rt = resolve_unqualified_column(schema, aliases, rc);
            }

            if (!lt.empty() && !rt.empty()) {
                int li = column_index(schema, lt, lc);
                int ri = column_index(schema, rt, rc);
                out.push_back({lt, lc, li, rt, rc, ri});
            }
        }
    }
}

/// Build equijoins from USING clause columns.
void extract_using_equalities(
        const LpNodeList& using_cols,
        const LpNode* left_from,
        const LpNode* right_from,
        const SchemaMap& schema,
        const AliasMap& aliases,
        std::vector<JoinEquality>& out) {
    // Resolve table names from the immediate FROM items.
    auto resolve_from = [&](const LpNode* from) -> std::string {
        if (from && from->kind == LP_FROM_TABLE) {
            std::string name = from->u.from_table.name;
            if (from->u.from_table.alias) {
                return resolve_table(aliases,
                    std::string(from->u.from_table.alias));
            }
            return name;
        }
        return {};
    };

    // For USING, we need the table names from both sides.
    // For nested joins, the "table" is the result of the join —
    // we'd need to search deeper. For now, handle the simple case.
    std::string lt = resolve_from(left_from);
    std::string rt = resolve_from(right_from);
    if (lt.empty() || rt.empty()) return;

    for (int i = 0; i < using_cols.count; ++i) {
        const LpNode* col_node = using_cols.items[i];
        if (!col_node) continue;
        // USING columns are column references or identifiers.
        std::string col;
        if (col_node->kind == LP_EXPR_COLUMN_REF) {
            col = col_node->u.column_ref.column;
        } else if (col_node->kind == LP_EXPR_LITERAL_STRING) {
            col = col_node->u.literal.value;
        }
        if (col.empty()) continue;

        int li = column_index(schema, lt, col);
        int ri = column_index(schema, rt, col);
        if (li >= 0 && ri >= 0) {
            out.push_back({lt, col, li, rt, col, ri});
        }
    }
}

/// Build equijoins from NATURAL join by finding matching column names.
void extract_natural_equalities(
        const LpNode* left_from,
        const LpNode* right_from,
        const SchemaMap& schema,
        const AliasMap& aliases,
        std::vector<JoinEquality>& out) {
    auto resolve_from = [&](const LpNode* from) -> std::string {
        if (from && from->kind == LP_FROM_TABLE) {
            if (from->u.from_table.alias) {
                return resolve_table(aliases,
                    std::string(from->u.from_table.alias));
            }
            return std::string(from->u.from_table.name);
        }
        return {};
    };

    std::string lt = resolve_from(left_from);
    std::string rt = resolve_from(right_from);
    if (lt.empty() || rt.empty()) return;

    auto lit = schema.find(lt);
    auto rit = schema.find(rt);
    if (lit == schema.end() || rit == schema.end()) return;

    // Find columns present in both tables.
    for (const auto& lci : lit->second) {
        for (const auto& rci : rit->second) {
            if (lci.name == rci.name) {
                out.push_back({lt, lci.name, lci.index,
                               rt, rci.name, rci.index});
            }
        }
    }
}

/// Build the RA tree for a FROM clause (table refs and joins).
RAPtr build_from(const LpNode* from, const SchemaMap& schema,
                 AliasMap& aliases) {
    if (!from) return nullptr;

    if (from->kind == LP_FROM_TABLE) {
        std::string table = from->u.from_table.name;
        std::string alias = from->u.from_table.alias
            ? from->u.from_table.alias : table;
        aliases[alias] = table;
        return std::make_unique<RAScan>(table);
    }

    if (from->kind == LP_FROM_SUBQUERY) {
        // Subqueries in FROM: conservatively collect tables from the
        // inner select. We don't push predicates into subqueries.
        // For now, treat as opaque — the outer query depends on
        // all tables the subquery references.
        // TODO: recurse into subquery for deeper analysis.
        return nullptr;
    }

    if (from->kind == LP_JOIN_CLAUSE) {
        auto left = build_from(from->u.join.left, schema, aliases);
        auto right = build_from(from->u.join.right, schema, aliases);
        if (left && right) {
            auto join = std::make_unique<RAJoin>(
                std::move(left), std::move(right));

            // Extract equijoin conditions and column refs from ON clause.
            if (from->u.join.on_expr) {
                extract_join_equalities(
                    from->u.join.on_expr, schema, aliases,
                    join->equalities);
                collect_expr_columns(
                    from->u.join.on_expr, schema, aliases,
                    join->columns_read);
            }

            // USING clause → explicit equijoins.
            if (from->u.join.using_columns.count > 0) {
                extract_using_equalities(
                    from->u.join.using_columns,
                    from->u.join.left, from->u.join.right,
                    schema, aliases, join->equalities);
            }

            // NATURAL join → equijoins on all matching column names.
            if (from->u.join.join_type & LP_JOIN_NATURAL) {
                extract_natural_equalities(
                    from->u.join.left, from->u.join.right,
                    schema, aliases, join->equalities);
            }

            return join;
        }
        return left ? std::move(left) : std::move(right);
    }

    return nullptr;
}

/// Extract implicit equijoin conditions from a WHERE expression.
/// Finds column=column predicates where the two columns belong to
/// different tables (comma-join style). These are added to the
/// nearest enclosing Join node.
void extract_implicit_equijoins(
        const LpNode* expr,
        const SchemaMap& schema,
        const AliasMap& aliases,
        std::vector<JoinEquality>& equijoins) {
    if (!expr) return;

    if (expr->kind == LP_EXPR_BINARY_OP && expr->u.binary.op == LP_OP_AND) {
        extract_implicit_equijoins(
            expr->u.binary.left, schema, aliases, equijoins);
        extract_implicit_equijoins(
            expr->u.binary.right, schema, aliases, equijoins);
        return;
    }

    if (expr->kind == LP_EXPR_BINARY_OP && expr->u.binary.op == LP_OP_EQ) {
        const LpNode* lhs = expr->u.binary.left;
        const LpNode* rhs = expr->u.binary.right;
        if (is_column_ref(lhs) && is_column_ref(rhs)) {
            std::string lt, lc, rt, rc;
            lc = lhs->u.column_ref.column;
            rc = rhs->u.column_ref.column;

            if (lhs->u.column_ref.table) {
                lt = resolve_table(aliases,
                    std::string(lhs->u.column_ref.table));
            } else {
                lt = resolve_unqualified_column(schema, aliases, lc);
            }
            if (rhs->u.column_ref.table) {
                rt = resolve_table(aliases,
                    std::string(rhs->u.column_ref.table));
            } else {
                rt = resolve_unqualified_column(schema, aliases, rc);
            }

            // Only capture cross-table equalities (implicit joins).
            if (!lt.empty() && !rt.empty() && lt != rt) {
                int li = column_index(schema, lt, lc);
                int ri = column_index(schema, rt, rc);
                equijoins.push_back({lt, lc, li, rt, rc, ri});
            }
        }
    }
}

// ── RA optimization passes ─────────────────────────────────────

/// Collect the set of tables reachable from an RA subtree.
std::set<std::string> tables_of(const RANode* node) {
    std::set<std::string> t;
    if (node) node->collect_tables(t);
    return t;
}

/// Check if a predicate's table is reachable from an RA subtree.
bool predicate_applies_to(const ResolvedPredicate& pred, const RANode* node) {
    auto t = tables_of(node);
    return t.count(pred.table) > 0;
}

/// Push Filter predicates down through the RA tree toward Scan nodes.
/// Returns the optimized tree. Modifies the tree in place where possible.
RAPtr push_filters_down(RAPtr node) {
    if (!node) return nullptr;

    switch (node->kind) {
        case RANode::Filter: {
            auto* f = static_cast<RAFilter*>(node.get());
            // First, recursively optimize the child.
            f->child = push_filters_down(std::move(f->child));

            // If child is a Join, try to push predicates into the
            // join's left or right subtree.
            if (f->child && f->child->kind == RANode::Join) {
                auto* j = static_cast<RAJoin*>(f->child.get());
                std::vector<ResolvedPredicate> remaining;

                for (auto& pred : f->predicates) {
                    bool pushed = false;
                    // Can push to left if predicate's table is in left subtree.
                    if (predicate_applies_to(pred, j->left.get()) &&
                        !predicate_applies_to(pred, j->right.get())) {
                        // Wrap left in a Filter with this predicate.
                        auto lf = std::make_unique<RAFilter>(std::move(j->left));
                        lf->predicates.push_back(std::move(pred));
                        j->left = push_filters_down(std::move(lf));
                        pushed = true;
                    }
                    // Can push to right if predicate's table is in right subtree.
                    else if (predicate_applies_to(pred, j->right.get()) &&
                             !predicate_applies_to(pred, j->left.get())) {
                        auto rf = std::make_unique<RAFilter>(std::move(j->right));
                        rf->predicates.push_back(std::move(pred));
                        j->right = push_filters_down(std::move(rf));
                        pushed = true;
                    }

                    if (!pushed) {
                        remaining.push_back(std::move(pred));
                    }
                }

                f->predicates = std::move(remaining);

                // If all predicates were pushed down, elide the empty Filter.
                if (f->predicates.empty() && !f->has_opaque_terms) {
                    return std::move(f->child);
                }
            }

            // If child is a Project, push through it (project doesn't filter).
            if (f->child && f->child->kind == RANode::Project) {
                auto* p = static_cast<RAProject*>(f->child.get());
                // Move filter below project: Filter(Project(x)) → Project(Filter(x))
                auto inner = std::move(p->child);
                auto new_filter = std::make_unique<RAFilter>(std::move(inner));
                new_filter->predicates = std::move(f->predicates);
                new_filter->has_opaque_terms = f->has_opaque_terms;
                p->child = push_filters_down(std::move(new_filter));
                return std::move(f->child);
            }

            return std::move(node);
        }

        case RANode::Join: {
            auto* j = static_cast<RAJoin*>(node.get());
            j->left = push_filters_down(std::move(j->left));
            j->right = push_filters_down(std::move(j->right));
            return std::move(node);
        }

        case RANode::Project: {
            auto* p = static_cast<RAProject*>(node.get());
            p->child = push_filters_down(std::move(p->child));
            return std::move(node);
        }

        case RANode::Aggregate: {
            auto* a = static_cast<RAAggregate*>(node.get());
            a->child = push_filters_down(std::move(a->child));
            return std::move(node);
        }

        case RANode::SetOp: {
            auto* s = static_cast<RASetOp*>(node.get());
            s->left = push_filters_down(std::move(s->left));
            s->right = push_filters_down(std::move(s->right));
            return std::move(node);
        }

        default:
            return std::move(node);
    }
}

/// Create per-predicate Filter nodes from a Filter with multiple predicates.
/// Filter({a.x=1, b.y=2}, child) → Filter(a.x=1, Filter(b.y=2, child))
RAPtr split_filters(RAPtr node) {
    if (!node) return nullptr;

    switch (node->kind) {
        case RANode::Filter: {
            auto* f = static_cast<RAFilter*>(node.get());
            f->child = split_filters(std::move(f->child));

            if (f->predicates.size() <= 1) return std::move(node);

            // Build a chain: innermost first.
            RAPtr result = std::move(f->child);
            for (auto& pred : f->predicates) {
                auto new_f = std::make_unique<RAFilter>(std::move(result));
                new_f->predicates.push_back(std::move(pred));
                result = std::move(new_f);
            }
            // If the original had opaque terms, add an opaque filter at top.
            if (f->has_opaque_terms) {
                auto opaque = std::make_unique<RAFilter>(std::move(result));
                opaque->has_opaque_terms = true;
                result = std::move(opaque);
            }
            return result;
        }

        case RANode::Join: {
            auto* j = static_cast<RAJoin*>(node.get());
            j->left = split_filters(std::move(j->left));
            j->right = split_filters(std::move(j->right));
            return std::move(node);
        }

        case RANode::Project: {
            auto* p = static_cast<RAProject*>(node.get());
            p->child = split_filters(std::move(p->child));
            return std::move(node);
        }

        case RANode::Aggregate: {
            auto* a = static_cast<RAAggregate*>(node.get());
            a->child = split_filters(std::move(a->child));
            return std::move(node);
        }

        case RANode::SetOp: {
            auto* s = static_cast<RASetOp*>(node.get());
            s->left = split_filters(std::move(s->left));
            s->right = split_filters(std::move(s->right));
            return std::move(node);
        }

        default:
            return std::move(node);
    }
}

/// Add propagated predicates as new Filter nodes above relevant Scans.
/// For each (table, predicate) derived from equijoin propagation,
/// wraps the matching Scan in a Filter if one doesn't already exist.
RAPtr inject_propagated_predicates(
        RAPtr node,
        const std::vector<ResolvedPredicate>& propagated) {
    if (!node || propagated.empty()) return std::move(node);

    switch (node->kind) {
        case RANode::Scan: {
            auto* s = static_cast<RAScan*>(node.get());
            // Collect predicates for this table.
            std::vector<ResolvedPredicate> mine;
            for (const auto& p : propagated) {
                if (p.table == s->table) mine.push_back(p);
            }
            if (mine.empty()) return std::move(node);
            auto f = std::make_unique<RAFilter>(std::move(node));
            f->predicates = std::move(mine);
            return f;
        }

        case RANode::Filter: {
            auto* f = static_cast<RAFilter*>(node.get());
            f->child = inject_propagated_predicates(
                std::move(f->child), propagated);
            return std::move(node);
        }

        case RANode::Join: {
            auto* j = static_cast<RAJoin*>(node.get());
            j->left = inject_propagated_predicates(
                std::move(j->left), propagated);
            j->right = inject_propagated_predicates(
                std::move(j->right), propagated);
            return std::move(node);
        }

        case RANode::Project: {
            auto* p = static_cast<RAProject*>(node.get());
            p->child = inject_propagated_predicates(
                std::move(p->child), propagated);
            return std::move(node);
        }

        case RANode::Aggregate: {
            auto* a = static_cast<RAAggregate*>(node.get());
            a->child = inject_propagated_predicates(
                std::move(a->child), propagated);
            return std::move(node);
        }

        case RANode::SetOp: {
            auto* s = static_cast<RASetOp*>(node.get());
            s->left = inject_propagated_predicates(
                std::move(s->left), propagated);
            s->right = inject_propagated_predicates(
                std::move(s->right), propagated);
            return std::move(node);
        }

        default:
            return std::move(node);
    }
}

// RA-RA transforms for optimization.
RAPtr optimize_ra(RAPtr ra);

/// Transform a SELECT AST into an RA tree.
RAPtr select_to_ra(const LpNode* select, const SchemaMap& schema,
                   AliasMap& aliases) {
    if (!select || select->kind != LP_STMT_SELECT) return nullptr;

    // Build FROM (scans + joins), extracting equijoin conditions.
    RAPtr ra = build_from(select->u.select.from, schema, aliases);
    if (!ra) {
        // No FROM clause — e.g. SELECT 1. No table dependencies.
        return nullptr;
    }

    // WHERE → Filter with predicate extraction + implicit join detection.
    if (select->u.select.where) {
        auto filter = std::make_unique<RAFilter>(std::move(ra));
        extract_predicates(
            select->u.select.where, schema, aliases,
            filter->predicates, filter->has_opaque_terms);
        // Collect all column references in WHERE (including opaque terms).
        collect_expr_columns(
            select->u.select.where, schema, aliases, filter->columns_read);

        // Extract implicit equijoin conditions (column=column across tables)
        // from WHERE and add to the nearest Join node.
        if (filter->child && filter->child->kind == RANode::Join) {
            auto* j = static_cast<RAJoin*>(filter->child.get());
            extract_implicit_equijoins(
                select->u.select.where, schema, aliases,
                j->equalities);
        }

        ra = std::move(filter);
    }

    // GROUP BY → Aggregate with column tracking.
    if (select->u.select.group_by.count > 0) {
        auto agg = std::make_unique<RAAggregate>(std::move(ra));
        for (int i = 0; i < select->u.select.group_by.count; ++i) {
            collect_expr_columns(
                select->u.select.group_by.items[i], schema, aliases,
                agg->columns_read);
        }
        ra = std::move(agg);
    }

    // HAVING → another Filter (on aggregated results).
    if (select->u.select.having) {
        auto filter = std::make_unique<RAFilter>(std::move(ra));
        filter->has_opaque_terms = true;  // HAVING predicates are post-aggregate
        collect_expr_columns(
            select->u.select.having, schema, aliases, filter->columns_read);
        ra = std::move(filter);
    }

    // SELECT list → Project with column tracking.
    {
        auto proj = std::make_unique<RAProject>(std::move(ra));
        for (int i = 0; i < select->u.select.result_columns.count; ++i) {
            auto* rc = select->u.select.result_columns.items[i];
            if (rc && rc->kind == LP_RESULT_COLUMN) {
                collect_expr_columns(
                    rc->u.result_column.expr, schema, aliases,
                    proj->columns_read);
            }
        }
        // ORDER BY columns are also relevant — changing an ORDER BY column
        // can reorder results, which changes the query output.
        for (int i = 0; i < select->u.select.order_by.count; ++i) {
            auto* ot = select->u.select.order_by.items[i];
            if (ot && ot->kind == LP_ORDER_TERM) {
                collect_expr_columns(
                    ot->u.order_term.expr, schema, aliases,
                    proj->columns_read);
            }
        }
        ra = std::move(proj);
    }

    return ra;
}

/// Transform a compound SELECT (UNION/INTERSECT/EXCEPT) into an RA tree.
RAPtr compound_to_ra(const LpNode* node, const SchemaMap& schema) {
    if (node->kind == LP_STMT_SELECT) {
        AliasMap aliases;
        return select_to_ra(node, schema, aliases);
    }
    if (node->kind == LP_COMPOUND_SELECT) {
        auto left = compound_to_ra(node->u.compound.left, schema);
        auto right = compound_to_ra(node->u.compound.right, schema);
        if (left && right) {
            return std::make_unique<RASetOp>(std::move(left), std::move(right));
        }
        return left ? std::move(left) : std::move(right);
    }
    return nullptr;
}

/// Top-level: parse SQL, produce an RA tree, and optimize it.
/// Returns nullptr if the SQL can't be analyzed (not a SELECT, parse error).
RAPtr sql_to_ra(const std::string& sql, const SchemaMap& schema) {
    arena_t* arena = arena_create(4096);
    if (!arena) return nullptr;
    const char* err = nullptr;
    LpNode* ast = lp_parse(sql.c_str(), arena, &err);
    if (!ast) {
        arena_destroy(arena);
        return nullptr;
    }

    RAPtr ra;
    if (ast->kind == LP_STMT_SELECT) {
        AliasMap aliases;
        ra = select_to_ra(ast, schema, aliases);
    } else if (ast->kind == LP_COMPOUND_SELECT) {
        ra = compound_to_ra(ast, schema);
    }

    arena_destroy(arena);

    // Optimize: propagate predicates through equijoins, split, push to leaves.
    ra = optimize_ra(std::move(ra));

    return ra;
}

/// Collect all equality predicates from an RA tree (from all Filter nodes).
/// Collect all column references from the RA tree.
void collect_all_columns(const RANode* node, ColumnRefSet& out) {
    if (!node) return;
    switch (node->kind) {
        case RANode::Scan:
            break;  // Scan itself doesn't read columns; parent nodes do.
        case RANode::Filter: {
            auto* f = static_cast<const RAFilter*>(node);
            out.insert(f->columns_read.begin(), f->columns_read.end());
            // Also include predicate columns.
            for (const auto& pred : f->predicates) {
                if (pred.column_index >= 0)
                    out.insert({pred.table, pred.column_index});
            }
            collect_all_columns(f->child.get(), out);
            break;
        }
        case RANode::Project: {
            auto* p = static_cast<const RAProject*>(node);
            out.insert(p->columns_read.begin(), p->columns_read.end());
            collect_all_columns(p->child.get(), out);
            break;
        }
        case RANode::Join: {
            auto* j = static_cast<const RAJoin*>(node);
            out.insert(j->columns_read.begin(), j->columns_read.end());
            for (const auto& eq : j->equalities) {
                if (eq.left_index >= 0) out.insert({eq.left_table, eq.left_index});
                if (eq.right_index >= 0) out.insert({eq.right_table, eq.right_index});
            }
            collect_all_columns(j->left.get(), out);
            collect_all_columns(j->right.get(), out);
            break;
        }
        case RANode::Aggregate: {
            auto* a = static_cast<const RAAggregate*>(node);
            out.insert(a->columns_read.begin(), a->columns_read.end());
            collect_all_columns(a->child.get(), out);
            break;
        }
        case RANode::SetOp: {
            auto* s = static_cast<const RASetOp*>(node);
            collect_all_columns(s->left.get(), out);
            collect_all_columns(s->right.get(), out);
            break;
        }
        default:
            break;
    }
}

/// Get the set of column indices referenced by a query for a specific table.
std::set<int> columns_for_table(const RANode* ra, const std::string& table) {
    ColumnRefSet all;
    collect_all_columns(ra, all);
    std::set<int> result;
    for (const auto& cr : all) {
        if (cr.table == table) result.insert(cr.column_index);
    }
    return result;
}

void collect_predicates(const RANode* node,
                        std::vector<ResolvedPredicate>& out) {
    if (!node) return;
    switch (node->kind) {
        case RANode::Filter: {
            auto* f = static_cast<const RAFilter*>(node);
            out.insert(out.end(), f->predicates.begin(), f->predicates.end());
            collect_predicates(f->child.get(), out);
            break;
        }
        case RANode::Project:
            collect_predicates(
                static_cast<const RAProject*>(node)->child.get(), out);
            break;
        case RANode::Aggregate:
            collect_predicates(
                static_cast<const RAAggregate*>(node)->child.get(), out);
            break;
        case RANode::Join: {
            auto* j = static_cast<const RAJoin*>(node);
            collect_predicates(j->left.get(), out);
            collect_predicates(j->right.get(), out);
            break;
        }
        case RANode::SetOp: {
            auto* s = static_cast<const RASetOp*>(node);
            collect_predicates(s->left.get(), out);
            collect_predicates(s->right.get(), out);
            break;
        }
        default:
            break;
    }
}

/// Collect all equijoin conditions from an RA tree.
void collect_equijoins(const RANode* node,
                       std::vector<JoinEquality>& out) {
    if (!node) return;
    switch (node->kind) {
        case RANode::Join: {
            auto* j = static_cast<const RAJoin*>(node);
            out.insert(out.end(), j->equalities.begin(), j->equalities.end());
            collect_equijoins(j->left.get(), out);
            collect_equijoins(j->right.get(), out);
            break;
        }
        case RANode::Filter:
            collect_equijoins(
                static_cast<const RAFilter*>(node)->child.get(), out);
            break;
        case RANode::Project:
            collect_equijoins(
                static_cast<const RAProject*>(node)->child.get(), out);
            break;
        case RANode::Aggregate:
            collect_equijoins(
                static_cast<const RAAggregate*>(node)->child.get(), out);
            break;
        case RANode::SetOp: {
            auto* s = static_cast<const RASetOp*>(node);
            collect_equijoins(s->left.get(), out);
            collect_equijoins(s->right.get(), out);
            break;
        }
        default:
            break;
    }
}

/// Propagate predicates through equijoin conditions.
/// For each predicate {table.column = value} and equijoin
/// {A.col1 = B.col2}, if table.column matches one side, derive
/// a predicate for the other side.
/// Repeats until no new predicates are derived (transitive closure).
/// Check if two predicates are structurally identical.
bool predicates_match(const ResolvedPredicate& a, const ResolvedPredicate& b) {
    return a.table == b.table && a.column == b.column &&
           a.op == b.op && a.value == b.value && a.values == b.values &&
           a.negated == b.negated;
}

void propagate_predicates(
        std::vector<ResolvedPredicate>& predicates,
        const std::vector<JoinEquality>& equijoins) {
    if (equijoins.empty()) return;

    bool changed = true;
    while (changed) {
        changed = false;
        for (const auto& eq : equijoins) {
            for (size_t i = 0, n = predicates.size(); i < n; ++i) {
                const auto& pred = predicates[i];

                // Check if predicate matches the left side of the equijoin.
                if (pred.table == eq.left_table &&
                    pred.column == eq.left_column) {
                    ResolvedPredicate derived{
                        eq.right_table, eq.right_column,
                        eq.right_index, pred.op, pred.value, pred.values};
                    bool exists = false;
                    for (const auto& p : predicates) {
                        if (predicates_match(p, derived)) {
                            exists = true; break;
                        }
                    }
                    if (!exists) {
                        predicates.push_back(std::move(derived));
                        changed = true;
                    }
                }

                // Check the right side.
                if (pred.table == eq.right_table &&
                    pred.column == eq.right_column) {
                    ResolvedPredicate derived{
                        eq.left_table, eq.left_column,
                        eq.left_index, pred.op, pred.value, pred.values};
                    bool exists = false;
                    for (const auto& p : predicates) {
                        if (predicates_match(p, derived)) {
                            exists = true; break;
                        }
                    }
                    if (!exists) {
                        predicates.push_back(std::move(derived));
                        changed = true;
                    }
                }
            }
        }
    }
}

/// Run all optimization passes on an RA tree:
/// 1. Propagate predicates through equijoins
/// 2. Inject propagated predicates at leaf Scans
/// 3. Split multi-predicate Filters
/// 4. Push Filters toward leaves
RAPtr optimize_ra(RAPtr ra) {
    if (!ra) return nullptr;

    // Collect all predicates and equijoins.
    std::vector<ResolvedPredicate> predicates;
    collect_predicates(ra.get(), predicates);
    std::vector<JoinEquality> equijoins;
    collect_equijoins(ra.get(), equijoins);

    // Propagate predicates through equijoins to derive new ones.
    auto original_count = predicates.size();
    propagate_predicates(predicates, equijoins);

    // Inject any newly derived predicates at the relevant Scans.
    if (predicates.size() > original_count) {
        std::vector<ResolvedPredicate> new_preds(
            predicates.begin() + static_cast<std::ptrdiff_t>(original_count),
            predicates.end());
        ra = inject_propagated_predicates(std::move(ra), new_preds);
    }

    // Split and push filters down.
    ra = split_filters(std::move(ra));
    ra = push_filters_down(std::move(ra));

    return ra;
}

// ── Predicate VM ────────────────────────────────────────────────
//
// A small bytecode VM that evaluates subscription predicates against
// changeset rows. Compiled once at subscribe time from the RA's
// pushed-down Filter predicates. Evaluated per changeset row.
//
// The program is run twice per row — once against old values, once
// against new values. If either run returns true, the subscription
// is affected. This correctly handles AND semantics: all predicates
// must match on the SAME row state (old or new), not across states.

/// VM opcodes.
enum class VMOp : std::uint8_t {
    LoadCol,    // push column value; next byte = column index
    ConstInt,   // push int64; next 8 bytes = value (LE)
    ConstFloat, // push double; next 8 bytes = value (LE)
    ConstStr,   // push string; next 2 bytes = length (LE), then chars
    ConstNull,  // push null
    ConstBlob,  // push blob; next 4 bytes = length (LE), then bytes
    Eq,         // pop 2, push (a == b)
    Ne,         // pop 2, push (a != b)
    Lt,         // pop 2, push (a < b)
    Le,         // pop 2, push (a <= b)
    Gt,         // pop 2, push (a > b)
    Ge,         // pop 2, push (a >= b)
    IsNull,     // pop 1, push (a is null)
    IsNotNull,  // pop 1, push (a is not null)
    InList,     // next byte = count N; pop value + N items, push (value in items)
    And,        // pop 2 bools, push (a && b)
    Or,         // pop 2 bools, push (a || b)
    Not,        // pop 1 bool, push (!a)
    True,       // push true
    Halt,       // stop; result = top of stack as bool
};

/// A compiled predicate program for one (subscription, table) pair.
using Program = std::vector<std::uint8_t>;

/// Compilation: emit helpers.
void emit_op(Program& p, VMOp op) { p.push_back(static_cast<uint8_t>(op)); }
void emit_u8(Program& p, uint8_t v) { p.push_back(v); }
void emit_u16(Program& p, uint16_t v) {
    p.push_back(v & 0xFF); p.push_back((v >> 8) & 0xFF);
}
void emit_i64(Program& p, int64_t v) {
    auto u = static_cast<uint64_t>(v);
    for (int i = 0; i < 8; ++i) p.push_back((u >> (i * 8)) & 0xFF);
}
void emit_f64(Program& p, double v) {
    uint64_t u;
    std::memcpy(&u, &v, 8);
    for (int i = 0; i < 8; ++i) p.push_back((u >> (i * 8)) & 0xFF);
}

/// Emit a constant value push.
void emit_const(Program& p, const Value& val) {
    std::visit([&](const auto& v) {
        using T = std::decay_t<decltype(v)>;
        if constexpr (std::is_same_v<T, std::monostate>) {
            emit_op(p, VMOp::ConstNull);
        } else if constexpr (std::is_same_v<T, std::int64_t>) {
            emit_op(p, VMOp::ConstInt);
            emit_i64(p, v);
        } else if constexpr (std::is_same_v<T, double>) {
            emit_op(p, VMOp::ConstFloat);
            emit_f64(p, v);
        } else if constexpr (std::is_same_v<T, std::string>) {
            emit_op(p, VMOp::ConstStr);
            emit_u16(p, static_cast<uint16_t>(v.size()));
            p.insert(p.end(), v.begin(), v.end());
        } else if constexpr (std::is_same_v<T, std::vector<uint8_t>>) {
            emit_op(p, VMOp::ConstBlob);
            uint32_t len = static_cast<uint32_t>(v.size());
            for (int i = 0; i < 4; ++i)
                p.push_back((len >> (i * 8)) & 0xFF);
            p.insert(p.end(), v.begin(), v.end());
        }
    }, val);
}

/// Emit a single predicate check: [LoadCol col][const value][cmp op].
void emit_predicate(Program& p, const ResolvedPredicate& pred) {
    if (pred.column_index < 0) {
        // Unknown column → conservative: always true.
        emit_op(p, VMOp::True);
        return;
    }

    switch (pred.op) {
        case CheckOp::Eq: case CheckOp::Ne:
        case CheckOp::Lt: case CheckOp::Le:
        case CheckOp::Gt: case CheckOp::Ge:
            emit_op(p, VMOp::LoadCol);
            emit_u8(p, static_cast<uint8_t>(pred.column_index));
            emit_const(p, pred.value);
            switch (pred.op) {
                case CheckOp::Eq: emit_op(p, VMOp::Eq); break;
                case CheckOp::Ne: emit_op(p, VMOp::Ne); break;
                case CheckOp::Lt: emit_op(p, VMOp::Lt); break;
                case CheckOp::Le: emit_op(p, VMOp::Le); break;
                case CheckOp::Gt: emit_op(p, VMOp::Gt); break;
                case CheckOp::Ge: emit_op(p, VMOp::Ge); break;
                default: break;
            }
            break;
        case CheckOp::IsNull:
            emit_op(p, VMOp::LoadCol);
            emit_u8(p, static_cast<uint8_t>(pred.column_index));
            emit_op(p, VMOp::IsNull);
            break;
        case CheckOp::IsNotNull:
            emit_op(p, VMOp::LoadCol);
            emit_u8(p, static_cast<uint8_t>(pred.column_index));
            emit_op(p, VMOp::IsNotNull);
            break;
        case CheckOp::InList:
            // Push the column value, then all list values, then InList.
            emit_op(p, VMOp::LoadCol);
            emit_u8(p, static_cast<uint8_t>(pred.column_index));
            for (const auto& v : pred.values) emit_const(p, v);
            emit_op(p, VMOp::InList);
            emit_u8(p, static_cast<uint8_t>(pred.values.size()));
            break;
    }
    // Apply negation if set (e.g., NOT IN).
    if (pred.negated) {
        emit_op(p, VMOp::Not);
    }
}

/// Compile predicates for a specific table into a bytecode program.
/// All predicates for the table are AND-connected.
/// Returns an empty program if no predicates apply (= always affected).
/// Compile result: program bytecode and whether preloading is needed.
struct CompileResult {
    Program program;
    bool    needs_preload = false;
};

CompileResult compile_predicates(
        const std::vector<ResolvedPredicate>& predicates,
        const std::string& table) {
    // Collect predicates for this table.
    std::vector<const ResolvedPredicate*> mine;
    for (const auto& pred : predicates) {
        if (pred.table == table && pred.column_index >= 0) {
            mine.push_back(&pred);
        }
    }
    if (mine.empty()) return {};  // no predicates → no program

    // Check if predicates reference more than one distinct column.
    // Multi-column predicates need preloading for UPDATE changesets.
    std::set<int> pred_columns;
    for (const auto* p : mine) pred_columns.insert(p->column_index);
    bool needs_preload = pred_columns.size() > 1;

    Program prog;
    emit_predicate(prog, *mine[0]);
    for (size_t i = 1; i < mine.size(); ++i) {
        emit_predicate(prog, *mine[i]);
        emit_op(prog, VMOp::And);
    }
    emit_op(prog, VMOp::Halt);
    return {std::move(prog), needs_preload};
}

// ── VM evaluator ────────────────────────────────────────────────

/// Convert a sqlite3_value to a sqlpipe::Value.
Value sqlite3_value_to_value(sqlite3_value* v) {
    if (!v) return std::monostate{};
    switch (sqlite3_value_type(v)) {
        case SQLITE_INTEGER:
            return sqlite3_value_int64(v);
        case SQLITE_FLOAT:
            return sqlite3_value_double(v);
        case SQLITE_TEXT: {
            const char* t = reinterpret_cast<const char*>(
                sqlite3_value_text(v));
            return t ? std::string(t) : std::string{};
        }
        case SQLITE_BLOB: {
            int len = sqlite3_value_bytes(v);
            auto* p = static_cast<const std::uint8_t*>(sqlite3_value_blob(v));
            return std::vector<std::uint8_t>(p, p + len);
        }
        default:
            return std::monostate{};
    }
}

/// Compare two Values. Returns <0, 0, >0 following SQLite affinity rules.
int compare_values(const Value& a, const Value& b) {
    bool a_null = std::holds_alternative<std::monostate>(a);
    bool b_null = std::holds_alternative<std::monostate>(b);
    if (a_null && b_null) return 0;
    if (a_null) return -1;
    if (b_null) return 1;

    if (auto* ai = std::get_if<std::int64_t>(&a)) {
        if (auto* bi = std::get_if<std::int64_t>(&b))
            return (*ai < *bi) ? -1 : (*ai > *bi) ? 1 : 0;
        if (auto* bd = std::get_if<double>(&b))
            return (static_cast<double>(*ai) < *bd) ? -1 :
                   (static_cast<double>(*ai) > *bd) ? 1 : 0;
    }
    if (auto* ad = std::get_if<double>(&a)) {
        if (auto* bd = std::get_if<double>(&b))
            return (*ad < *bd) ? -1 : (*ad > *bd) ? 1 : 0;
        if (auto* bi = std::get_if<std::int64_t>(&b))
            return (*ad < static_cast<double>(*bi)) ? -1 :
                   (*ad > static_cast<double>(*bi)) ? 1 : 0;
    }
    if (auto* as = std::get_if<std::string>(&a)) {
        if (auto* bs = std::get_if<std::string>(&b))
            return as->compare(*bs);
    }
    if (auto* ab = std::get_if<std::vector<std::uint8_t>>(&a)) {
        if (auto* bb = std::get_if<std::vector<std::uint8_t>>(&b)) {
            auto minlen = std::min(ab->size(), bb->size());
            int cmp = std::memcmp(ab->data(), bb->data(), minlen);
            if (cmp != 0) return cmp;
            return (ab->size() < bb->size()) ? -1 :
                   (ab->size() > bb->size()) ? 1 : 0;
        }
    }

    auto type_rank = [](const Value& v) -> int {
        if (std::holds_alternative<std::monostate>(v)) return 0;
        if (std::holds_alternative<std::int64_t>(v)) return 1;
        if (std::holds_alternative<double>(v)) return 1;
        if (std::holds_alternative<std::string>(v)) return 2;
        return 3;
    };
    return type_rank(a) < type_rank(b) ? -1 :
           type_rank(a) > type_rank(b) ? 1 : 0;
}

/// Loaded row values for UPDATE operations where the changeset
/// doesn't carry all columns needed by multi-column predicates.
struct LoadedRow {
    std::vector<Value> old_values;
    std::vector<Value> new_values;
};

/// Load old and new row state for an UPDATE changeset entry.
/// The changeset has already been applied, so the current DB state
/// is the new row. Old state is reconstructed by overlaying changeset
/// old values (PK + changed columns) onto the current row (unchanged
/// columns are the same in old and new).
LoadedRow load_update_row(sqlite3* db, const std::string& table,
                          sqlite3_changeset_iter* iter, int ncol) {
    LoadedRow row;
    // Get rowid from changeset PK.
    sqlite3_value* pk_val = nullptr;
    sqlite3changeset_old(iter, 0, &pk_val);
    if (!pk_val) return row;
    int64_t rowid = sqlite3_value_int64(pk_val);

    // Read current row from DB (= new state).
    std::string sql = "SELECT * FROM \"" + table + "\" WHERE rowid = ?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        if (stmt) sqlite3_finalize(stmt);
        return row;
    }
    sqlite3_bind_int64(stmt, 1, rowid);

    row.new_values.resize(static_cast<size_t>(ncol));
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        for (int i = 0; i < ncol; ++i) {
            row.new_values[static_cast<size_t>(i)] =
                sqlite3_value_to_value(sqlite3_column_value(stmt, i));
        }
    }
    sqlite3_finalize(stmt);

    // Old = new, then overlay changeset old values for changed columns.
    row.old_values = row.new_values;
    for (int i = 0; i < ncol; ++i) {
        sqlite3_value* val = nullptr;
        sqlite3changeset_old(iter, i, &val);
        if (val) {
            row.old_values[static_cast<size_t>(i)] =
                sqlite3_value_to_value(val);
        }
    }
    return row;
}

/// VM execution context: provides column values for LoadCol.
struct VMContext {
    sqlite3_changeset_iter* iter;
    int op;   // SQLITE_INSERT, SQLITE_UPDATE, or SQLITE_DELETE
    bool use_new;  // true = LoadCol reads new values, false = old values

    /// Loaded full row for UPDATE with multi-column predicates.
    /// When set, LoadCol reads from here instead of the changeset.
    const LoadedRow* loaded = nullptr;
};

/// Read a LE uint16 from program at position pc. Advances pc.
uint16_t read_u16(const Program& p, size_t& pc) {
    uint16_t v = p[pc] | (p[pc+1] << 8);
    pc += 2;
    return v;
}

/// Read a LE int64 from program at position pc. Advances pc.
int64_t read_i64(const Program& p, size_t& pc) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= static_cast<uint64_t>(p[pc+i]) << (i*8);
    pc += 8;
    return static_cast<int64_t>(v);
}

/// Read a LE double from program at position pc. Advances pc.
double read_f64(const Program& p, size_t& pc) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= static_cast<uint64_t>(p[pc+i]) << (i*8);
    pc += 8;
    double d;
    std::memcpy(&d, &v, 8);
    return d;
}

/// Run a program against a changeset row context. Returns true if matched.
bool vm_run(const Program& prog, VMContext& ctx) {
    if (prog.empty()) return true;  // no program → conservative match

    std::vector<Value> stack;
    stack.reserve(8);
    size_t pc = 0;

    while (pc < prog.size()) {
        auto op = static_cast<VMOp>(prog[pc++]);
        switch (op) {
            case VMOp::LoadCol: {
                uint8_t col = prog[pc++];

                // If we have a loaded full row, use it directly.
                if (ctx.loaded) {
                    const auto& row = ctx.use_new
                        ? ctx.loaded->new_values
                        : ctx.loaded->old_values;
                    stack.push_back(col < row.size()
                        ? row[col] : Value{std::monostate{}});
                    break;
                }

                // Read directly from changeset.
                sqlite3_value* val = nullptr;
                if (ctx.op == SQLITE_INSERT) {
                    sqlite3changeset_new(ctx.iter, col, &val);
                } else if (ctx.op == SQLITE_DELETE) {
                    sqlite3changeset_old(ctx.iter, col, &val);
                } else if (ctx.op == SQLITE_UPDATE) {
                    // Single-column predicate path: try preferred direction,
                    // fall back to other. If neither has a value, bail.
                    if (ctx.use_new) {
                        sqlite3changeset_new(ctx.iter, col, &val);
                        if (!val) sqlite3changeset_old(ctx.iter, col, &val);
                    } else {
                        sqlite3changeset_old(ctx.iter, col, &val);
                        if (!val) sqlite3changeset_new(ctx.iter, col, &val);
                    }
                    if (!val) return true;  // conservative
                }
                stack.push_back(sqlite3_value_to_value(val));
                break;
            }
            case VMOp::ConstInt:
                stack.push_back(read_i64(prog, pc));
                break;
            case VMOp::ConstFloat:
                stack.push_back(read_f64(prog, pc));
                break;
            case VMOp::ConstStr: {
                uint16_t len = read_u16(prog, pc);
                stack.push_back(std::string(
                    reinterpret_cast<const char*>(&prog[pc]), len));
                pc += len;
                break;
            }
            case VMOp::ConstNull:
                stack.push_back(std::monostate{});
                break;
            case VMOp::ConstBlob: {
                uint32_t len = 0;
                for (int i = 0; i < 4; ++i)
                    len |= static_cast<uint32_t>(prog[pc+i]) << (i*8);
                pc += 4;
                stack.push_back(std::vector<uint8_t>(&prog[pc], &prog[pc+len]));
                pc += len;
                break;
            }
            case VMOp::Eq: case VMOp::Ne:
            case VMOp::Lt: case VMOp::Le:
            case VMOp::Gt: case VMOp::Ge: {
                auto b = stack.back(); stack.pop_back();
                auto a = stack.back(); stack.pop_back();
                // SQL: any comparison with NULL yields NULL.
                bool a_null = std::holds_alternative<std::monostate>(a);
                bool b_null = std::holds_alternative<std::monostate>(b);
                if (a_null || b_null) {
                    stack.push_back(std::monostate{});
                    break;
                }
                int cmp = compare_values(a, b);
                bool result;
                switch (op) {
                    case VMOp::Eq: result = (a == b); break;
                    case VMOp::Ne: result = (a != b); break;
                    case VMOp::Lt: result = cmp < 0; break;
                    case VMOp::Le: result = cmp <= 0; break;
                    case VMOp::Gt: result = cmp > 0; break;
                    case VMOp::Ge: result = cmp >= 0; break;
                    default: result = true; break;
                }
                stack.push_back(result ? std::int64_t{1} : std::int64_t{0});
                break;
            }
            case VMOp::IsNull: {
                auto v = stack.back(); stack.pop_back();
                stack.push_back(std::holds_alternative<std::monostate>(v)
                    ? std::int64_t{1} : std::int64_t{0});
                break;
            }
            case VMOp::IsNotNull: {
                auto v = stack.back(); stack.pop_back();
                stack.push_back(!std::holds_alternative<std::monostate>(v)
                    ? std::int64_t{1} : std::int64_t{0});
                break;
            }
            case VMOp::InList: {
                uint8_t count = prog[pc++];
                // Stack: [... value, list_item_0, ..., list_item_(count-1)]
                std::vector<Value> items(
                    stack.end() - count, stack.end());
                stack.resize(stack.size() - count);
                auto val = stack.back(); stack.pop_back();
                // SQL IN: NULL value → NULL. NULL in list → NULL if no match.
                if (std::holds_alternative<std::monostate>(val)) {
                    stack.push_back(std::monostate{});
                } else {
                    bool found = false;
                    bool has_null_item = false;
                    for (const auto& item : items) {
                        if (std::holds_alternative<std::monostate>(item)) {
                            has_null_item = true;
                        } else if (val == item) {
                            found = true; break;
                        }
                    }
                    if (found) {
                        stack.push_back(std::int64_t{1});
                    } else if (has_null_item) {
                        stack.push_back(std::monostate{});
                    } else {
                        stack.push_back(std::int64_t{0});
                    }
                }
                break;
            }
            case VMOp::And: {
                // SQL three-valued AND:
                // false AND _ = false, _ AND false = false
                // true AND true = true
                // NULL AND true = NULL, true AND NULL = NULL
                // NULL AND NULL = NULL
                auto bv = stack.back(); stack.pop_back();
                auto av = stack.back(); stack.pop_back();
                bool a_null = std::holds_alternative<std::monostate>(av);
                bool b_null = std::holds_alternative<std::monostate>(bv);
                if (!a_null && std::get<std::int64_t>(av) == 0) {
                    stack.push_back(std::int64_t{0});  // false AND _ = false
                } else if (!b_null && std::get<std::int64_t>(bv) == 0) {
                    stack.push_back(std::int64_t{0});  // _ AND false = false
                } else if (a_null || b_null) {
                    stack.push_back(std::monostate{});  // NULL involved = NULL
                } else {
                    stack.push_back(std::int64_t{1});   // true AND true = true
                }
                break;
            }
            case VMOp::Or: {
                // SQL three-valued OR:
                // true OR _ = true, _ OR true = true
                // false OR false = false
                // NULL OR false = NULL, false OR NULL = NULL
                // NULL OR NULL = NULL
                auto bv = stack.back(); stack.pop_back();
                auto av = stack.back(); stack.pop_back();
                bool a_null = std::holds_alternative<std::monostate>(av);
                bool b_null = std::holds_alternative<std::monostate>(bv);
                if (!a_null && std::get<std::int64_t>(av) != 0) {
                    stack.push_back(std::int64_t{1});  // true OR _ = true
                } else if (!b_null && std::get<std::int64_t>(bv) != 0) {
                    stack.push_back(std::int64_t{1});  // _ OR true = true
                } else if (a_null || b_null) {
                    stack.push_back(std::monostate{});  // NULL involved = NULL
                } else {
                    stack.push_back(std::int64_t{0});   // false OR false = false
                }
                break;
            }
            case VMOp::Not: {
                auto v = stack.back(); stack.pop_back();
                if (std::holds_alternative<std::monostate>(v)) {
                    stack.push_back(std::monostate{});  // NOT NULL = NULL
                } else {
                    auto a = std::get<std::int64_t>(v);
                    stack.push_back(std::int64_t{a ? 0 : 1});
                }
                break;
            }
            case VMOp::True:
                stack.push_back(std::int64_t{1});
                break;
            case VMOp::Halt:
                goto done;
        }
    }
done:
    if (stack.empty()) return true;  // empty program → conservative
    return std::holds_alternative<std::int64_t>(stack.back()) &&
           std::get<std::int64_t>(stack.back()) != 0;
}

// ── Predicate index using VM programs ───────────────────────────

/// Per-(subscription, table) compiled program + relevant column set.
struct SubProgram {
    SubscriptionId sub_id;
    Program        program;       // empty = no predicates for this table → always affected
    std::set<int>  columns_used;  // columns the query reads from this table
                                  // empty = unknown → conservative (all columns relevant)
    bool needs_preload = false;   // true if program has multi-column predicates
};

/// The predicate index: maps table → list of compiled programs.
using ProgramIndex = std::unordered_map<std::string, std::vector<SubProgram>>;

/// Evaluate a changeset against compiled VM programs.
/// Runs each program twice (old values, new values) per changeset row.
/// Returns the set of subscription IDs affected.
std::set<SubscriptionId> evaluate_changeset(
        sqlite3* db,
        const Changeset& data,
        const ProgramIndex& index,
        const std::unordered_map<std::string, std::set<SubscriptionId>>& table_subs) {
    std::set<SubscriptionId> affected;
    if (data.empty()) return affected;

    sqlite3_changeset_iter* iter = nullptr;
    int rc = sqlite3changeset_start(&iter,
        static_cast<int>(data.size()),
        const_cast<void*>(static_cast<const void*>(data.data())));
    if (rc != SQLITE_OK) {
        for (const auto& [_, subs] : table_subs) {
            affected.insert(subs.begin(), subs.end());
        }
        return affected;
    }

    while (sqlite3changeset_next(iter) == SQLITE_ROW) {
        const char* tbl = nullptr;
        int ncol = 0, cs_op = 0, indirect = 0;
        sqlite3changeset_op(iter, &tbl, &ncol, &cs_op, &indirect);
        if (!tbl) continue;

        std::string table_name(tbl);
        auto idx_it = index.find(table_name);

        // Subscriptions with no program for this table → check table_subs.
        auto ts_it = table_subs.find(table_name);
        if (ts_it == table_subs.end()) continue;

        if (idx_it == index.end()) {
            // No programs at all for this table → all subs are affected.
            for (auto sub_id : ts_it->second) {
                affected.insert(sub_id);
            }
            continue;
        }

        // For UPDATE, determine which columns changed.
        std::set<int> changed_cols;
        if (cs_op == SQLITE_UPDATE) {
            for (int col = 0; col < ncol; ++col) {
                sqlite3_value* val = nullptr;
                sqlite3changeset_new(iter, col, &val);
                if (val) changed_cols.insert(col);
            }
        }

        // Run each subscription's program.
        for (const auto& sp : idx_it->second) {
            if (affected.count(sp.sub_id)) continue;

            // For UPDATE: if the subscription's relevant columns don't
            // overlap with the changed columns, the result can't change.
            if (cs_op == SQLITE_UPDATE && !sp.columns_used.empty()) {
                bool any_overlap = false;
                for (int col : changed_cols) {
                    if (sp.columns_used.count(col)) {
                        any_overlap = true;
                        break;
                    }
                }
                if (!any_overlap) continue;  // no relevant column changed
            }

            if (sp.program.empty()) {
                // No predicates for this table → always affected.
                affected.insert(sp.sub_id);
                continue;
            }

            VMContext ctx{iter, cs_op, false, nullptr};
            bool old_match = false, new_match = false;

            // For UPDATE with multi-column predicates, load the full
            // row from the DB to provide unchanged column values.
            LoadedRow loaded_row;
            if (cs_op == SQLITE_UPDATE && sp.needs_preload && db) {
                loaded_row = load_update_row(db, table_name, iter, ncol);
                if (!loaded_row.old_values.empty()) {
                    ctx.loaded = &loaded_row;
                }
            }

            // Run against old values (UPDATE, DELETE).
            if (cs_op == SQLITE_UPDATE || cs_op == SQLITE_DELETE) {
                ctx.use_new = false;
                old_match = vm_run(sp.program, ctx);
            }

            // Run against new values (INSERT, UPDATE).
            if (!old_match &&
                (cs_op == SQLITE_INSERT || cs_op == SQLITE_UPDATE)) {
                ctx.use_new = true;
                new_match = vm_run(sp.program, ctx);
            }

            if (old_match || new_match) {
                affected.insert(sp.sub_id);
            }
        }

        // Also check for subscriptions on this table with NO entry in
        // the program index (they have no predicates at all).
        for (auto sub_id : ts_it->second) {
            if (affected.count(sub_id)) continue;
            bool has_program = false;
            for (const auto& sp : idx_it->second) {
                if (sp.sub_id == sub_id) { has_program = true; break; }
            }
            if (!has_program) {
                affected.insert(sub_id);
            }
        }
    }

    sqlite3changeset_finalize(iter);
    return affected;
}

} // namespace sqlpipe::detail

// ── query_watch.cpp ─────────────────────────────────────────────

namespace sqlpipe {

struct QueryWatch::Impl {
    sqlite3* db;
    detail::SchemaMap schema;

    struct Subscription {
        SubscriptionId               id;
        std::string                  sql;
        std::set<std::string>        tables;
        detail::RAPtr                ra;        // relational algebra tree
        std::vector<detail::ResolvedPredicate> predicates;  // extracted filters
        detail::StmtGuard            stmt;     // cached prepared statement
        std::vector<std::string>     columns;  // cached column names
        std::uint64_t                result_hash = 0;  // hash of last delivered result
    };
    std::map<SubscriptionId, Subscription> subscriptions;
    // Reverse index: table name → subscription IDs that depend on it.
    std::unordered_map<std::string, std::set<SubscriptionId>> table_subs;
    // Program index: table → compiled VM programs per subscription.
    detail::ProgramIndex prog_index;
    // Subscriptions registered since last notify — need initial evaluation.
    std::set<SubscriptionId> pending_new;
    SubscriptionId next_sub_id = 1;

    /// Rebuild the program index from all subscriptions.
    void rebuild_prog_index() {
        prog_index.clear();
        for (const auto& [id, sub] : subscriptions) {
            for (const auto& table : sub.tables) {
                auto cr = detail::compile_predicates(
                    sub.predicates, table);
                std::set<int> cols;
                if (sub.ra) {
                    cols = detail::columns_for_table(sub.ra.get(), table);
                }
                prog_index[table].push_back(
                    {id, std::move(cr.program), std::move(cols),
                     cr.needs_preload});
            }
        }
    }

    /// Analyze a subscription query using the RA transform.
    /// Returns table dependencies and extracts predicates.
    std::set<std::string> analyze_query(const std::string& sql,
                                        detail::RAPtr& ra_out,
                                        std::vector<detail::ResolvedPredicate>& preds_out) {
        // Ensure schema is current.
        schema = detail::build_schema_map(db);

        ra_out = detail::sql_to_ra(sql, schema);
        std::set<std::string> tables;

        if (ra_out) {
            ra_out->collect_tables(tables);
            // After optimization, predicates are pushed to leaf Filters.
            // Collect them all for changeset checking.
            detail::collect_predicates(ra_out.get(), preds_out);
        } else {
            // RA transform failed (non-SELECT or parse error).
            // Fall back to authorizer-based table discovery.
            sqlite3_set_authorizer(db, [](void* ctx, int action,
                    const char* a1, const char*, const char*, const char*) -> int {
                if (action == SQLITE_READ && a1) {
                    std::string name(a1);
                    if (name.compare(0, 9, "_sqlpipe_") != 0 &&
                        name.compare(0, 7, "sqlite_") != 0) {
                        static_cast<std::set<std::string>*>(ctx)->insert(name);
                    }
                }
                return SQLITE_OK;
            }, &tables);

            sqlite3_stmt* stmt = nullptr;
            sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
            if (stmt) sqlite3_finalize(stmt);
            sqlite3_set_authorizer(db, nullptr, nullptr);
        }
        return tables;
    }

    // Evaluate a subscription query. Returns the result and its hash.
    std::pair<QueryResult, std::uint64_t> evaluate_query(Subscription& sub) {
        QueryResult result;
        result.id = sub.id;
        result.columns = sub.columns;

        std::uint64_t h = detail::kFnv64Offset;
        sqlite3_reset(sub.stmt.get());
        int ncols = static_cast<int>(sub.columns.size());
        while (sqlite3_step(sub.stmt.get()) == SQLITE_ROW) {
            detail::fnv64_byte(h, 0xFF);  // row separator
            std::vector<Value> row;
            row.reserve(static_cast<std::size_t>(ncols));
            for (int i = 0; i < ncols; ++i) {
                row.push_back(detail::to_value(
                    sqlite3_column_value(sub.stmt.get(), i)));
                detail::hash_value(h, row.back());
            }
            result.rows.push_back(std::move(row));
        }
        return {std::move(result), h};
    }

    std::vector<QueryResult> evaluate_invalidated(
            const std::set<std::string>& affected,
            const Changeset* changeset = nullptr) {
        // Determine which subscriptions to evaluate.
        std::set<SubscriptionId> ids;

        if (changeset && !changeset->empty() && !prog_index.empty()) {
            // VM evaluation: iterate changeset once, run compiled
            // programs for each subscription.
            ids = detail::evaluate_changeset(
                db, *changeset, prog_index, table_subs);
        } else {
            // No changeset or no predicates — table-level invalidation.
            for (const auto& table : affected) {
                auto it = table_subs.find(table);
                if (it != table_subs.end()) {
                    ids.insert(it->second.begin(), it->second.end());
                }
            }
        }

        // Also include any newly registered subscriptions that haven't
        // been evaluated yet (their initial result delivery).
        ids.insert(pending_new.begin(), pending_new.end());
        pending_new.clear();

        std::vector<QueryResult> results;
        for (auto id : ids) {
            auto it = subscriptions.find(id);
            if (it == subscriptions.end()) continue;
            auto& sub = it->second;

            auto [result, hash] = evaluate_query(sub);
            if (hash != sub.result_hash) {
                sub.result_hash = hash;
                results.push_back(std::move(result));
            }
        }
        return results;
    }
};

QueryWatch::QueryWatch(sqlite3* db)
    : impl_(std::make_unique<Impl>()) {
    impl_->db = db;
}

QueryWatch::~QueryWatch() = default;
QueryWatch::QueryWatch(QueryWatch&&) noexcept = default;
QueryWatch& QueryWatch::operator=(QueryWatch&&) noexcept = default;

SubscriptionId QueryWatch::subscribe(const std::string& sql) {
    detail::RAPtr ra;
    std::vector<detail::ResolvedPredicate> predicates;
    auto tables = impl_->analyze_query(sql, ra, predicates);
    auto id = impl_->next_sub_id++;

    // Prepare statement once and cache column names.
    auto stmt = detail::prepare(impl_->db, sql.c_str());
    int ncols = sqlite3_column_count(stmt.get());
    std::vector<std::string> columns;
    columns.reserve(static_cast<std::size_t>(ncols));
    for (int i = 0; i < ncols; ++i) {
        const char* name = sqlite3_column_name(stmt.get(), i);
        columns.push_back(name ? name : "");
    }

    // Build reverse index entries.
    for (const auto& t : tables) {
        impl_->table_subs[t].insert(id);
    }

    // Register with hash=0 (never evaluated). The next notify() will
    // evaluate and deliver the initial result.
    impl_->subscriptions[id] = {id, sql, std::move(tables), std::move(ra),
                                std::move(predicates), std::move(stmt),
                                std::move(columns), 0};
    impl_->pending_new.insert(id);
    impl_->rebuild_prog_index();
    return id;
}

void QueryWatch::unsubscribe(SubscriptionId id) {
    auto it = impl_->subscriptions.find(id);
    if (it != impl_->subscriptions.end()) {
        // Remove reverse index entries.
        for (const auto& t : it->second.tables) {
            auto ts_it = impl_->table_subs.find(t);
            if (ts_it != impl_->table_subs.end()) {
                ts_it->second.erase(id);
                if (ts_it->second.empty()) {
                    impl_->table_subs.erase(ts_it);
                }
            }
        }
        impl_->pending_new.erase(id);
        impl_->subscriptions.erase(it);
        impl_->rebuild_prog_index();
    }
}

std::vector<QueryResult> QueryWatch::notify(
        const std::set<std::string>& affected_tables) {
    return impl_->evaluate_invalidated(affected_tables);
}

std::vector<QueryResult> QueryWatch::notify(
        const std::set<std::string>& affected_tables,
        const Changeset& changeset_data) {
    return impl_->evaluate_invalidated(affected_tables, &changeset_data);
}

bool QueryWatch::empty() const {
    return impl_->subscriptions.empty();
}


// ── query (one-shot) ────────────────────────────────────────────

QueryResult query(sqlite3* db, const std::string& sql) {
    auto stmt = detail::prepare(db, sql.c_str());
    int ncols = sqlite3_column_count(stmt.get());

    QueryResult result;
    result.id = 0;
    result.columns.reserve(static_cast<std::size_t>(ncols));
    for (int i = 0; i < ncols; ++i) {
        const char* name = sqlite3_column_name(stmt.get(), i);
        result.columns.push_back(name ? name : "");
    }

    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        std::vector<Value> row;
        row.reserve(static_cast<std::size_t>(ncols));
        for (int i = 0; i < ncols; ++i) {
            row.push_back(detail::to_value(
                sqlite3_column_value(stmt.get(), i)));
        }
        result.rows.push_back(std::move(row));
    }
    return result;
}

} // namespace sqlpipe

// ── replica.cpp ─────────────────────────────────────────────────

namespace sqlpipe {

struct Replica::Impl {
    sqlite3*       db;
    ReplicaConfig  config;
    Seq            seq = 0;
    Replica::State state = Replica::State::Init;
    QueryWatch     watch;

    // Prediction state.
    enum class PredictionState : uint8_t { None, Drafting, Committed };
    PredictionState prediction = PredictionState::None;

    Impl(sqlite3* db_, ReplicaConfig cfg)
        : db(db_), config(std::move(cfg)), watch(db_) {}

    const std::set<std::string>* filter() const {
        return config.table_filter ? &*config.table_filter : nullptr;
    }

    void report(DiffPhase phase, const std::string& table,
                std::int64_t done, std::int64_t total) {
        if (config.on_progress) {
            config.on_progress(DiffProgress{phase, table, done, total});
        }
    }

    void init() {
        detail::ensure_meta_table(db);
        seq = detail::read_seq(db, config.seq_key);
        SQLPIPE_LOG(config.on_log, LogLevel::Info, "replica initialized at seq={}", seq);
    }

    std::vector<ChangeEvent> apply_changeset(const Changeset& data, Seq new_seq) {
        if (new_seq != seq + 1) {
            throw Error(ErrorCode::ProtocolError,
                        "changeset seq gap: expected " +
                        std::to_string(seq + 1) + ", got " +
                        std::to_string(new_seq));
        }
        int rc = sqlite3changeset_apply(
            db,
            static_cast<int>(data.size()),
            const_cast<void*>(static_cast<const void*>(data.data())),
            nullptr,
            [](void* ctx, int conflict_type, sqlite3_changeset_iter* iter)
                -> int {
                auto* cfg = static_cast<ReplicaConfig*>(ctx);
                if (!cfg->on_conflict) {
                    return SQLITE_CHANGESET_ABORT;
                }

                auto event = detail::extract_event(iter);

                ConflictType ct;
                switch (conflict_type) {
                case SQLITE_CHANGESET_DATA:        ct = ConflictType::Data; break;
                case SQLITE_CHANGESET_NOTFOUND:    ct = ConflictType::NotFound; break;
                case SQLITE_CHANGESET_CONFLICT:    ct = ConflictType::Conflict; break;
                case SQLITE_CHANGESET_CONSTRAINT:  ct = ConflictType::Constraint; break;
                case SQLITE_CHANGESET_FOREIGN_KEY: ct = ConflictType::ForeignKey; break;
                default:                           ct = ConflictType::Data; break;
                }

                auto action = cfg->on_conflict(ct, event);
                switch (action) {
                case ConflictAction::Omit:    return SQLITE_CHANGESET_OMIT;
                case ConflictAction::Replace: return SQLITE_CHANGESET_REPLACE;
                case ConflictAction::Abort:   return SQLITE_CHANGESET_ABORT;
                default:                      return SQLITE_CHANGESET_ABORT;
                }
            },
            &config);

        if (rc != SQLITE_OK) {
            throw Error(ErrorCode::SqliteError,
                        std::string("changeset_apply: ") + sqlite3_errmsg(db));
        }

        auto events = detail::collect_events(data);

        seq = new_seq;
        detail::write_seq(db, seq, config.seq_key);
        return events;
    }

    HandleResult handle_hello_from_master(const HelloMsg& m) {
        if (state != Replica::State::Handshake) {
            state = Replica::State::Error;
            return {{Message{ErrorMsg{ErrorCode::InvalidState,
                "received HelloMsg in unexpected state"}}}, {}, {}};
        }
        if (m.protocol_version != kProtocolVersion) {
            state = Replica::State::Error;
            return {{Message{ErrorMsg{ErrorCode::ProtocolError,
                "unsupported protocol version"}}}, {}, {}};
        }

        // Fast reconnect: master confirmed seq match — skip to Live.
        if (m.last_seq > 0 && m.last_seq == seq) {
            state = Replica::State::Live;
            SQLPIPE_LOG(config.on_log, LogLevel::Info,
                        "fast reconnect: seq match ({}), skipping diff sync", seq);
            return {{Message{AckMsg{seq}}}, {}, {}};
        }

        // Compute bucket hashes and send to master.
        report(DiffPhase::ComputingBuckets, {}, 0, 0);
        auto buckets = detail::compute_all_buckets(
            db, filter(), config.bucket_size);
        report(DiffPhase::ComputingBuckets, {},
               static_cast<std::int64_t>(buckets.size()),
               static_cast<std::int64_t>(buckets.size()));
        state = Replica::State::DiffBuckets;
        SQLPIPE_LOG(config.on_log, LogLevel::Info, "sending {} bucket hashes (seq={})", buckets.size(), seq);
        return {{Message{BucketHashesMsg{
            std::move(buckets), seq, kProtocolVersion,
            detail::compute_schema_fingerprint(db, filter())}}}, {}, {}};
    }

    HandleResult handle_need_buckets(const NeedBucketsMsg& m) {
        // Accept in DiffBuckets (normal handshake) or Live (re-convergence).
        if (state != Replica::State::DiffBuckets &&
            state != Replica::State::Live) {
            state = Replica::State::Error;
            return {{Message{ErrorMsg{ErrorCode::InvalidState,
                "received NeedBucketsMsg in unexpected state"}}}, {}, {}};
        }

        state = Replica::State::DiffRows;

        if (m.ranges.empty()) {
            // All buckets match; waiting for DiffReadyMsg.
            SQLPIPE_LOG(config.on_log, LogLevel::Info, "all buckets match, waiting for DiffReady");
            return {};
        }

        // Compute row hashes for requested ranges.
        RowHashesMsg rh;
        std::int64_t ranges_done = 0;
        auto ranges_total = static_cast<std::int64_t>(m.ranges.size());
        for (const auto& range : m.ranges) {
            report(DiffPhase::ComputingRowHashes, range.table,
                   ranges_done, ranges_total);
            auto rows = detail::compute_row_hashes(
                db, range.table, range.lo, range.hi);

            RowHashesEntry entry;
            entry.table = range.table;
            entry.lo = range.lo;
            entry.hi = range.hi;

            // Run-length encode: group contiguous rowids.
            if (!rows.empty()) {
                RowHashRun current_run;
                current_run.start_rowid = rows[0].rowid;
                current_run.count = 1;
                current_run.hashes.push_back(rows[0].hash);

                for (std::size_t i = 1; i < rows.size(); ++i) {
                    if (rows[i].rowid ==
                        current_run.start_rowid + current_run.count) {
                        // Contiguous.
                        current_run.count++;
                        current_run.hashes.push_back(rows[i].hash);
                    } else {
                        // Gap — start a new run.
                        entry.runs.push_back(std::move(current_run));
                        current_run = RowHashRun{};
                        current_run.start_rowid = rows[i].rowid;
                        current_run.count = 1;
                        current_run.hashes.push_back(rows[i].hash);
                    }
                }
                entry.runs.push_back(std::move(current_run));
            }

            rh.entries.push_back(std::move(entry));
            ++ranges_done;
        }

        SQLPIPE_LOG(config.on_log, LogLevel::Info, "sending row hashes for {} ranges", m.ranges.size());
        return {{Message{std::move(rh)}}, {}, {}};
    }

    HandleResult handle_diff_ready(const DiffReadyMsg& m) {
        // Accept in DiffRows, DiffBuckets (normal handshake), or Live (re-convergence).
        if (state != Replica::State::DiffRows &&
            state != Replica::State::DiffBuckets &&
            state != Replica::State::Live) {
            state = Replica::State::Error;
            return {{Message{ErrorMsg{ErrorCode::InvalidState,
                "received DiffReadyMsg in unexpected state"}}}, {}, {}};
        }

        std::vector<ChangeEvent> events;

        // Save and disable foreign keys.
        auto fk_stmt = detail::prepare(db, "PRAGMA foreign_keys");
        bool fk_was_on = false;
        if (sqlite3_step(fk_stmt.get()) == SQLITE_ROW) {
            fk_was_on = sqlite3_column_int(fk_stmt.get(), 0) != 0;
        }
        fk_stmt = detail::StmtGuard{};
        if (fk_was_on) {
            detail::exec(db, "PRAGMA foreign_keys = OFF");
        }

        detail::exec(db, "BEGIN");

        report(DiffPhase::ApplyingPatchset, {},
               0, static_cast<std::int64_t>(m.deletes.size()) + 1);

        // Apply INSERT patchset (handles both inserts and updates via REPLACE).
        if (!m.patchset.empty()) {
            int rc = sqlite3changeset_apply(
                db,
                static_cast<int>(m.patchset.size()),
                const_cast<void*>(
                    static_cast<const void*>(m.patchset.data())),
                nullptr,
                [](void*, int, sqlite3_changeset_iter*) -> int {
                    return SQLITE_CHANGESET_REPLACE;
                },
                nullptr);

            if (rc != SQLITE_OK) {
                detail::exec(db, "ROLLBACK");
                if (fk_was_on) detail::exec(db, "PRAGMA foreign_keys = ON");
                throw Error(ErrorCode::SqliteError,
                            std::string("diff patchset apply: ") +
                            sqlite3_errmsg(db));
            }

            events = detail::collect_events(m.patchset);
        }

        // Delete rows by rowid.
        for (const auto& td : m.deletes) {
            for (auto rid : td.rowids) {
                // Query the row before deleting to collect change events.
                std::string sel_sql =
                    "SELECT * FROM \"" + td.table + "\" WHERE rowid = ?";
                auto sel_stmt = detail::prepare(db, sel_sql.c_str());
                sqlite3_bind_int64(sel_stmt.get(), 1, rid);
                if (sqlite3_step(sel_stmt.get()) == SQLITE_ROW) {
                    ChangeEvent ev;
                    ev.table = td.table;
                    ev.op = OpType::Delete;
                    int ncol = sqlite3_column_count(sel_stmt.get());
                    ev.old_values.resize(static_cast<std::size_t>(ncol));
                    for (int c = 0; c < ncol; ++c) {
                        ev.old_values[static_cast<std::size_t>(c)] =
                            detail::to_value(
                                sqlite3_column_value(sel_stmt.get(), c));
                    }
                    events.push_back(std::move(ev));
                }
                sel_stmt = detail::StmtGuard{};

                std::string del_sql =
                    "DELETE FROM \"" + td.table + "\" WHERE rowid = ?";
                auto del_stmt = detail::prepare(db, del_sql.c_str());
                sqlite3_bind_int64(del_stmt.get(), 1, rid);
                detail::step_done(db, del_stmt.get());
            }
        }

        // Update seq.
        seq = m.seq;
        detail::write_seq(db, seq, config.seq_key);

        detail::exec(db, "COMMIT");

        if (fk_was_on) {
            detail::exec(db, "PRAGMA foreign_keys = ON");
        }

        state = Replica::State::Live;
        SQLPIPE_LOG(config.on_log, LogLevel::Info, "diff applied, entering live at seq={}", seq);

        return {{Message{AckMsg{m.seq}}}, std::move(events), {}};
    }
};

// ── Public API ──────────────────────────────────────────────────────

Replica::Replica(sqlite3* db, ReplicaConfig config)
    : impl_(std::make_unique<Impl>(db, std::move(config))) {
    impl_->init();
}

Replica::~Replica() = default;
Replica::Replica(Replica&&) noexcept = default;
Replica& Replica::operator=(Replica&&) noexcept = default;

Message Replica::hello() const {
    impl_->state = State::Handshake;
    const auto* f = impl_->config.table_filter
        ? &*impl_->config.table_filter : nullptr;
    return Message{HelloMsg{kProtocolVersion,
                    detail::compute_schema_fingerprint(impl_->db, f), {},
                    impl_->seq}};
}

std::vector<Message> Replica::converge() {
    // Compute bucket hashes and transition to DiffBuckets, waiting for
    // the master's NeedBuckets response. Can be called in any state.
    const auto* f = impl_->config.table_filter
        ? &*impl_->config.table_filter : nullptr;

    impl_->report(DiffPhase::ComputingBuckets, {}, 0, 0);
    auto buckets = detail::compute_all_buckets(
        impl_->db, f, impl_->config.bucket_size);
    impl_->report(DiffPhase::ComputingBuckets, {},
               static_cast<std::int64_t>(buckets.size()),
               static_cast<std::int64_t>(buckets.size()));

    auto sv = detail::compute_schema_fingerprint(impl_->db, f);

    impl_->state = State::DiffBuckets;
    SQLPIPE_LOG(impl_->config.on_log, LogLevel::Info,
                "converge: sending {} bucket hashes (seq={})",
                buckets.size(), impl_->seq);
    return {Message{BucketHashesMsg{
        std::move(buckets), impl_->seq, kProtocolVersion, sv}}};
}

HandleResult Replica::handle_message(const Message& msg) {
    // Auto-rollback a committed prediction before applying server data.
    if (impl_->prediction == Impl::PredictionState::Committed) {
        detail::exec(impl_->db, "ROLLBACK TO _sqlpipe_prediction");
        detail::exec(impl_->db, "RELEASE _sqlpipe_prediction");
        impl_->prediction = Impl::PredictionState::None;
        SQLPIPE_LOG(impl_->config.on_log, LogLevel::Debug,
                    "prediction auto-rolled back (server response)");
    }

    auto prev_state = impl_->state;
    const Changeset* changeset_data = nullptr;  // for predicate-aware notify
    auto result = std::visit([&](const auto& m) -> HandleResult {
        using T = std::decay_t<decltype(m)>;

        if constexpr (std::is_same_v<T, HelloMsg>) {
            return impl_->handle_hello_from_master(m);
        }
        else if constexpr (std::is_same_v<T, NeedBucketsMsg>) {
            return impl_->handle_need_buckets(m);
        }
        else if constexpr (std::is_same_v<T, DiffReadyMsg>) {
            return impl_->handle_diff_ready(m);
        }
        else if constexpr (std::is_same_v<T, ChangesetMsg>) {
            if (impl_->state != State::Live) {
                impl_->state = State::Error;
                return {{Message{ErrorMsg{ErrorCode::InvalidState,
                    "received ChangesetMsg in unexpected state"}}}, {}, {}};
            }
            changeset_data = &m.data;
            auto events = impl_->apply_changeset(m.data, m.seq);
            SQLPIPE_LOG(impl_->config.on_log, LogLevel::Debug, "applied changeset seq={}", m.seq);
            return {{Message{AckMsg{m.seq}}}, std::move(events), {}};
        }
        else if constexpr (std::is_same_v<T, ErrorMsg>) {
            if (m.code == ErrorCode::SchemaMismatch) {
                bool resolved = false;
                if (impl_->config.on_schema_mismatch) {
                    // User callback gets first shot.
                    auto my_sv = schema_version();
                    resolved = impl_->config.on_schema_mismatch(
                        m.remote_schema_version, my_sv,
                        m.remote_schema_sql);
                } else if (!m.remote_schema_sql.empty()) {
                    // Auto-migrate: use sqlift to adopt master's schema.
                    resolved = detail::auto_migrate_schema(
                        impl_->db, m.remote_schema_sql,
                        impl_->config.on_log);
                }
                if (resolved) {
                    SQLPIPE_LOG(impl_->config.on_log, LogLevel::Info,
                                "schema mismatch resolved, "
                                "resetting to Init");
                    impl_->state = State::Init;
                    impl_->seq = detail::read_seq(
                        impl_->db, impl_->config.seq_key);
                    return {};
                }
            }
            impl_->state = State::Error;
            SQLPIPE_LOG(impl_->config.on_log, LogLevel::Error, "received error from master: {}", m.detail);
            return {};
        }
        else {
            return {{Message{ErrorMsg{ErrorCode::InvalidState,
                "unexpected message type from master"}}}, {}, {}};
        }
    }, msg);

    // Evaluate subscriptions only when Live — never during handshake or
    // diff sync, where schema may be incomplete or data in flux.
    if (impl_->state == State::Live && !impl_->watch.empty()) {
        if (!result.changes.empty()) {
            std::set<std::string> affected;
            for (const auto& ev : result.changes) {
                if (!ev.table.empty()) affected.insert(ev.table);
            }
            if (changeset_data) {
                result.subscriptions = impl_->watch.notify(
                    affected, *changeset_data);
            } else {
                result.subscriptions = impl_->watch.notify(affected);
            }
        } else if (prev_state != State::Live) {
            // Just entered Live (e.g., diff sync found no differences).
            // Force-evaluate all subscriptions so clients that subscribed
            // before sync get current data.
            auto all_tables = detail::get_tracked_tables(
                impl_->db, impl_->filter());
            std::set<std::string> all(all_tables.begin(), all_tables.end());
            result.subscriptions = impl_->watch.notify(all);
        }
    }

    return result;
}

HandleResult Replica::handle_messages(std::span<const Message> msgs) {
    if (impl_->prediction == Impl::PredictionState::Committed) {
        detail::exec(impl_->db, "ROLLBACK TO _sqlpipe_prediction");
        detail::exec(impl_->db, "RELEASE _sqlpipe_prediction");
        impl_->prediction = Impl::PredictionState::None;
    }
    auto prev_state = impl_->state;
    HandleResult combined;
    std::set<std::string> affected;

    for (const auto& msg : msgs) {
        auto result = std::visit([&](const auto& m) -> HandleResult {
            using T = std::decay_t<decltype(m)>;

            if constexpr (std::is_same_v<T, HelloMsg>) {
                return impl_->handle_hello_from_master(m);
            }
            else if constexpr (std::is_same_v<T, NeedBucketsMsg>) {
                return impl_->handle_need_buckets(m);
            }
            else if constexpr (std::is_same_v<T, DiffReadyMsg>) {
                return impl_->handle_diff_ready(m);
            }
            else if constexpr (std::is_same_v<T, ChangesetMsg>) {
                if (impl_->state != State::Live) {
                    impl_->state = State::Error;
                    return {{Message{ErrorMsg{ErrorCode::InvalidState,
                        "received ChangesetMsg in unexpected state"}}}, {}, {}};
                }
                auto events = impl_->apply_changeset(m.data, m.seq);
                SQLPIPE_LOG(impl_->config.on_log, LogLevel::Debug, "applied changeset seq={}", m.seq);
                return {{Message{AckMsg{m.seq}}}, std::move(events), {}};
            }
            else if constexpr (std::is_same_v<T, ErrorMsg>) {
                if (m.code == ErrorCode::SchemaMismatch) {
                    bool resolved = false;
                    if (impl_->config.on_schema_mismatch) {
                        auto my_sv = schema_version();
                        resolved = impl_->config.on_schema_mismatch(
                            m.remote_schema_version, my_sv,
                            m.remote_schema_sql);
                    } else if (!m.remote_schema_sql.empty()) {
                        resolved = detail::auto_migrate_schema(
                            impl_->db, m.remote_schema_sql,
                            impl_->config.on_log);
                    }
                    if (resolved) {
                        SQLPIPE_LOG(impl_->config.on_log, LogLevel::Info,
                                    "schema mismatch resolved, "
                                    "resetting to Init");
                        impl_->state = State::Init;
                        impl_->seq = detail::read_seq(
                            impl_->db, impl_->config.seq_key);
                        return {};
                    }
                }
                impl_->state = State::Error;
                SQLPIPE_LOG(impl_->config.on_log, LogLevel::Error, "received error from master: {}", m.detail);
                return {};
            }
            else {
                return {{Message{ErrorMsg{ErrorCode::InvalidState,
                    "unexpected message type from master"}}}, {}, {}};
            }
        }, msg);

        combined.messages.insert(combined.messages.end(),
                                 result.messages.begin(),
                                 result.messages.end());
        for (const auto& ev : result.changes) {
            if (!ev.table.empty()) affected.insert(ev.table);
        }
        combined.changes.insert(combined.changes.end(),
                                result.changes.begin(),
                                result.changes.end());
    }

    // Evaluate subscriptions only when Live.
    if (impl_->state == State::Live && !impl_->watch.empty()) {
        if (!affected.empty()) {
            combined.subscriptions = impl_->watch.notify(affected);
        } else if (prev_state != State::Live) {
            auto all_tables = detail::get_tracked_tables(
                impl_->db, impl_->filter());
            std::set<std::string> all(all_tables.begin(), all_tables.end());
            combined.subscriptions = impl_->watch.notify(all);
        }
    }

    return combined;
}

SubscriptionId Replica::subscribe(const std::string& sql) {
    return impl_->watch.subscribe(sql);
}

void Replica::unsubscribe(SubscriptionId id) {
    impl_->watch.unsubscribe(id);
}

void Replica::begin_prediction() {
    using PS = Impl::PredictionState;
    if (impl_->prediction != PS::None) {
        throw Error(ErrorCode::InvalidState,
                    "prediction already active");
    }
    detail::exec(impl_->db, "SAVEPOINT _sqlpipe_prediction");
    impl_->prediction = PS::Drafting;
    SQLPIPE_LOG(impl_->config.on_log, LogLevel::Debug, "prediction begun");
}

void Replica::commit_prediction() {
    using PS = Impl::PredictionState;
    if (impl_->prediction != PS::Drafting) {
        throw Error(ErrorCode::InvalidState,
                    "no drafting prediction to commit");
    }
    impl_->prediction = PS::Committed;
    SQLPIPE_LOG(impl_->config.on_log, LogLevel::Debug, "prediction committed (awaiting server)");
}

void Replica::rollback_prediction() {
    using PS = Impl::PredictionState;
    if (impl_->prediction == PS::None) {
        throw Error(ErrorCode::InvalidState,
                    "no active prediction to rollback");
    }
    detail::exec(impl_->db, "ROLLBACK TO _sqlpipe_prediction");
    detail::exec(impl_->db, "RELEASE _sqlpipe_prediction");
    impl_->prediction = PS::None;
    SQLPIPE_LOG(impl_->config.on_log, LogLevel::Debug, "prediction rolled back");
}

void Replica::reset() {
    // Rollback any active prediction before resetting.
    if (impl_->prediction != Impl::PredictionState::None) {
        detail::exec(impl_->db, "ROLLBACK TO _sqlpipe_prediction");
        detail::exec(impl_->db, "RELEASE _sqlpipe_prediction");
        impl_->prediction = Impl::PredictionState::None;
    }
    impl_->state = State::Init;
    impl_->seq = detail::read_seq(impl_->db, impl_->config.seq_key);
    SQLPIPE_LOG(impl_->config.on_log, LogLevel::Info, "replica reset to Init at seq={}", impl_->seq);
}

Seq Replica::current_seq() const { return impl_->seq; }

SchemaVersion Replica::schema_version() const {
    const auto* f = impl_->config.table_filter
        ? &*impl_->config.table_filter : nullptr;
    return detail::compute_schema_fingerprint(impl_->db, f);
}

Replica::State Replica::state() const { return impl_->state; }

} // namespace sqlpipe

// ── peer_protocol.cpp ───────────────────────────────────────────

namespace sqlpipe {

std::vector<std::uint8_t> serialize(const PeerMessage& msg) {
    auto inner = serialize(msg.payload);  // [4B len][tag][payload]

    // Read inner length from bytes 0..3.
    std::uint32_t inner_len =
        static_cast<std::uint32_t>(inner[0]) |
        (static_cast<std::uint32_t>(inner[1]) << 8) |
        (static_cast<std::uint32_t>(inner[2]) << 16) |
        (static_cast<std::uint32_t>(inner[3]) << 24);

    // New total = inner_len + 1 (for sender_role byte).
    std::uint32_t total = inner_len + 1;

    std::vector<std::uint8_t> buf;
    buf.reserve(4 + 1 + inner_len);

    // Length prefix.
    buf.push_back(static_cast<std::uint8_t>(total));
    buf.push_back(static_cast<std::uint8_t>(total >> 8));
    buf.push_back(static_cast<std::uint8_t>(total >> 16));
    buf.push_back(static_cast<std::uint8_t>(total >> 24));

    // Sender role.
    buf.push_back(static_cast<std::uint8_t>(msg.sender_role));

    // Tag + payload (skip the inner's 4-byte length prefix).
    buf.insert(buf.end(), inner.begin() + 4, inner.end());

    return buf;
}

PeerMessage deserialize_peer(std::span<const std::uint8_t> buf) {
    if (buf.size() < 6) {
        throw Error(ErrorCode::ProtocolError, "peer message too short");
    }

    // Read total length (bytes 0..3).
    std::uint32_t total =
        static_cast<std::uint32_t>(buf[0]) |
        (static_cast<std::uint32_t>(buf[1]) << 8) |
        (static_cast<std::uint32_t>(buf[2]) << 16) |
        (static_cast<std::uint32_t>(buf[3]) << 24);

    auto role = static_cast<SenderRole>(buf[4]);
    if (role != SenderRole::AsMaster && role != SenderRole::AsReplica) {
        throw Error(ErrorCode::ProtocolError,
                    "invalid sender role: " +
                    std::to_string(static_cast<int>(buf[4])));
    }

    // Reconstruct inner Message buffer: [4B len][tag+payload].
    std::uint32_t msg_len = total - 1;
    std::vector<std::uint8_t> msg_buf;
    msg_buf.reserve(4 + msg_len);
    msg_buf.push_back(static_cast<std::uint8_t>(msg_len));
    msg_buf.push_back(static_cast<std::uint8_t>(msg_len >> 8));
    msg_buf.push_back(static_cast<std::uint8_t>(msg_len >> 16));
    msg_buf.push_back(static_cast<std::uint8_t>(msg_len >> 24));
    msg_buf.insert(msg_buf.end(), buf.begin() + 5, buf.end());

    return PeerMessage{role, deserialize(msg_buf)};
}

} // namespace sqlpipe

// ── peer.cpp ────────────────────────────────────────────────────

namespace sqlpipe {

struct Peer::Impl {
    sqlite3*    db;
    PeerConfig  config;
    Peer::State state = Peer::State::Init;

    std::set<std::string> my_tables;
    std::set<std::string> their_tables;

    std::unique_ptr<Master>  master;
    std::unique_ptr<Replica> replica;

    bool master_handshake_done = false;
    bool replica_handshake_done = false;

    bool is_server() const {
        return config.role == PeerRole::Server;
    }

    void create_master() {
        MasterConfig mc;
        mc.table_filter = my_tables;
        mc.seq_key = "master_seq";
        mc.on_progress = config.on_progress;
        mc.on_schema_mismatch = config.on_schema_mismatch;
        mc.on_log = config.on_log;
        master = std::make_unique<Master>(db, mc);
    }

    void create_replica() {
        ReplicaConfig rc;
        rc.on_conflict = config.on_conflict;
        rc.table_filter = their_tables;
        rc.seq_key = "replica_seq";
        rc.on_progress = config.on_progress;
        rc.on_schema_mismatch = config.on_schema_mismatch;
        rc.on_log = config.on_log;
        replica = std::make_unique<Replica>(db, rc);
    }

    void check_live() {
        if (master_handshake_done && replica_handshake_done) {
            state = Peer::State::Live;
            SQLPIPE_LOG(config.on_log, LogLevel::Info,
                        "peer is live: owning {} tables, replicating {} tables",
                        my_tables.size(), their_tables.size());
        }
    }

    std::set<std::string> complement_tables(
            const std::set<std::string>& subset) {
        std::vector<std::string> all;
        if (config.table_filter) {
            all.assign(config.table_filter->begin(),
                       config.table_filter->end());
        } else {
            all = detail::get_tracked_tables(db);
        }
        std::set<std::string> result;
        for (auto& t : all) {
            if (subset.find(t) == subset.end()) {
                result.insert(std::move(t));
            }
        }
        return result;
    }

    PeerHandleResult handle_as_replica(const PeerMessage& msg) {
        PeerHandleResult result;

        // First AsReplica HelloMsg triggers ownership negotiation.
        if (auto* hello = std::get_if<HelloMsg>(&msg.payload)) {
            if (state == Peer::State::Init ||
                (state == Peer::State::Negotiating && !master)) {
                // Ownership negotiation.
                if (hello->owned_tables.empty()) {
                    state = Peer::State::Error;
                    result.messages.push_back(PeerMessage{
                        SenderRole::AsMaster,
                        ErrorMsg{ErrorCode::ProtocolError,
                                 "peer hello must include owned_tables"}});
                    return result;
                }

                // Reject if client claims tables outside our table_filter.
                if (config.table_filter) {
                    for (const auto& t : hello->owned_tables) {
                        if (config.table_filter->find(t) ==
                                config.table_filter->end()) {
                            state = Peer::State::Error;
                            result.messages.push_back(PeerMessage{
                                SenderRole::AsMaster,
                                ErrorMsg{ErrorCode::OwnershipRejected,
                                    "table '" + t +
                                    "' is not in table_filter"}});
                            return result;
                        }
                    }
                }

                if (config.approve_ownership) {
                    if (!config.approve_ownership(hello->owned_tables)) {
                        state = Peer::State::Error;
                        result.messages.push_back(PeerMessage{
                            SenderRole::AsMaster,
                            ErrorMsg{ErrorCode::OwnershipRejected,
                                     "ownership request rejected"}});
                        return result;
                    }
                }

                // Accept: their tables = what they claimed, ours = complement.
                their_tables = hello->owned_tables;
                my_tables = complement_tables(their_tables);
                state = Peer::State::Diffing;

                create_master();
                create_replica();

                // Patch hello's schema_version to match our Master's so
                // the Master doesn't trigger a spurious schema mismatch.
                HelloMsg patched = *hello;
                patched.schema_version = master->schema_version();
                patched.owned_tables = {};
                patched.last_seq = -1;  // Peer directions use different seq keys

                auto master_resp = master->handle_message(patched);
                for (auto& om : master_resp) {
                    if (std::holds_alternative<DiffReadyMsg>(om)) {
                        master_handshake_done = true;
                    }
                    result.messages.push_back(PeerMessage{
                        SenderRole::AsMaster, std::move(om)});
                }

                // Also initiate our Replica's hello (to sync their tables).
                auto our_hello = replica->hello();
                auto& h = std::get<HelloMsg>(our_hello);
                h.owned_tables = my_tables;
                h.last_seq = -1;  // Peer directions use different seq keys
                result.messages.push_back(PeerMessage{
                    SenderRole::AsReplica, std::move(our_hello)});

                check_live();
                return result;
            }
        }

        // Subsequent AsReplica messages → forward to Master.
        if (!master) {
            result.messages.push_back(PeerMessage{
                SenderRole::AsMaster,
                ErrorMsg{ErrorCode::InvalidState,
                         "master not initialized"}});
            return result;
        }

        auto master_resp = master->handle_message(msg.payload);
        for (auto& om : master_resp) {
            if (std::holds_alternative<DiffReadyMsg>(om)) {
                master_handshake_done = true;
            }
            result.messages.push_back(PeerMessage{
                SenderRole::AsMaster, std::move(om)});
        }

        check_live();
        return result;
    }

    PeerHandleResult handle_as_master(const PeerMessage& msg) {
        PeerHandleResult result;

        if (!replica) {
            result.messages.push_back(PeerMessage{
                SenderRole::AsReplica,
                ErrorMsg{ErrorCode::InvalidState,
                         "replica not initialized"}});
            return result;
        }

        // If this is a HelloMsg, patch schema_version and transition state.
        Message forwarded = msg.payload;
        if (auto* hello = std::get_if<HelloMsg>(&forwarded)) {
            if (state == Peer::State::Negotiating) {
                state = Peer::State::Diffing;
            }
            hello->schema_version = replica->schema_version();
            hello->owned_tables = {};
            hello->last_seq = -1;  // Peer directions use different seq keys
        }

        auto hr = replica->handle_message(forwarded);

        for (auto& om : hr.messages) {
            result.messages.push_back(PeerMessage{
                SenderRole::AsReplica, std::move(om)});
        }
        result.changes = std::move(hr.changes);
        result.subscriptions = std::move(hr.subscriptions);

        // Check if replica just went live.
        if (replica->state() == Replica::State::Live) {
            replica_handshake_done = true;
            check_live();
        }

        return result;
    }
};

// ── Peer public API ─────────────────────────────────────────────────

Peer::Peer(sqlite3* db, PeerConfig config)
    : impl_(std::make_unique<Impl>()) {
    impl_->db = db;
    impl_->config = std::move(config);
    detail::ensure_meta_table(db);
    SQLPIPE_LOG(impl_->config.on_log, LogLevel::Info, "peer created ({})",
                impl_->is_server() ? "server" : "client");
}

Peer::~Peer() = default;
Peer::Peer(Peer&&) noexcept = default;
Peer& Peer::operator=(Peer&&) noexcept = default;

std::vector<PeerMessage> Peer::start() {
    if (impl_->state != State::Init) {
        throw Error(ErrorCode::InvalidState, "start() already called");
    }
    if (impl_->is_server()) {
        throw Error(ErrorCode::InvalidState,
                    "server peer must not call start()");
    }

    // Validate owned_tables ⊆ table_filter when filter is set.
    if (impl_->config.table_filter) {
        for (const auto& t : impl_->config.owned_tables) {
            if (impl_->config.table_filter->find(t) ==
                    impl_->config.table_filter->end()) {
                throw Error(ErrorCode::InvalidState,
                    "owned_tables entry '" + t +
                    "' is not in table_filter");
            }
        }
    }

    impl_->state = State::Negotiating;
    impl_->my_tables = impl_->config.owned_tables;
    impl_->their_tables = impl_->complement_tables(impl_->my_tables);

    impl_->create_master();
    impl_->create_replica();

    auto hello_out = impl_->replica->hello();
    auto& h = std::get<HelloMsg>(hello_out);
    h.owned_tables = impl_->my_tables;
    h.last_seq = -1;  // Peer directions use different seq keys

    return {PeerMessage{SenderRole::AsReplica, std::move(hello_out)}};
}

std::vector<PeerMessage> Peer::flush() {
    if (!impl_->master) return {};
    if (impl_->state != State::Live && impl_->state != State::Diffing) return {};

    auto msgs = impl_->master->flush();
    std::vector<PeerMessage> result;
    result.reserve(msgs.size());
    for (auto& om : msgs) {
        result.push_back(PeerMessage{
            SenderRole::AsMaster, std::move(om)});
    }
    return result;
}

PeerHandleResult Peer::handle_message(const PeerMessage& msg) {
    if (msg.sender_role == SenderRole::AsReplica) {
        return impl_->handle_as_replica(msg);
    } else {
        return impl_->handle_as_master(msg);
    }
}

SubscriptionId Peer::subscribe(const std::string& sql) {
    if (!impl_->replica) {
        throw Error(ErrorCode::InvalidState,
                    "subscribe() requires replica to be initialized");
    }
    return impl_->replica->subscribe(sql);
}

void Peer::unsubscribe(SubscriptionId id) {
    if (!impl_->replica) {
        throw Error(ErrorCode::InvalidState,
                    "unsubscribe() requires replica to be initialized");
    }
    impl_->replica->unsubscribe(id);
}

void Peer::reset() {
    impl_->state = State::Init;
    impl_->master.reset();
    impl_->replica.reset();
    impl_->master_handshake_done = false;
    impl_->replica_handshake_done = false;
    SQLPIPE_LOG(impl_->config.on_log, LogLevel::Info, "peer reset to Init");
}

Peer::State Peer::state() const { return impl_->state; }

const std::set<std::string>& Peer::owned_tables() const {
    return impl_->my_tables;
}

const std::set<std::string>& Peer::remote_tables() const {
    return impl_->their_tables;
}

// ── Convenience utilities ────────────────────────────────────────

void sync_handshake(Master& master, Replica& replica) {
    auto pending = master.handle_message(replica.hello());
    while (!pending.empty()) {
        std::vector<Message> for_master;
        for (const auto& out : pending) {
            auto hr = replica.handle_message(out);
            for_master.insert(for_master.end(),
                              hr.messages.begin(), hr.messages.end());
        }
        pending.clear();
        for (const auto& out : for_master) {
            auto resp = master.handle_message(out);
            pending.insert(pending.end(), resp.begin(), resp.end());
        }
    }
}

// ── Relay ───────────────────────────────────────────────────────────

struct Relay::Impl {
    sqlite3*     db;
    RelayConfig  config;
    Master       master;
    Replica      replica;
    std::map<std::size_t, SinkCallback> sinks;
    std::size_t  next_sink_id = 1;

    Impl(sqlite3* db_, RelayConfig cfg)
        : db(db_),
          config(std::move(cfg)),
          master(db_, make_master_config()),
          replica(db_, make_replica_config()) {}

    MasterConfig make_master_config() {
        MasterConfig mc;
        mc.table_filter = config.table_filter;
        mc.on_log = config.on_log;
        return mc;
    }

    ReplicaConfig make_replica_config() {
        ReplicaConfig rc;
        rc.table_filter = config.table_filter;
        rc.on_conflict = config.on_conflict;
        rc.on_schema_mismatch = config.on_schema_mismatch;
        rc.on_log = config.on_log;
        return rc;
    }

    void broadcast() {
        auto msgs = master.flush();
        for (auto& out : msgs) {
            for (auto& [_, cb] : sinks) {
                cb(out);
            }
        }
    }
};

Relay::Relay(sqlite3* db, RelayConfig config)
    : impl_(std::make_unique<Impl>(db, std::move(config))) {}

Relay::~Relay() = default;
Relay::Relay(Relay&&) noexcept = default;
Relay& Relay::operator=(Relay&&) noexcept = default;

std::size_t Relay::add_sink(SinkCallback cb) {
    auto id = impl_->next_sink_id++;
    impl_->sinks[id] = std::move(cb);
    return id;
}

void Relay::remove_sink(std::size_t id) {
    impl_->sinks.erase(id);
}

Message Relay::hello() {
    return impl_->replica.hello();
}

std::vector<Message> Relay::handle_upstream(const Message& msg) {
    auto hr = impl_->replica.handle_message(msg);
    impl_->broadcast();
    return std::move(hr.messages);
}

std::vector<Message> Relay::handle_downstream(const Message& msg) {
    return impl_->master.handle_message(msg);
}

SubscriptionId Relay::subscribe(const std::string& sql) {
    return impl_->replica.subscribe(sql);
}

void Relay::unsubscribe(SubscriptionId id) {
    impl_->replica.unsubscribe(id);
}

void Relay::reset() {
    impl_->replica.reset();
}

// ── Convenience utilities ────────────────────────────────────────

void sync_handshake(Peer& client, Peer& server) {
    auto pending_for_server = client.start();
    while (!pending_for_server.empty() ||
           client.state() != Peer::State::Live ||
           server.state() != Peer::State::Live) {
        std::vector<PeerMessage> pending_for_client;
        for (const auto& pout : pending_for_server) {
            auto hr = server.handle_message(pout);
            pending_for_client.insert(pending_for_client.end(),
                                      hr.messages.begin(), hr.messages.end());
        }
        pending_for_server.clear();
        for (const auto& pout : pending_for_client) {
            auto hr = client.handle_message(pout);
            pending_for_server.insert(pending_for_server.end(),
                                      hr.messages.begin(), hr.messages.end());
        }
        if (pending_for_server.empty() &&
            (client.state() != Peer::State::Live ||
             server.state() != Peer::State::Live)) {
            break;
        }
    }
}

void sync_handshake(Master& master, Relay& relay) {
    auto pending = master.handle_message(relay.hello());
    while (!pending.empty()) {
        std::vector<Message> for_master;
        for (const auto& out : pending) {
            auto resp = relay.handle_upstream(out);
            for_master.insert(for_master.end(), resp.begin(), resp.end());
        }
        pending.clear();
        for (const auto& out : for_master) {
            auto resp = master.handle_message(out);
            pending.insert(pending.end(), resp.begin(), resp.end());
        }
    }
}

} // namespace sqlpipe
