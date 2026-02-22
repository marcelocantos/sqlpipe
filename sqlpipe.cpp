// Copyright 2026 The sqlpipe Authors
// SPDX-License-Identifier: Apache-2.0
#include "sqlpipe.h"

#include <cassert>
#include <cstring>
#include <spdlog/spdlog.h>

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

/// Create _sqlpipe_log table if it doesn't exist (master only).
void ensure_log_table(sqlite3* db);

/// Read the current sequence number from _sqlpipe_meta.
Seq read_seq(sqlite3* db);

/// Write the sequence number to _sqlpipe_meta.
void write_seq(sqlite3* db, Seq seq);

/// Read PRAGMA schema_version.
SchemaVersion read_schema_version(sqlite3* db);

/// Compute a fingerprint of the user table definitions (excludes internal tables).
/// Uses FNV-1a over the sorted CREATE TABLE SQL.
SchemaVersion compute_schema_fingerprint(sqlite3* db);

/// Get all user table names (excludes _sqlpipe_* and sqlite_* tables).
/// Only includes tables with explicit PRIMARY KEYs.
std::vector<std::string> get_tracked_tables(sqlite3* db);

/// Get the CREATE TABLE SQL for all tracked user tables.
std::string get_schema_sql(sqlite3* db);

/// Get the CREATE TABLE SQL for a single table.
std::string get_table_create_sql(sqlite3* db, const std::string& table);

} // namespace sqlpipe::detail

// ── changeset_iter.h ────────────────────────────────────────────
namespace sqlpipe::detail {

/// Convert a sqlite3_value* to our Value variant.
Value to_value(sqlite3_value* val);

/// Convert an SQLite op code (SQLITE_INSERT/UPDATE/DELETE) to OpType.
OpType sqlite_op_to_optype(int sqlite_op);

/// Iterate a changeset and invoke the callback for each row change.
/// Returns true if all callbacks returned true, false if one returned false.
bool iterate_changeset(const Changeset& data, const ChangeCallback& cb);

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
    put_bytes(buf, cs.data(), static_cast<std::uint32_t>(cs.size()));
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

    std::string read_string() {
        auto len = read_u32();
        check(len);
        std::string s(reinterpret_cast<const char*>(data_ + pos_), len);
        pos_ += len;
        return s;
    }

    Changeset read_changeset() {
        auto len = read_u32();
        check(len);
        Changeset cs(data_ + pos_, data_ + pos_ + len);
        pos_ += len;
        return cs;
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
            put_i64(buf, m.seq);
            put_i32(buf, m.schema_version);
        }
        else if constexpr (std::is_same_v<T, CatchupBeginMsg>) {
            put_u8(buf, static_cast<std::uint8_t>(MessageTag::CatchupBegin));
            put_i64(buf, m.from_seq);
            put_i64(buf, m.to_seq);
        }
        else if constexpr (std::is_same_v<T, ChangesetMsg>) {
            put_u8(buf, static_cast<std::uint8_t>(MessageTag::Changeset));
            put_i64(buf, m.seq);
            put_changeset(buf, m.data);
        }
        else if constexpr (std::is_same_v<T, CatchupEndMsg>) {
            put_u8(buf, static_cast<std::uint8_t>(MessageTag::CatchupEnd));
        }
        else if constexpr (std::is_same_v<T, ResyncBeginMsg>) {
            put_u8(buf, static_cast<std::uint8_t>(MessageTag::ResyncBegin));
            put_i32(buf, m.schema_version);
            put_string(buf, m.schema_sql);
        }
        else if constexpr (std::is_same_v<T, ResyncTableMsg>) {
            put_u8(buf, static_cast<std::uint8_t>(MessageTag::ResyncTable));
            put_string(buf, m.table_name);
            put_changeset(buf, m.data);
        }
        else if constexpr (std::is_same_v<T, ResyncEndMsg>) {
            put_u8(buf, static_cast<std::uint8_t>(MessageTag::ResyncEnd));
            put_i64(buf, m.seq);
        }
        else if constexpr (std::is_same_v<T, AckMsg>) {
            put_u8(buf, static_cast<std::uint8_t>(MessageTag::Ack));
            put_i64(buf, m.seq);
        }
        else if constexpr (std::is_same_v<T, ErrorMsg>) {
            put_u8(buf, static_cast<std::uint8_t>(MessageTag::Error));
            put_i32(buf, static_cast<std::int32_t>(m.code));
            put_string(buf, m.detail);
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

    Reader r(buf);
    auto total_len = r.read_u32();
    (void)total_len;  // already have the full buffer

    auto tag = static_cast<MessageTag>(r.read_u8());

    switch (tag) {
    case MessageTag::Hello: {
        HelloMsg m;
        m.protocol_version = r.read_u32();
        m.seq = r.read_i64();
        m.schema_version = r.read_i32();
        return m;
    }
    case MessageTag::CatchupBegin: {
        CatchupBeginMsg m;
        m.from_seq = r.read_i64();
        m.to_seq = r.read_i64();
        return m;
    }
    case MessageTag::Changeset: {
        ChangesetMsg m;
        m.seq = r.read_i64();
        m.data = r.read_changeset();
        return m;
    }
    case MessageTag::CatchupEnd:
        return CatchupEndMsg{};
    case MessageTag::ResyncBegin: {
        ResyncBeginMsg m;
        m.schema_version = r.read_i32();
        m.schema_sql = r.read_string();
        return m;
    }
    case MessageTag::ResyncTable: {
        ResyncTableMsg m;
        m.table_name = r.read_string();
        m.data = r.read_changeset();
        return m;
    }
    case MessageTag::ResyncEnd: {
        ResyncEndMsg m;
        m.seq = r.read_i64();
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

void ensure_log_table(sqlite3* db) {
    exec(db,
        "CREATE TABLE IF NOT EXISTS _sqlpipe_log ("
        "  seq       INTEGER PRIMARY KEY,"
        "  changeset BLOB NOT NULL,"
        "  created   TEXT NOT NULL DEFAULT (datetime('now'))"
        ")");
}

Seq read_seq(sqlite3* db) {
    auto stmt = prepare(db, "SELECT value FROM _sqlpipe_meta WHERE key='seq'");
    int rc = sqlite3_step(stmt.get());
    if (rc == SQLITE_ROW) {
        return sqlite3_column_int64(stmt.get(), 0);
    }
    return 0;
}

void write_seq(sqlite3* db, Seq seq) {
    auto stmt = prepare(db,
        "INSERT OR REPLACE INTO _sqlpipe_meta (key, value) VALUES ('seq', ?)");
    sqlite3_bind_int64(stmt.get(), 1, seq);
    step_done(db, stmt.get());
}

SchemaVersion read_schema_version(sqlite3* db) {
    auto stmt = prepare(db, "PRAGMA schema_version");
    int rc = sqlite3_step(stmt.get());
    if (rc == SQLITE_ROW) {
        return static_cast<SchemaVersion>(sqlite3_column_int(stmt.get(), 0));
    }
    return 0;
}

SchemaVersion compute_schema_fingerprint(sqlite3* db) {
    auto sql = get_schema_sql(db);
    // FNV-1a 32-bit.
    std::uint32_t hash = 2166136261u;
    for (char c : sql) {
        hash ^= static_cast<std::uint8_t>(c);
        hash *= 16777619u;
    }
    return static_cast<SchemaVersion>(hash);
}

std::vector<std::string> get_tracked_tables(sqlite3* db) {
    // Get tables with explicit PRIMARY KEYs, excluding internal tables.
    // A table has an explicit PK if table_info shows a pk > 0 column.
    auto stmt = prepare(db,
        "SELECT name FROM sqlite_master "
        "WHERE type='table' "
        "  AND name NOT LIKE '_sqlpipe_%' "
        "  AND name NOT LIKE 'sqlite_%' "
        "ORDER BY name");

    std::vector<std::string> tables;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        std::string name(reinterpret_cast<const char*>(
            sqlite3_column_text(stmt.get(), 0)));

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

        if (has_pk) {
            tables.push_back(std::move(name));
        } else {
            SPDLOG_WARN("table '{}' has no explicit PRIMARY KEY, skipping", name);
        }
    }

    return tables;
}

std::string get_schema_sql(sqlite3* db) {
    auto tables = get_tracked_tables(db);
    std::string sql;
    for (const auto& t : tables) {
        if (!sql.empty()) sql += ";\n";
        sql += get_table_create_sql(db, t);
    }
    if (!sql.empty()) sql += ";";
    return sql;
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

bool iterate_changeset(const Changeset& data, const ChangeCallback& cb) {
    if (!cb || data.empty()) return true;

    sqlite3_changeset_iter* iter = nullptr;
    int rc = sqlite3changeset_start(
        &iter,
        static_cast<int>(data.size()),
        const_cast<void*>(static_cast<const void*>(data.data())));
    if (rc != SQLITE_OK) {
        throw Error(ErrorCode::SqliteError, "sqlite3changeset_start failed");
    }

    while (sqlite3changeset_next(iter) == SQLITE_ROW) {
        auto event = extract_event(iter);
        if (!cb(event)) {
            sqlite3changeset_finalize(iter);
            return false;
        }
    }

    sqlite3changeset_finalize(iter);
    return true;
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

    void init() {
        detail::ensure_meta_table(db);
        detail::ensure_log_table(db);
        seq = detail::read_seq(db);
        cached_sv = detail::compute_schema_fingerprint(db);
        scan_tables();
        recreate_session();
        SPDLOG_INFO("master initialized at seq={}", seq);
    }

    void scan_tables() {
        tracked_tables = detail::get_tracked_tables(db);
        SPDLOG_INFO("tracking {} tables", tracked_tables.size());
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

    void store_changeset(Seq s, const Changeset& cs) {
        auto stmt = detail::prepare(db,
            "INSERT INTO _sqlpipe_log (seq, changeset) VALUES (?, ?)");
        sqlite3_bind_int64(stmt.get(), 1, s);
        sqlite3_bind_blob(stmt.get(), 2, cs.data(),
                          static_cast<int>(cs.size()), SQLITE_TRANSIENT);
        detail::step_done(db, stmt.get());
    }

    void prune_log() {
        if (config.max_log_entries == 0) return;

        auto stmt = detail::prepare(db,
            "DELETE FROM _sqlpipe_log WHERE seq <= "
            "(SELECT MAX(seq) - ? FROM _sqlpipe_log)");
        sqlite3_bind_int64(stmt.get(), 1,
                           static_cast<std::int64_t>(config.max_log_entries));
        detail::step_done(db, stmt.get());
    }

    Seq min_log_seq() {
        auto stmt = detail::prepare(db,
            "SELECT MIN(seq) FROM _sqlpipe_log");
        if (sqlite3_step(stmt.get()) == SQLITE_ROW &&
            sqlite3_column_type(stmt.get(), 0) != SQLITE_NULL) {
            return sqlite3_column_int64(stmt.get(), 0);
        }
        return seq + 1;  // empty log
    }

    std::vector<Message> catchup(Seq from, Seq to) {
        std::vector<Message> msgs;
        msgs.push_back(CatchupBeginMsg{from, to});

        auto stmt = detail::prepare(db,
            "SELECT seq, changeset FROM _sqlpipe_log "
            "WHERE seq >= ? AND seq <= ? ORDER BY seq");
        sqlite3_bind_int64(stmt.get(), 1, from);
        sqlite3_bind_int64(stmt.get(), 2, to);

        while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
            ChangesetMsg cm;
            cm.seq = sqlite3_column_int64(stmt.get(), 0);
            auto* blob = static_cast<const std::uint8_t*>(
                sqlite3_column_blob(stmt.get(), 1));
            int blob_len = sqlite3_column_bytes(stmt.get(), 1);
            cm.data.assign(blob, blob + blob_len);
            msgs.push_back(std::move(cm));
        }

        msgs.push_back(CatchupEndMsg{});
        return msgs;
    }

    std::vector<Message> generate_resync() {
        std::vector<Message> msgs;

        auto sv = detail::compute_schema_fingerprint(db);
        auto schema_sql = detail::get_schema_sql(db);
        msgs.push_back(ResyncBeginMsg{sv, schema_sql});

        // Attach an empty in-memory DB with the same schema to diff against.
        detail::exec(db, "ATTACH ':memory:' AS _sqlpipe_empty");

        for (const auto& table : tracked_tables) {
            auto create_sql = detail::get_table_create_sql(db, table);
            // Rewrite CREATE TABLE <name> to CREATE TABLE _sqlpipe_empty.<name>
            std::string prefixed = create_sql;
            auto pos = prefixed.find("CREATE TABLE ");
            if (pos != std::string::npos) {
                prefixed.insert(pos + 13, "_sqlpipe_empty.");
            }
            detail::exec(db, prefixed.c_str());

            // Generate diff: everything in main.<table> not in _sqlpipe_empty.<table>
            sqlite3_session* diff_raw = nullptr;
            int rc = sqlite3session_create(db, "main", &diff_raw);
            if (rc != SQLITE_OK) {
                detail::exec(db, "DETACH _sqlpipe_empty");
                throw Error(ErrorCode::SqliteError,
                            std::string("session_create for diff: ") + sqlite3_errmsg(db));
            }
            detail::SessionGuard diff_session(diff_raw);

            rc = sqlite3session_attach(diff_raw, table.c_str());
            if (rc != SQLITE_OK) {
                detail::exec(db, "DETACH _sqlpipe_empty");
                throw Error(ErrorCode::SqliteError,
                            std::string("session_attach for diff: ") + sqlite3_errmsg(db));
            }

            char* err = nullptr;
            rc = sqlite3session_diff(diff_raw, "_sqlpipe_empty",
                                     table.c_str(), &err);
            if (rc != SQLITE_OK) {
                std::string msg = err ? err : "unknown";
                sqlite3_free(err);
                detail::exec(db, "DETACH _sqlpipe_empty");
                throw Error(ErrorCode::SqliteError,
                            "session_diff: " + msg);
            }

            int n = 0;
            void* p = nullptr;
            sqlite3session_changeset(diff_raw, &n, &p);

            if (n > 0 && p) {
                Changeset cs(static_cast<std::uint8_t*>(p),
                             static_cast<std::uint8_t*>(p) + n);
                sqlite3_free(p);
                msgs.push_back(ResyncTableMsg{table, std::move(cs)});
            } else {
                sqlite3_free(p);
            }
        }

        detail::exec(db, "DETACH _sqlpipe_empty");
        msgs.push_back(ResyncEndMsg{seq});
        return msgs;
    }

    std::vector<Message> handle_hello(const HelloMsg& hello) {
        if (hello.protocol_version != kProtocolVersion) {
            return {ErrorMsg{ErrorCode::ProtocolError,
                "unsupported protocol version: " +
                std::to_string(hello.protocol_version)}};
        }

        auto my_sv = detail::compute_schema_fingerprint(db);

        // Schema mismatch → full resync.
        if (hello.schema_version != my_sv) {
            SPDLOG_INFO("schema mismatch (replica={}, master={}), initiating resync",
                        hello.schema_version, my_sv);
            return generate_resync();
        }

        // Replica is up to date.
        if (hello.seq == seq) {
            SPDLOG_INFO("replica is up to date at seq={}", seq);
            std::vector<Message> msgs;
            msgs.push_back(HelloMsg{kProtocolVersion, seq, my_sv});
            msgs.push_back(CatchupEndMsg{});
            return msgs;
        }

        // Replica is ahead — shouldn't happen in master-replica.
        if (hello.seq > seq) {
            return {ErrorMsg{ErrorCode::ProtocolError,
                "replica seq " + std::to_string(hello.seq) +
                " ahead of master seq " + std::to_string(seq)}};
        }

        // Replica is behind. Can we catch up from the log?
        Seq needed_from = hello.seq + 1;
        Seq log_min = min_log_seq();

        if (log_min <= needed_from) {
            SPDLOG_INFO("catchup from seq {} to {}", needed_from, seq);
            std::vector<Message> msgs;
            msgs.push_back(HelloMsg{kProtocolVersion, seq, my_sv});
            auto catchup_msgs = catchup(needed_from, seq);
            msgs.insert(msgs.end(), catchup_msgs.begin(), catchup_msgs.end());
            return msgs;
        }

        // Log doesn't go back far enough — full resync.
        SPDLOG_INFO("log starts at seq={}, need seq={}, initiating resync",
                    log_min, needed_from);
        return generate_resync();
    }
};

// ── Public API ──────────────────────────────────────────────────────

Master::Master(sqlite3* db, MasterConfig config)
    : impl_(std::make_unique<Impl>()) {
    impl_->db = db;
    impl_->config = config;
    impl_->init();
}

Master::~Master() = default;
Master::Master(Master&&) noexcept = default;
Master& Master::operator=(Master&&) noexcept = default;

std::vector<Message> Master::flush() {
    // Check if schema changed; re-scan tables if so.
    auto sv = detail::compute_schema_fingerprint(impl_->db);
    if (sv != impl_->cached_sv) {
        impl_->cached_sv = sv;
        impl_->scan_tables();
        impl_->recreate_session();
    }

    auto cs = impl_->extract_changeset();
    if (cs.empty()) return {};

    impl_->recreate_session();

    impl_->seq++;
    detail::write_seq(impl_->db, impl_->seq);
    impl_->store_changeset(impl_->seq, cs);
    impl_->prune_log();

    SPDLOG_DEBUG("flushed changeset seq={} ({} bytes)", impl_->seq, cs.size());

    return {ChangesetMsg{impl_->seq, std::move(cs)}};
}

std::vector<Message> Master::handle_message(const Message& msg) {
    return std::visit([&](const auto& m) -> std::vector<Message> {
        using T = std::decay_t<decltype(m)>;

        if constexpr (std::is_same_v<T, HelloMsg>) {
            return impl_->handle_hello(m);
        }
        else if constexpr (std::is_same_v<T, AckMsg>) {
            SPDLOG_DEBUG("replica acked seq={}", m.seq);
            return {};
        }
        else {
            return {ErrorMsg{ErrorCode::InvalidState,
                "unexpected message from replica"}};
        }
    }, msg);
}

Seq Master::current_seq() const { return impl_->seq; }

SchemaVersion Master::schema_version() const {
    return detail::compute_schema_fingerprint(impl_->db);
}

std::vector<Message> Master::generate_resync() {
    return impl_->generate_resync();
}

} // namespace sqlpipe

// ── replica.cpp ─────────────────────────────────────────────────

namespace sqlpipe {

struct Replica::Impl {
    sqlite3*       db;
    ReplicaConfig  config;
    Seq            seq = 0;
    Replica::State state = Replica::State::Init;

    void init() {
        detail::ensure_meta_table(db);
        seq = detail::read_seq(db);
        SPDLOG_INFO("replica initialized at seq={}", seq);
    }

    void apply_changeset(const Changeset& data, Seq new_seq) {
        // Apply via SQLite session extension.
        int rc = sqlite3changeset_apply(
            db,
            static_cast<int>(data.size()),
            const_cast<void*>(static_cast<const void*>(data.data())),
            // Filter callback: accept all tables.
            nullptr,
            // Conflict callback.
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

        // Emit change events post-apply.
        detail::iterate_changeset(data, config.on_change);

        // Update sequence number.
        seq = new_seq;
        detail::write_seq(db, seq);
    }

    void begin_resync(const ResyncBeginMsg& msg) {
        if (config.on_resync_begin) {
            config.on_resync_begin();
        }

        // Drop all user tables and recreate from master schema.
        auto tables = detail::get_tracked_tables(db);
        for (const auto& t : tables) {
            detail::exec(db, ("DROP TABLE IF EXISTS \"" + t + "\"").c_str());
        }

        // Also drop any tables that the master has but we don't.
        detail::exec(db, msg.schema_sql.c_str());

        SPDLOG_INFO("resync: schema applied, sv={}", msg.schema_version);
    }

    void apply_resync_table(const ResyncTableMsg& msg) {
        if (msg.data.empty()) return;

        int rc = sqlite3changeset_apply(
            db,
            static_cast<int>(msg.data.size()),
            const_cast<void*>(static_cast<const void*>(msg.data.data())),
            nullptr,
            [](void*, int, sqlite3_changeset_iter*) -> int {
                // During resync, force all changes through.
                return SQLITE_CHANGESET_REPLACE;
            },
            nullptr);

        if (rc != SQLITE_OK) {
            throw Error(ErrorCode::SqliteError,
                        std::string("resync table apply: ") + sqlite3_errmsg(db));
        }

        // Emit change events for resync data too.
        detail::iterate_changeset(msg.data, config.on_change);

        SPDLOG_DEBUG("resync: applied table '{}'", msg.table_name);
    }

    void end_resync(const ResyncEndMsg& msg) {
        seq = msg.seq;
        detail::write_seq(db, seq);
        state = Replica::State::Live;

        if (config.on_resync_end) {
            config.on_resync_end();
        }

        SPDLOG_INFO("resync complete, now at seq={}", seq);
    }
};

// ── Public API ──────────────────────────────────────────────────────

Replica::Replica(sqlite3* db, ReplicaConfig config)
    : impl_(std::make_unique<Impl>()) {
    impl_->db = db;
    impl_->config = std::move(config);
    impl_->init();
}

Replica::~Replica() = default;
Replica::Replica(Replica&&) noexcept = default;
Replica& Replica::operator=(Replica&&) noexcept = default;

Message Replica::hello() const {
    impl_->state = State::Handshake;
    return HelloMsg{kProtocolVersion, impl_->seq,
                    detail::compute_schema_fingerprint(impl_->db)};
}

std::vector<Message> Replica::handle_message(const Message& msg) {
    return std::visit([&](const auto& m) -> std::vector<Message> {
        using T = std::decay_t<decltype(m)>;

        if constexpr (std::is_same_v<T, HelloMsg>) {
            if (impl_->state != State::Handshake) {
                impl_->state = State::Error;
                return {ErrorMsg{ErrorCode::InvalidState,
                    "received HelloMsg in unexpected state"}};
            }
            if (m.protocol_version != kProtocolVersion) {
                impl_->state = State::Error;
                return {ErrorMsg{ErrorCode::ProtocolError,
                    "unsupported protocol version"}};
            }
            // Master responded; wait for CatchupBegin/CatchupEnd/ResyncBegin.
            return {};
        }
        else if constexpr (std::is_same_v<T, CatchupBeginMsg>) {
            impl_->state = State::Catchup;
            SPDLOG_INFO("catchup: expecting seq {} to {}",
                        m.from_seq, m.to_seq);
            return {};
        }
        else if constexpr (std::is_same_v<T, ChangesetMsg>) {
            if (impl_->state != State::Catchup &&
                impl_->state != State::Live) {
                impl_->state = State::Error;
                return {ErrorMsg{ErrorCode::InvalidState,
                    "received ChangesetMsg in unexpected state"}};
            }
            impl_->apply_changeset(m.data, m.seq);
            SPDLOG_DEBUG("applied changeset seq={}", m.seq);
            return {AckMsg{m.seq}};
        }
        else if constexpr (std::is_same_v<T, CatchupEndMsg>) {
            impl_->state = State::Live;
            SPDLOG_INFO("catchup complete, entering live mode at seq={}",
                        impl_->seq);
            return {};
        }
        else if constexpr (std::is_same_v<T, ResyncBeginMsg>) {
            impl_->state = State::Resync;
            impl_->begin_resync(m);
            return {};
        }
        else if constexpr (std::is_same_v<T, ResyncTableMsg>) {
            if (impl_->state != State::Resync) {
                impl_->state = State::Error;
                return {ErrorMsg{ErrorCode::InvalidState,
                    "received ResyncTableMsg outside resync"}};
            }
            impl_->apply_resync_table(m);
            return {};
        }
        else if constexpr (std::is_same_v<T, ResyncEndMsg>) {
            if (impl_->state != State::Resync) {
                impl_->state = State::Error;
                return {ErrorMsg{ErrorCode::InvalidState,
                    "received ResyncEndMsg outside resync"}};
            }
            impl_->end_resync(m);
            return {AckMsg{m.seq}};
        }
        else if constexpr (std::is_same_v<T, ErrorMsg>) {
            impl_->state = State::Error;
            SPDLOG_ERROR("received error from master: {}", m.detail);
            return {};
        }
        else {
            return {ErrorMsg{ErrorCode::InvalidState,
                "unexpected message type from master"}};
        }
    }, msg);
}

Seq Replica::current_seq() const { return impl_->seq; }

SchemaVersion Replica::schema_version() const {
    return detail::compute_schema_fingerprint(impl_->db);
}

Replica::State Replica::state() const { return impl_->state; }

} // namespace sqlpipe
