// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0
//
// Emscripten C API shim for sqlpipe. Provides extern "C" functions
// callable from JavaScript via cwrap/ccall. Messages cross the boundary
// as serialized bytes (wire format).

#include "../dist/sqlpipe.h"

#include <cstring>
#include <new>
#include <vector>

#include <emscripten/emscripten.h>
#include <sqlite3.h>

// ── Opaque handle structs ───────────────────────────────────────

struct sqlpipe_master {
    sqlpipe::Master impl;
    sqlpipe_master(sqlite3* db, sqlpipe::MasterConfig cfg)
        : impl(db, std::move(cfg)) {}
};

struct sqlpipe_replica {
    sqlpipe::Replica impl;
    sqlpipe_replica(sqlite3* db, sqlpipe::ReplicaConfig cfg)
        : impl(db, std::move(cfg)) {}
};

struct sqlpipe_peer {
    sqlpipe::Peer impl;
    sqlpipe_peer(sqlite3* db, sqlpipe::PeerConfig cfg)
        : impl(db, std::move(cfg)) {}
};

struct sqlpipe_query_watch {
    sqlpipe::QueryWatch impl;
    sqlpipe_query_watch(sqlite3* db) : impl(db) {}
};

// ── Byte buffer ─────────────────────────────────────────────────

struct sqlpipe_buf {
    uint8_t* data;
    size_t   len;
};

// ── Error ───────────────────────────────────────────────────────

struct sqlpipe_error {
    int   code;  // 0 = OK, >0 = sqlpipe::ErrorCode
    char* msg;   // Heap-allocated, or NULL.
};

// ── Callback signatures ─────────────────────────────────────────

typedef void (*sqlpipe_progress_fn)(
    int ctx, uint8_t phase, const char* table,
    int64_t done, int64_t total);

typedef int (*sqlpipe_schema_mismatch_fn)(
    int ctx, int32_t remote_sv, int32_t local_sv,
    const char* remote_schema_sql);

typedef uint8_t (*sqlpipe_conflict_fn)(
    int ctx, uint8_t conflict_type,
    const uint8_t* event_data, size_t event_len);

typedef int (*sqlpipe_approve_ownership_fn)(
    int ctx, const char** tables, size_t table_count);

typedef void (*sqlpipe_log_fn)(
    int ctx, uint8_t level, const char* message);

// ── Encoding helpers ────────────────────────────────────────────

namespace {

using Buf = std::vector<uint8_t>;

void put_u8(Buf& b, uint8_t v) { b.push_back(v); }

void put_u32(Buf& b, uint32_t v) {
    b.push_back(v & 0xFF);
    b.push_back((v >> 8) & 0xFF);
    b.push_back((v >> 16) & 0xFF);
    b.push_back((v >> 24) & 0xFF);
}

void put_u64(Buf& b, uint64_t v) {
    for (int i = 0; i < 8; ++i)
        b.push_back((v >> (i * 8)) & 0xFF);
}

void put_i64(Buf& b, int64_t v) { put_u64(b, static_cast<uint64_t>(v)); }

void put_string(Buf& b, const std::string& s) {
    put_u32(b, static_cast<uint32_t>(s.size()));
    b.insert(b.end(), s.begin(), s.end());
}

void put_bytes(Buf& b, const uint8_t* data, size_t len) {
    b.insert(b.end(), data, data + len);
}

void encode_value(Buf& b, const sqlpipe::Value& v) {
    if (std::holds_alternative<std::monostate>(v)) {
        put_u8(b, 0x00);
    } else if (auto* p = std::get_if<int64_t>(&v)) {
        put_u8(b, 0x01);
        put_i64(b, *p);
    } else if (auto* p = std::get_if<double>(&v)) {
        put_u8(b, 0x02);
        uint64_t bits;
        std::memcpy(&bits, p, 8);
        put_u64(b, bits);
    } else if (auto* p = std::get_if<std::string>(&v)) {
        put_u8(b, 0x03);
        put_string(b, *p);
    } else if (auto* p = std::get_if<std::vector<uint8_t>>(&v)) {
        put_u8(b, 0x04);
        put_u32(b, static_cast<uint32_t>(p->size()));
        put_bytes(b, p->data(), p->size());
    }
}

void encode_change_event(Buf& b, const sqlpipe::ChangeEvent& e) {
    put_string(b, e.table);
    put_u8(b, static_cast<uint8_t>(e.op));
    put_u32(b, static_cast<uint32_t>(e.pk_flags.size()));
    for (bool f : e.pk_flags) put_u8(b, f ? 1 : 0);
    put_u32(b, static_cast<uint32_t>(e.old_values.size()));
    for (auto& v : e.old_values) encode_value(b, v);
    put_u32(b, static_cast<uint32_t>(e.new_values.size()));
    for (auto& v : e.new_values) encode_value(b, v);
}

void encode_query_result(Buf& b, const sqlpipe::QueryResult& qr) {
    put_u64(b, qr.id);
    put_u32(b, static_cast<uint32_t>(qr.columns.size()));
    for (auto& col : qr.columns) put_string(b, col);
    put_u32(b, static_cast<uint32_t>(qr.rows.size()));
    for (auto& row : qr.rows) {
        for (auto& v : row) encode_value(b, v);
    }
}

Buf encode_messages(const std::vector<sqlpipe::Message>& msgs) {
    Buf b;
    put_u32(b, static_cast<uint32_t>(msgs.size()));
    for (auto& msg : msgs) {
        auto wire = sqlpipe::serialize(msg);
        put_bytes(b, wire.data(), wire.size());
    }
    return b;
}

Buf encode_peer_messages(const std::vector<sqlpipe::PeerMessage>& msgs) {
    Buf b;
    put_u32(b, static_cast<uint32_t>(msgs.size()));
    for (auto& msg : msgs) {
        auto wire = sqlpipe::serialize(msg);
        put_bytes(b, wire.data(), wire.size());
    }
    return b;
}

Buf encode_handle_result(const sqlpipe::HandleResult& hr) {
    Buf b;
    put_u32(b, static_cast<uint32_t>(hr.messages.size()));
    for (auto& msg : hr.messages) {
        auto wire = sqlpipe::serialize(msg);
        put_bytes(b, wire.data(), wire.size());
    }
    put_u32(b, static_cast<uint32_t>(hr.changes.size()));
    for (auto& ce : hr.changes) encode_change_event(b, ce);
    put_u32(b, static_cast<uint32_t>(hr.subscriptions.size()));
    for (auto& qr : hr.subscriptions) encode_query_result(b, qr);
    return b;
}

Buf encode_peer_handle_result(const sqlpipe::PeerHandleResult& phr) {
    Buf b;
    put_u32(b, static_cast<uint32_t>(phr.messages.size()));
    for (auto& msg : phr.messages) {
        auto wire = sqlpipe::serialize(msg);
        put_bytes(b, wire.data(), wire.size());
    }
    put_u32(b, static_cast<uint32_t>(phr.changes.size()));
    for (auto& ce : phr.changes) encode_change_event(b, ce);
    put_u32(b, static_cast<uint32_t>(phr.subscriptions.size()));
    for (auto& qr : phr.subscriptions) encode_query_result(b, qr);
    return b;
}

sqlpipe_buf to_buf(Buf&& v) {
    if (v.empty()) return {nullptr, 0};
    auto* p = static_cast<uint8_t*>(std::malloc(v.size()));
    std::memcpy(p, v.data(), v.size());
    return {p, v.size()};
}

sqlpipe_error ok() { return {0, nullptr}; }

sqlpipe_error make_error(const sqlpipe::Error& e) {
    return {static_cast<int>(e.code()), strdup(e.what())};
}

sqlpipe_error make_error(int code, const char* msg) {
    return {code, strdup(msg)};
}

// Convert callback + context to C++ config helpers.

sqlpipe::MasterConfig to_master_config(
    const char** table_filter, size_t table_filter_count,
    const char* seq_key, int64_t bucket_size,
    sqlpipe_progress_fn on_progress, int progress_ctx,
    sqlpipe_schema_mismatch_fn on_schema_mismatch, int schema_mismatch_ctx,
    sqlpipe_log_fn on_log, int log_ctx) {

    sqlpipe::MasterConfig mc;
    if (table_filter && table_filter_count > 0) {
        std::set<std::string> tf;
        for (size_t i = 0; i < table_filter_count; ++i)
            tf.insert(table_filter[i]);
        mc.table_filter = std::move(tf);
    }
    if (seq_key) mc.seq_key = seq_key;
    if (bucket_size > 0) mc.bucket_size = bucket_size;
    if (on_progress) {
        auto fn = on_progress;
        auto ctx = progress_ctx;
        mc.on_progress = [fn, ctx](const sqlpipe::DiffProgress& dp) {
            fn(ctx, static_cast<uint8_t>(dp.phase),
               dp.table.c_str(), dp.items_done, dp.items_total);
        };
    }
    if (on_schema_mismatch) {
        auto fn = on_schema_mismatch;
        auto ctx = schema_mismatch_ctx;
        mc.on_schema_mismatch = [fn, ctx](
            sqlpipe::SchemaVersion rsv, sqlpipe::SchemaVersion lsv,
            const std::string& rsql) -> bool {
            return fn(ctx, rsv, lsv, rsql.c_str()) != 0;
        };
    }
    if (on_log) {
        auto fn = on_log;
        auto ctx = log_ctx;
        mc.on_log = [fn, ctx](sqlpipe::LogLevel level, std::string_view msg) {
            fn(ctx, static_cast<uint8_t>(level),
               std::string(msg).c_str());
        };
    }
    return mc;
}

sqlpipe::ReplicaConfig to_replica_config(
    sqlpipe_conflict_fn on_conflict, int conflict_ctx,
    const char** table_filter, size_t table_filter_count,
    const char* seq_key, int64_t bucket_size,
    sqlpipe_progress_fn on_progress, int progress_ctx,
    sqlpipe_schema_mismatch_fn on_schema_mismatch, int schema_mismatch_ctx,
    sqlpipe_log_fn on_log, int log_ctx) {

    sqlpipe::ReplicaConfig rc;
    if (on_conflict) {
        auto fn = on_conflict;
        auto ctx = conflict_ctx;
        rc.on_conflict = [fn, ctx](
            sqlpipe::ConflictType ct,
            const sqlpipe::ChangeEvent& ce) -> sqlpipe::ConflictAction {
            Buf eb;
            encode_change_event(eb, ce);
            uint8_t action = fn(ctx, static_cast<uint8_t>(ct), eb.data(), eb.size());
            return static_cast<sqlpipe::ConflictAction>(action);
        };
    }
    if (table_filter && table_filter_count > 0) {
        std::set<std::string> tf;
        for (size_t i = 0; i < table_filter_count; ++i)
            tf.insert(table_filter[i]);
        rc.table_filter = std::move(tf);
    }
    if (seq_key) rc.seq_key = seq_key;
    if (bucket_size > 0) rc.bucket_size = bucket_size;
    if (on_progress) {
        auto fn = on_progress;
        auto ctx = progress_ctx;
        rc.on_progress = [fn, ctx](const sqlpipe::DiffProgress& dp) {
            fn(ctx, static_cast<uint8_t>(dp.phase),
               dp.table.c_str(), dp.items_done, dp.items_total);
        };
    }
    if (on_schema_mismatch) {
        auto fn = on_schema_mismatch;
        auto ctx = schema_mismatch_ctx;
        rc.on_schema_mismatch = [fn, ctx](
            sqlpipe::SchemaVersion rsv, sqlpipe::SchemaVersion lsv,
            const std::string& rsql) -> bool {
            return fn(ctx, rsv, lsv, rsql.c_str()) != 0;
        };
    }
    if (on_log) {
        auto fn = on_log;
        auto ctx = log_ctx;
        rc.on_log = [fn, ctx](sqlpipe::LogLevel level, std::string_view msg) {
            fn(ctx, static_cast<uint8_t>(level),
               std::string(msg).c_str());
        };
    }
    return rc;
}

sqlpipe::PeerConfig to_peer_config(
    const char** owned_tables, size_t owned_table_count,
    const char** table_filter, size_t table_filter_count,
    sqlpipe_approve_ownership_fn approve_ownership, int approve_ownership_ctx,
    sqlpipe_conflict_fn on_conflict, int conflict_ctx,
    sqlpipe_progress_fn on_progress, int progress_ctx,
    sqlpipe_schema_mismatch_fn on_schema_mismatch, int schema_mismatch_ctx,
    sqlpipe_log_fn on_log, int log_ctx) {

    sqlpipe::PeerConfig pc;
    for (size_t i = 0; i < owned_table_count; ++i)
        pc.owned_tables.insert(owned_tables[i]);
    if (table_filter && table_filter_count > 0) {
        std::set<std::string> tf;
        for (size_t i = 0; i < table_filter_count; ++i)
            tf.insert(table_filter[i]);
        pc.table_filter = std::move(tf);
    }
    if (approve_ownership) {
        auto fn = approve_ownership;
        auto ctx = approve_ownership_ctx;
        pc.approve_ownership = [fn, ctx](
            const std::set<std::string>& tables) -> bool {
            std::vector<const char*> ptrs;
            ptrs.reserve(tables.size());
            for (auto& t : tables) ptrs.push_back(t.c_str());
            return fn(ctx, ptrs.data(), ptrs.size()) != 0;
        };
    }
    if (on_conflict) {
        auto fn = on_conflict;
        auto ctx = conflict_ctx;
        pc.on_conflict = [fn, ctx](
            sqlpipe::ConflictType ct,
            const sqlpipe::ChangeEvent& ce) -> sqlpipe::ConflictAction {
            Buf eb;
            encode_change_event(eb, ce);
            uint8_t action = fn(ctx, static_cast<uint8_t>(ct), eb.data(), eb.size());
            return static_cast<sqlpipe::ConflictAction>(action);
        };
    }
    if (on_progress) {
        auto fn = on_progress;
        auto ctx = progress_ctx;
        pc.on_progress = [fn, ctx](const sqlpipe::DiffProgress& dp) {
            fn(ctx, static_cast<uint8_t>(dp.phase),
               dp.table.c_str(), dp.items_done, dp.items_total);
        };
    }
    if (on_schema_mismatch) {
        auto fn = on_schema_mismatch;
        auto ctx = schema_mismatch_ctx;
        pc.on_schema_mismatch = [fn, ctx](
            sqlpipe::SchemaVersion rsv, sqlpipe::SchemaVersion lsv,
            const std::string& rsql) -> bool {
            return fn(ctx, rsv, lsv, rsql.c_str()) != 0;
        };
    }
    if (on_log) {
        auto fn = on_log;
        auto ctx = log_ctx;
        pc.on_log = [fn, ctx](sqlpipe::LogLevel level, std::string_view msg) {
            fn(ctx, static_cast<uint8_t>(level),
               std::string(msg).c_str());
        };
    }
    return pc;
}

} // anonymous namespace

// ── Exported C API ──────────────────────────────────────────────

extern "C" {

// ── Memory management ───────────────────────────────────────────

EMSCRIPTEN_KEEPALIVE
void sqlpipe_free_buf(uint8_t* data) {
    std::free(data);
}

EMSCRIPTEN_KEEPALIVE
void sqlpipe_free_error(char* msg) {
    std::free(msg);
}

EMSCRIPTEN_KEEPALIVE
void sqlpipe_free_string_array(char** arr, size_t count) {
    if (!arr) return;
    for (size_t i = 0; i < count; ++i) std::free(arr[i]);
    std::free(arr);
}

// ── SQLite database management ──────────────────────────────────

EMSCRIPTEN_KEEPALIVE
sqlite3* sqlpipe_db_open(const char* path) {
    sqlite3* db = nullptr;
    sqlite3_open(path, &db);
    return db;
}

EMSCRIPTEN_KEEPALIVE
void sqlpipe_db_close(sqlite3* db) {
    sqlite3_close(db);
}

EMSCRIPTEN_KEEPALIVE
int sqlpipe_db_exec(sqlite3* db, const char* sql) {
    return sqlite3_exec(db, sql, nullptr, nullptr, nullptr);
}

EMSCRIPTEN_KEEPALIVE
const char* sqlpipe_db_errmsg(sqlite3* db) {
    return sqlite3_errmsg(db);
}

// Serialize a database to a byte buffer. Caller must free data with sqlite3_free().
// Returns 0 on success, sets *out_data and *out_len.
EMSCRIPTEN_KEEPALIVE
int sqlpipe_db_serialize(sqlite3* db, uint8_t** out_data, int64_t* out_len) {
    sqlite3_int64 sz = 0;
    uint8_t* data = sqlite3_serialize(db, "main", &sz, 0);
    if (!data) return 1;
    *out_data = data;
    *out_len = sz;
    return 0;
}

// Deserialize a byte buffer into an open :memory: database.
// The buffer is copied; caller retains ownership.
EMSCRIPTEN_KEEPALIVE
int sqlpipe_db_deserialize(sqlite3* db, const uint8_t* data, int64_t len) {
    // sqlite3_deserialize takes ownership of the buffer, so we must
    // provide a sqlite3_malloc'd copy.
    uint8_t* copy = static_cast<uint8_t*>(sqlite3_malloc64(len));
    if (!copy) return SQLITE_NOMEM;
    std::memcpy(copy, data, len);
    return sqlite3_deserialize(db, "main", copy, len, len,
        SQLITE_DESERIALIZE_FREEONCLOSE | SQLITE_DESERIALIZE_RESIZEABLE);
}

// Free a buffer allocated by sqlite3_serialize.
EMSCRIPTEN_KEEPALIVE
void sqlpipe_db_free_serialized(uint8_t* data) {
    sqlite3_free(data);
}

// ── One-shot query ──────────────────────────────────────────────

EMSCRIPTEN_KEEPALIVE
int sqlpipe_db_query(sqlite3* db, const char* sql,
                     sqlpipe_buf* out, sqlpipe_error* err) {
    try {
        auto qr = sqlpipe::query(db, sql);
        Buf b;
        encode_query_result(b, qr);
        *out = to_buf(std::move(b));
        *err = ok();
        return 0;
    } catch (const sqlpipe::Error& e) { *err = make_error(e); return static_cast<int>(e.code()); }
      catch (const std::exception& e) { *err = make_error(1, e.what()); return 1; }
}

// ── Result accessors ────────────────────────────────────────────
// These let JS read fields from heap-allocated result structs.

EMSCRIPTEN_KEEPALIVE
int sqlpipe_error_code(sqlpipe_error* e) { return e->code; }

EMSCRIPTEN_KEEPALIVE
const char* sqlpipe_error_msg(sqlpipe_error* e) { return e->msg; }

EMSCRIPTEN_KEEPALIVE
uint8_t* sqlpipe_buf_data(sqlpipe_buf* b) { return b->data; }

EMSCRIPTEN_KEEPALIVE
size_t sqlpipe_buf_len(sqlpipe_buf* b) { return b->len; }

// ── Master ──────────────────────────────────────────────────────

EMSCRIPTEN_KEEPALIVE
int sqlpipe_master_new(
    sqlite3* db,
    const char** table_filter, size_t table_filter_count,
    const char* seq_key, int64_t bucket_size,
    sqlpipe_progress_fn on_progress, int progress_ctx,
    sqlpipe_schema_mismatch_fn on_schema_mismatch, int schema_mismatch_ctx,
    sqlpipe_log_fn on_log, int log_ctx,
    sqlpipe_master** out, sqlpipe_error* err) {
    try {
        *out = new sqlpipe_master(db, to_master_config(
            table_filter, table_filter_count, seq_key, bucket_size,
            on_progress, progress_ctx,
            on_schema_mismatch, schema_mismatch_ctx,
            on_log, log_ctx));
        *err = ok();
        return 0;
    } catch (const sqlpipe::Error& e) {
        *out = nullptr;
        *err = make_error(e);
        return e.code() == sqlpipe::ErrorCode::Ok ? 1 : static_cast<int>(e.code());
    } catch (const std::exception& e) {
        *out = nullptr;
        *err = make_error(1, e.what());
        return 1;
    }
}

EMSCRIPTEN_KEEPALIVE
void sqlpipe_master_free(sqlpipe_master* m) { delete m; }

EMSCRIPTEN_KEEPALIVE
int sqlpipe_master_flush(sqlpipe_master* m, sqlpipe_buf* out, sqlpipe_error* err) {
    try {
        auto msgs = m->impl.flush();
        *out = to_buf(encode_messages(msgs));
        *err = ok();
        return 0;
    } catch (const sqlpipe::Error& e) { *err = make_error(e); return static_cast<int>(e.code()); }
      catch (const std::exception& e) { *err = make_error(1, e.what()); return 1; }
}

EMSCRIPTEN_KEEPALIVE
int sqlpipe_master_handle_message(
    sqlpipe_master* m,
    const uint8_t* msg_data, size_t msg_len,
    sqlpipe_buf* out, sqlpipe_error* err) {
    try {
        auto msg = sqlpipe::deserialize(
            std::span<const uint8_t>(msg_data, msg_len));
        auto resp = m->impl.handle_message(msg);
        *out = to_buf(encode_messages(resp));
        *err = ok();
        return 0;
    } catch (const sqlpipe::Error& e) { *err = make_error(e); return static_cast<int>(e.code()); }
      catch (const std::exception& e) { *err = make_error(1, e.what()); return 1; }
}

EMSCRIPTEN_KEEPALIVE
int64_t sqlpipe_master_current_seq(sqlpipe_master* m) {
    return m->impl.current_seq();
}

EMSCRIPTEN_KEEPALIVE
int32_t sqlpipe_master_schema_version(sqlpipe_master* m) {
    return m->impl.schema_version();
}

// ── Replica ─────────────────────────────────────────────────────

EMSCRIPTEN_KEEPALIVE
int sqlpipe_replica_new(
    sqlite3* db,
    sqlpipe_conflict_fn on_conflict, int conflict_ctx,
    const char** table_filter, size_t table_filter_count,
    const char* seq_key, int64_t bucket_size,
    sqlpipe_progress_fn on_progress, int progress_ctx,
    sqlpipe_schema_mismatch_fn on_schema_mismatch, int schema_mismatch_ctx,
    sqlpipe_log_fn on_log, int log_ctx,
    sqlpipe_replica** out, sqlpipe_error* err) {
    try {
        *out = new sqlpipe_replica(db, to_replica_config(
            on_conflict, conflict_ctx,
            table_filter, table_filter_count, seq_key, bucket_size,
            on_progress, progress_ctx,
            on_schema_mismatch, schema_mismatch_ctx,
            on_log, log_ctx));
        *err = ok();
        return 0;
    } catch (const sqlpipe::Error& e) {
        *out = nullptr;
        *err = make_error(e);
        return static_cast<int>(e.code());
    } catch (const std::exception& e) {
        *out = nullptr;
        *err = make_error(1, e.what());
        return 1;
    }
}

EMSCRIPTEN_KEEPALIVE
void sqlpipe_replica_free(sqlpipe_replica* r) { delete r; }

EMSCRIPTEN_KEEPALIVE
int sqlpipe_replica_hello(sqlpipe_replica* r, sqlpipe_buf* out, sqlpipe_error* err) {
    try {
        auto msg = r->impl.hello();
        auto wire = sqlpipe::serialize(msg);
        *out = to_buf(Buf(wire.begin(), wire.end()));
        *err = ok();
        return 0;
    } catch (const sqlpipe::Error& e) { *err = make_error(e); return static_cast<int>(e.code()); }
      catch (const std::exception& e) { *err = make_error(1, e.what()); return 1; }
}

EMSCRIPTEN_KEEPALIVE
int sqlpipe_replica_handle_message(
    sqlpipe_replica* r,
    const uint8_t* msg_data, size_t msg_len,
    sqlpipe_buf* out, sqlpipe_error* err) {
    try {
        auto msg = sqlpipe::deserialize(
            std::span<const uint8_t>(msg_data, msg_len));
        auto hr = r->impl.handle_message(msg);
        *out = to_buf(encode_handle_result(hr));
        *err = ok();
        return 0;
    } catch (const sqlpipe::Error& e) { *err = make_error(e); return static_cast<int>(e.code()); }
      catch (const std::exception& e) { *err = make_error(1, e.what()); return 1; }
}

EMSCRIPTEN_KEEPALIVE
int sqlpipe_replica_subscribe(
    sqlpipe_replica* r, const char* sql,
    uint64_t* out_id, sqlpipe_error* err) {
    try {
        *out_id = r->impl.subscribe(sql);
        *err = ok();
        return 0;
    } catch (const sqlpipe::Error& e) { *err = make_error(e); return static_cast<int>(e.code()); }
      catch (const std::exception& e) { *err = make_error(1, e.what()); return 1; }
}

EMSCRIPTEN_KEEPALIVE
int sqlpipe_replica_unsubscribe(sqlpipe_replica* r, uint64_t id, sqlpipe_error* err) {
    try {
        r->impl.unsubscribe(id);
        *err = ok();
        return 0;
    } catch (const sqlpipe::Error& e) { *err = make_error(e); return static_cast<int>(e.code()); }
      catch (const std::exception& e) { *err = make_error(1, e.what()); return 1; }
}

EMSCRIPTEN_KEEPALIVE
void sqlpipe_replica_reset(sqlpipe_replica* r) {
    r->impl.reset();
}

EMSCRIPTEN_KEEPALIVE
uint8_t sqlpipe_replica_state(sqlpipe_replica* r) {
    return static_cast<uint8_t>(r->impl.state());
}

EMSCRIPTEN_KEEPALIVE
int64_t sqlpipe_replica_current_seq(sqlpipe_replica* r) {
    return r->impl.current_seq();
}

EMSCRIPTEN_KEEPALIVE
int32_t sqlpipe_replica_schema_version(sqlpipe_replica* r) {
    return r->impl.schema_version();
}

// ── Peer ────────────────────────────────────────────────────────

EMSCRIPTEN_KEEPALIVE
int sqlpipe_peer_new(
    sqlite3* db,
    const char** owned_tables, size_t owned_table_count,
    const char** table_filter, size_t table_filter_count,
    sqlpipe_approve_ownership_fn approve_ownership, int approve_ownership_ctx,
    sqlpipe_conflict_fn on_conflict, int conflict_ctx,
    sqlpipe_progress_fn on_progress, int progress_ctx,
    sqlpipe_schema_mismatch_fn on_schema_mismatch, int schema_mismatch_ctx,
    sqlpipe_log_fn on_log, int log_ctx,
    sqlpipe_peer** out, sqlpipe_error* err) {
    try {
        *out = new sqlpipe_peer(db, to_peer_config(
            owned_tables, owned_table_count,
            table_filter, table_filter_count,
            approve_ownership, approve_ownership_ctx,
            on_conflict, conflict_ctx,
            on_progress, progress_ctx,
            on_schema_mismatch, schema_mismatch_ctx,
            on_log, log_ctx));
        *err = ok();
        return 0;
    } catch (const sqlpipe::Error& e) {
        *out = nullptr;
        *err = make_error(e);
        return static_cast<int>(e.code());
    } catch (const std::exception& e) {
        *out = nullptr;
        *err = make_error(1, e.what());
        return 1;
    }
}

EMSCRIPTEN_KEEPALIVE
void sqlpipe_peer_free(sqlpipe_peer* p) { delete p; }

EMSCRIPTEN_KEEPALIVE
int sqlpipe_peer_start(sqlpipe_peer* p, sqlpipe_buf* out, sqlpipe_error* err) {
    try {
        auto msgs = p->impl.start();
        *out = to_buf(encode_peer_messages(msgs));
        *err = ok();
        return 0;
    } catch (const sqlpipe::Error& e) { *err = make_error(e); return static_cast<int>(e.code()); }
      catch (const std::exception& e) { *err = make_error(1, e.what()); return 1; }
}

EMSCRIPTEN_KEEPALIVE
int sqlpipe_peer_flush(sqlpipe_peer* p, sqlpipe_buf* out, sqlpipe_error* err) {
    try {
        auto msgs = p->impl.flush();
        *out = to_buf(encode_peer_messages(msgs));
        *err = ok();
        return 0;
    } catch (const sqlpipe::Error& e) { *err = make_error(e); return static_cast<int>(e.code()); }
      catch (const std::exception& e) { *err = make_error(1, e.what()); return 1; }
}

EMSCRIPTEN_KEEPALIVE
int sqlpipe_peer_handle_message(
    sqlpipe_peer* p,
    const uint8_t* msg_data, size_t msg_len,
    sqlpipe_buf* out, sqlpipe_error* err) {
    try {
        auto msg = sqlpipe::deserialize_peer(
            std::span<const uint8_t>(msg_data, msg_len));
        auto phr = p->impl.handle_message(msg);
        *out = to_buf(encode_peer_handle_result(phr));
        *err = ok();
        return 0;
    } catch (const sqlpipe::Error& e) { *err = make_error(e); return static_cast<int>(e.code()); }
      catch (const std::exception& e) { *err = make_error(1, e.what()); return 1; }
}

EMSCRIPTEN_KEEPALIVE
int sqlpipe_peer_subscribe(
    sqlpipe_peer* p, const char* sql,
    uint64_t* out_id, sqlpipe_error* err) {
    try {
        *out_id = p->impl.subscribe(sql);
        *err = ok();
        return 0;
    } catch (const sqlpipe::Error& e) { *err = make_error(e); return static_cast<int>(e.code()); }
      catch (const std::exception& e) { *err = make_error(1, e.what()); return 1; }
}

EMSCRIPTEN_KEEPALIVE
int sqlpipe_peer_unsubscribe(sqlpipe_peer* p, uint64_t id, sqlpipe_error* err) {
    try {
        p->impl.unsubscribe(id);
        *err = ok();
        return 0;
    } catch (const sqlpipe::Error& e) { *err = make_error(e); return static_cast<int>(e.code()); }
      catch (const std::exception& e) { *err = make_error(1, e.what()); return 1; }
}

EMSCRIPTEN_KEEPALIVE
void sqlpipe_peer_reset(sqlpipe_peer* p) {
    p->impl.reset();
}

EMSCRIPTEN_KEEPALIVE
uint8_t sqlpipe_peer_state(sqlpipe_peer* p) {
    return static_cast<uint8_t>(p->impl.state());
}

// ── QueryWatch ──────────────────────────────────────────────────

EMSCRIPTEN_KEEPALIVE
sqlpipe_query_watch* sqlpipe_query_watch_new(sqlite3* db) {
    return new sqlpipe_query_watch(db);
}

EMSCRIPTEN_KEEPALIVE
void sqlpipe_query_watch_free(sqlpipe_query_watch* w) { delete w; }

EMSCRIPTEN_KEEPALIVE
int sqlpipe_query_watch_subscribe(
    sqlpipe_query_watch* w, const char* sql,
    uint64_t* out_id, sqlpipe_error* err) {
    try {
        *out_id = w->impl.subscribe(sql);
        *err = ok();
        return 0;
    } catch (const sqlpipe::Error& e) { *err = make_error(e); return static_cast<int>(e.code()); }
      catch (const std::exception& e) { *err = make_error(1, e.what()); return 1; }
}

EMSCRIPTEN_KEEPALIVE
void sqlpipe_query_watch_unsubscribe(sqlpipe_query_watch* w, uint64_t id) {
    w->impl.unsubscribe(id);
}

EMSCRIPTEN_KEEPALIVE
int sqlpipe_query_watch_notify(
    sqlpipe_query_watch* w,
    const char** tables, size_t table_count,
    sqlpipe_buf* out, sqlpipe_error* err) {
    try {
        std::set<std::string> ts;
        for (size_t i = 0; i < table_count; ++i)
            ts.insert(tables[i]);
        auto results = w->impl.notify(ts);
        Buf b;
        put_u32(b, static_cast<uint32_t>(results.size()));
        for (auto& qr : results) encode_query_result(b, qr);
        *out = to_buf(std::move(b));
        *err = ok();
        return 0;
    } catch (const sqlpipe::Error& e) { *err = make_error(e); return static_cast<int>(e.code()); }
      catch (const std::exception& e) { *err = make_error(1, e.what()); return 1; }
}

EMSCRIPTEN_KEEPALIVE
int sqlpipe_query_watch_empty(sqlpipe_query_watch* w) {
    return w->impl.empty() ? 1 : 0;
}

// ── Sync handshake (convenience) ────────────────────────────────

EMSCRIPTEN_KEEPALIVE
int sqlpipe_sync_handshake(
    sqlpipe_master* m, sqlpipe_replica* r, sqlpipe_error* err) {
    try {
        sqlpipe::sync_handshake(m->impl, r->impl);
        *err = ok();
        return 0;
    } catch (const sqlpipe::Error& e) { *err = make_error(e); return static_cast<int>(e.code()); }
      catch (const std::exception& e) { *err = make_error(1, e.what()); return 1; }
}

EMSCRIPTEN_KEEPALIVE
int sqlpipe_sync_handshake_peer(
    sqlpipe_peer* client, sqlpipe_peer* server, sqlpipe_error* err) {
    try {
        sqlpipe::sync_handshake(client->impl, server->impl);
        *err = ok();
        return 0;
    } catch (const sqlpipe::Error& e) { *err = make_error(e); return static_cast<int>(e.code()); }
      catch (const std::exception& e) { *err = make_error(1, e.what()); return 1; }
}

// ── Version ─────────────────────────────────────────────────────

EMSCRIPTEN_KEEPALIVE
const char* sqlpipe_version() {
    return SQLPIPE_VERSION;
}

EMSCRIPTEN_KEEPALIVE
uint32_t sqlpipe_protocol_version() {
    return sqlpipe::kProtocolVersion;
}

} // extern "C"
