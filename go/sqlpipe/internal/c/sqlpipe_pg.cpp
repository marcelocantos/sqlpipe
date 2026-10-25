// Copyright 2026 The sqlpipe Authors
// SPDX-License-Identifier: Apache-2.0
//
// Postgres engine: transactional outbox capture, DML changeset, bigint-PK
// diff. Compiled into dist/sqlpipe.cpp when SQLPIPE_HAVE_POSTGRES is set.

#ifndef EMSCRIPTEN
#ifdef SQLPIPE_HAVE_POSTGRES

#include <libpq-fe.h>
#include <cctype>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <map>
#include <sstream>

namespace sqlpipe {
namespace {

void pg_throw(PGresult* r, const std::string& what) {
    std::string msg = r ? PQresultErrorMessage(r) : "no result";
    if (r) PQclear(r);
    throw Error(ErrorCode::PostgresError, what + ": " + msg);
}

void pg_exec(PGconn* c, const std::string& sql) {
    PGresult* r = PQexec(c, sql.c_str());
    auto st = PQresultStatus(r);
    if (st != PGRES_COMMAND_OK && st != PGRES_TUPLES_OK)
        pg_throw(r, "exec");
    PQclear(r);
}

PGresult* pg_query(PGconn* c, const std::string& sql) {
    PGresult* r = PQexec(c, sql.c_str());
    if (PQresultStatus(r) != PGRES_TUPLES_OK)
        pg_throw(r, "query");
    return r;
}

std::string pg_quote_id(const std::string& name) {
    std::string out = "\"";
    for (char ch : name) {
        if (ch == '"') out += "\"\"";
        else out += ch;
    }
    out += '"';
    return out;
}

std::string pg_quote_lit(const std::string& s) {
    std::string out = "'";
    for (char ch : s) {
        if (ch == '\'') out += "''";
        else out += ch;
    }
    out += "'";
    return out;
}

bool pg_type_allowed(const std::string& t) {
    static const char* ok[] = {
        "bigint", "integer", "smallint", "int8", "int4", "int2",
        "text", "varchar", "character varying", "bytea",
        "double precision", "real", "float8", "float4",
        "boolean", "bool",
        "date",
        "timestamp without time zone", "timestamp with time zone",
        "timestamp", "timestamptz",
        "uuid", "jsonb", "json",
    };
    std::string lower;
    lower.reserve(t.size());
    for (char ch : t)
        lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
    auto paren = lower.find('(');
    if (paren != std::string::npos) lower = lower.substr(0, paren);
    while (!lower.empty() && lower.back() == ' ') lower.pop_back();
    for (auto* a : ok)
        if (lower == a) return true;
    return false;
}

bool pg_type_int(const std::string& t) {
    std::string lower;
    for (char ch : t)
        lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
    return lower == "bigint" || lower == "integer" || lower == "smallint"
        || lower == "int8" || lower == "int4" || lower == "int2";
}

struct PgCol {
    std::string name;
    std::string type;
};

struct PgTable {
    std::string name;
    std::string pk;
    std::vector<PgCol> cols;
};

std::vector<PgTable> pg_discover(PGconn* c, const std::set<std::string>* filter) {
    auto* r = pg_query(c,
        "SELECT c.relname FROM pg_class c "
        "JOIN pg_namespace n ON n.oid = c.relnamespace "
        "WHERE n.nspname = 'public' AND c.relkind = 'r' "
        "AND c.relname NOT LIKE '\\_%' "
        "ORDER BY c.relname");
    std::vector<std::string> names;
    for (int i = 0; i < PQntuples(r); ++i)
        names.emplace_back(PQgetvalue(r, i, 0));
    PQclear(r);

    std::vector<PgTable> tables;
    for (const auto& name : names) {
        if (filter && !filter->count(name)) continue;
        PgTable t;
        t.name = name;
        auto* pk = pg_query(c,
            "SELECT a.attname, format_type(a.atttypid, a.atttypmod) "
            "FROM pg_index i "
            "JOIN pg_attribute a ON a.attrelid = i.indrelid "
            " AND a.attnum = ANY (i.indkey) "
            "JOIN pg_class c ON c.oid = i.indrelid "
            "JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE n.nspname = 'public' AND c.relname = " + pg_quote_lit(name) +
            " AND i.indisprimary ORDER BY array_position(i.indkey, a.attnum)");
        int npk = PQntuples(pk);
        if (npk != 1) {
            PQclear(pk);
            throw Error(ErrorCode::UnsupportedTable,
                        "table " + name + " must have a single BIGINT-compatible PK");
        }
        t.pk = PQgetvalue(pk, 0, 0);
        std::string pk_type = PQgetvalue(pk, 0, 1);
        PQclear(pk);
        if (!pg_type_int(pk_type)) {
            throw Error(ErrorCode::UnsupportedTable,
                        "table " + name + " PK '" + t.pk +
                        "' is not BIGINT-compatible (" + pk_type + ")");
        }

        auto* cols = pg_query(c,
            "SELECT a.attname, format_type(a.atttypid, a.atttypmod) "
            "FROM pg_attribute a "
            "JOIN pg_class c ON c.oid = a.attrelid "
            "JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE n.nspname = 'public' AND c.relname = " + pg_quote_lit(name) +
            " AND a.attnum > 0 AND NOT a.attisdropped "
            "ORDER BY a.attnum");
        for (int i = 0; i < PQntuples(cols); ++i) {
            PgCol col{PQgetvalue(cols, i, 0), PQgetvalue(cols, i, 1)};
            if (!pg_type_allowed(col.type)) {
                PQclear(cols);
                throw Error(ErrorCode::UnsupportedTable,
                            "table " + name + " column '" + col.name +
                            "' has unsupported type " + col.type);
            }
            t.cols.push_back(std::move(col));
        }
        PQclear(cols);
        tables.push_back(std::move(t));
    }
    return tables;
}

int pq_exec_cb(void* ctx, const char* sql, char** err_msg) {
    auto* c = static_cast<PGconn*>(ctx);
    PGresult* r = PQexec(c, sql);
    auto st = PQresultStatus(r);
    if (st != PGRES_COMMAND_OK && st != PGRES_TUPLES_OK) {
        if (err_msg) *err_msg = strdup(PQresultErrorMessage(r));
        PQclear(r);
        return 1;
    }
    PQclear(r);
    return 0;
}

int pq_query_cb(void* ctx, const char* sql,
                void (*row)(void* row_ctx, int ncols, const char* const* cols),
                void* row_ctx, char** err_msg) {
    auto* c = static_cast<PGconn*>(ctx);
    PGresult* r = PQexec(c, sql);
    if (PQresultStatus(r) != PGRES_TUPLES_OK) {
        if (err_msg) *err_msg = strdup(PQresultErrorMessage(r));
        PQclear(r);
        return 1;
    }
    int nt = PQntuples(r);
    int nc = PQnfields(r);
    std::vector<const char*> cols(static_cast<size_t>(nc));
    for (int i = 0; i < nt; ++i) {
        for (int j = 0; j < nc; ++j)
            cols[static_cast<size_t>(j)] =
                PQgetisnull(r, i, j) ? nullptr : PQgetvalue(r, i, j);
        row(row_ctx, nc, cols.data());
    }
    PQclear(r);
    return 0;
}

sqlift_exec make_sqlift_exec(PGconn* c) {
    return sqlift_exec{c, pq_exec_cb, pq_query_cb};
}

void pg_ensure_catalog(PGconn* c) {
    pg_exec(c, "CREATE SCHEMA IF NOT EXISTS sqlpipe");
    // Default search_path is `"$user", public`. If the connecting role is
    // also named sqlpipe, unqualified DDL after this point would create
    // user tables inside the catalog schema. sqlift fingerprints `public`.
    pg_exec(c, "SET search_path TO public");
    pg_exec(c,
        "CREATE TABLE IF NOT EXISTS sqlpipe.meta ("
        "key text PRIMARY KEY, value text NOT NULL)");
    pg_exec(c,
        "CREATE TABLE IF NOT EXISTS sqlpipe.outbox ("
        "id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,"
        "table_name text NOT NULL,"
        "op smallint NOT NULL,"
        "pk bigint NOT NULL,"
        "old_row jsonb,"
        "new_row jsonb)");
    pg_exec(c,
        "CREATE OR REPLACE FUNCTION sqlpipe.outbox_trig() RETURNS trigger AS $$\n"
        "DECLARE pk bigint;\n"
        "BEGIN\n"
        "  IF TG_OP = 'DELETE' THEN\n"
        "    pk := (to_jsonb(OLD) ->> TG_ARGV[0])::bigint;\n"
        "    INSERT INTO sqlpipe.outbox(table_name, op, pk, old_row, new_row)\n"
        "    VALUES (TG_TABLE_NAME, 3, pk, to_jsonb(OLD), NULL);\n"
        "    RETURN OLD;\n"
        "  ELSIF TG_OP = 'UPDATE' THEN\n"
        "    pk := (to_jsonb(NEW) ->> TG_ARGV[0])::bigint;\n"
        "    INSERT INTO sqlpipe.outbox(table_name, op, pk, old_row, new_row)\n"
        "    VALUES (TG_TABLE_NAME, 2, pk, to_jsonb(OLD), to_jsonb(NEW));\n"
        "    RETURN NEW;\n"
        "  ELSE\n"
        "    pk := (to_jsonb(NEW) ->> TG_ARGV[0])::bigint;\n"
        "    INSERT INTO sqlpipe.outbox(table_name, op, pk, old_row, new_row)\n"
        "    VALUES (TG_TABLE_NAME, 1, pk, NULL, to_jsonb(NEW));\n"
        "    RETURN NEW;\n"
        "  END IF;\n"
        "END;\n"
        "$$ LANGUAGE plpgsql");
}

void pg_install_triggers(PGconn* c, const std::vector<PgTable>& tables) {
    for (const auto& t : tables) {
        std::string trig = "sqlpipe_outbox_" + t.name;
        pg_exec(c, "DROP TRIGGER IF EXISTS " + pg_quote_id(trig) +
                       " ON " + pg_quote_id(t.name));
        pg_exec(c,
            "CREATE TRIGGER " + pg_quote_id(trig) +
            " AFTER INSERT OR UPDATE OR DELETE ON " + pg_quote_id(t.name) +
            " FOR EACH ROW EXECUTE FUNCTION sqlpipe.outbox_trig(" +
            pg_quote_lit(t.pk) + ")");
    }
}

Seq pg_read_seq(PGconn* c, const std::string& key) {
    auto* r = pg_query(c,
        "SELECT value FROM sqlpipe.meta WHERE key = " + pg_quote_lit(key));
    Seq s = 0;
    if (PQntuples(r) == 1)
        s = static_cast<Seq>(std::stoll(PQgetvalue(r, 0, 0)));
    PQclear(r);
    return s;
}

void pg_write_seq(PGconn* c, Seq seq, const std::string& key) {
    pg_exec(c,
        "INSERT INTO sqlpipe.meta (key, value) VALUES (" +
        pg_quote_lit(key) + ", " + pg_quote_lit(std::to_string(seq)) + ") "
        "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value");
}

void pg_put_u16(std::vector<std::uint8_t>& buf, std::uint16_t v) {
    buf.push_back(static_cast<std::uint8_t>(v));
    buf.push_back(static_cast<std::uint8_t>(v >> 8));
}

void pg_put_u64(std::vector<std::uint8_t>& buf, std::uint64_t v) {
    for (int i = 0; i < 8; ++i)
        buf.push_back(static_cast<std::uint8_t>(v >> (i * 8)));
}

void pg_put_str(std::vector<std::uint8_t>& buf, const std::string& s) {
    auto n = static_cast<std::uint32_t>(s.size());
    for (int i = 0; i < 4; ++i)
        buf.push_back(static_cast<std::uint8_t>(n >> (i * 8)));
    buf.insert(buf.end(), s.begin(), s.end());
}

std::uint16_t pg_get_u16(const std::uint8_t*& p, const std::uint8_t* end) {
    if (p + 2 > end) throw Error(ErrorCode::ProtocolError, "short u16");
    std::uint16_t v = static_cast<std::uint16_t>(p[0] | (p[1] << 8));
    p += 2;
    return v;
}

std::uint32_t pg_get_u32(const std::uint8_t*& p, const std::uint8_t* end) {
    if (p + 4 > end) throw Error(ErrorCode::ProtocolError, "short u32");
    std::uint32_t v = static_cast<std::uint32_t>(
        p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24));
    p += 4;
    return v;
}

std::int64_t pg_get_i64(const std::uint8_t*& p, const std::uint8_t* end) {
    if (p + 8 > end) throw Error(ErrorCode::ProtocolError, "short i64");
    std::uint64_t u = 0;
    for (int i = 0; i < 8; ++i)
        u |= static_cast<std::uint64_t>(p[i]) << (i * 8);
    p += 8;
    return static_cast<std::int64_t>(u);
}

std::string pg_get_str(const std::uint8_t*& p, const std::uint8_t* end) {
    auto n = pg_get_u32(p, end);
    if (p + n > end) throw Error(ErrorCode::ProtocolError, "short str");
    std::string s(reinterpret_cast<const char*>(p), n);
    p += n;
    return s;
}

Value value_from_text(const PgCol& col, const char* text, bool isnull) {
    if (isnull || !text) return std::monostate{};
    if (pg_type_int(col.type))
        return static_cast<std::int64_t>(std::stoll(text));
    std::string lower;
    for (char ch : col.type)
        lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
    if (lower == "double precision" || lower == "real" ||
        lower == "float8" || lower == "float4")
        return std::stod(text);
    if (lower == "boolean" || lower == "bool")
        return static_cast<std::int64_t>(text[0] == 't' || text[0] == '1');
    if (lower == "bytea") {
        // PQgetvalue for bytea text is \xHEX
        std::vector<std::uint8_t> bytes;
        if (text[0] == '\\' && text[1] == 'x') {
            const char* h = text + 2;
            auto nib = [](char c) {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return 0;
            };
            while (h[0] && h[1]) {
                bytes.push_back(static_cast<std::uint8_t>((nib(h[0]) << 4) | nib(h[1])));
                h += 2;
            }
        }
        return bytes;
    }
    return std::string(text);
}

void put_pg_value(std::vector<std::uint8_t>& buf, const Value& v) {
    std::visit([&](const auto& val) {
        using T = std::decay_t<decltype(val)>;
        if constexpr (std::is_same_v<T, std::monostate>) {
            buf.push_back(0x00);
        } else if constexpr (std::is_same_v<T, std::int64_t>) {
            buf.push_back(0x01);
            pg_put_u64(buf, static_cast<std::uint64_t>(val));
        } else if constexpr (std::is_same_v<T, double>) {
            buf.push_back(0x02);
            std::uint64_t bits = 0;
            std::memcpy(&bits, &val, 8);
            pg_put_u64(buf, bits);
        } else if constexpr (std::is_same_v<T, std::string>) {
            buf.push_back(0x03);
            pg_put_str(buf, val);
        } else if constexpr (std::is_same_v<T, std::vector<std::uint8_t>>) {
            buf.push_back(0x04);
            auto n = static_cast<std::uint32_t>(val.size());
            for (int i = 0; i < 4; ++i)
                buf.push_back(static_cast<std::uint8_t>(n >> (i * 8)));
            buf.insert(buf.end(), val.begin(), val.end());
        }
    }, v);
}

Value get_pg_value(const std::uint8_t*& p, const std::uint8_t* end) {
    if (p >= end) throw Error(ErrorCode::ProtocolError, "short tag");
    auto tag = *p++;
    switch (tag) {
    case 0x00: return std::monostate{};
    case 0x01: return pg_get_i64(p, end);
    case 0x02: {
        auto bits = static_cast<std::uint64_t>(pg_get_i64(p, end));
        double d;
        std::memcpy(&d, &bits, 8);
        return d;
    }
    case 0x03: return pg_get_str(p, end);
    case 0x04: {
        auto n = pg_get_u32(p, end);
        if (p + n > end) throw Error(ErrorCode::ProtocolError, "short bytes");
        std::vector<std::uint8_t> b(p, p + n);
        p += n;
        return b;
    }
    case 0x05: {
        if (p >= end) throw Error(ErrorCode::ProtocolError, "short bool");
        return static_cast<std::int64_t>(*p++);
    }
    default:
        throw Error(ErrorCode::ProtocolError,
                    "unknown pg value tag " + std::to_string(tag));
    }
}

struct PgField {
    std::string name;
    Value value;
};

struct PgOp {
    OpType op;
    std::string table;
    std::int64_t pk;
    std::vector<PgField> old_row;
    std::vector<PgField> new_row;
};

Changeset encode_pg_ops(const std::vector<PgOp>& ops) {
    std::vector<std::uint8_t> buf;
    buf.push_back(1); // changeset_version
    auto n = static_cast<std::uint32_t>(ops.size());
    for (int i = 0; i < 4; ++i)
        buf.push_back(static_cast<std::uint8_t>(n >> (i * 8)));
    for (const auto& op : ops) {
        buf.push_back(static_cast<std::uint8_t>(op.op));
        pg_put_str(buf, op.table);
        pg_put_u64(buf, static_cast<std::uint64_t>(op.pk));
        pg_put_u16(buf, static_cast<std::uint16_t>(op.old_row.size()));
        for (const auto& f : op.old_row) {
            pg_put_str(buf, f.name);
            put_pg_value(buf, f.value);
        }
        pg_put_u16(buf, static_cast<std::uint16_t>(op.new_row.size()));
        for (const auto& f : op.new_row) {
            pg_put_str(buf, f.name);
            put_pg_value(buf, f.value);
        }
    }
    return buf;
}

std::vector<PgOp> decode_pg_ops(const Changeset& data) {
    if (data.empty()) return {};
    const auto* p = data.data();
    const auto* end = p + data.size();
    if (p >= end || *p++ != 1)
        throw Error(ErrorCode::ProtocolError, "bad pg changeset version");
    auto n = pg_get_u32(p, end);
    std::vector<PgOp> ops;
    ops.reserve(n);
    for (std::uint32_t i = 0; i < n; ++i) {
        if (p >= end) throw Error(ErrorCode::ProtocolError, "short op");
        PgOp op;
        op.op = static_cast<OpType>(*p++);
        op.table = pg_get_str(p, end);
        op.pk = pg_get_i64(p, end);
        auto nold = pg_get_u16(p, end);
        for (std::uint16_t j = 0; j < nold; ++j)
            op.old_row.push_back({pg_get_str(p, end), get_pg_value(p, end)});
        auto nnew = pg_get_u16(p, end);
        for (std::uint16_t j = 0; j < nnew; ++j)
            op.new_row.push_back({pg_get_str(p, end), get_pg_value(p, end)});
        ops.push_back(std::move(op));
    }
    return ops;
}

const PgTable* find_table(const std::vector<PgTable>& tables,
                          const std::string& name) {
    for (const auto& t : tables)
        if (t.name == name) return &t;
    return nullptr;
}

std::vector<PgField> fields_from_jsonb(PGconn* c, const PgTable& t,
                                       const char* jsonb, bool isnull) {
    std::vector<PgField> out;
    if (isnull || !jsonb) return out;
    for (const auto& col : t.cols) {
        std::string sql = "SELECT (" + pg_quote_lit(jsonb) + "::jsonb ->> " +
                          pg_quote_lit(col.name) + ") IS NULL, " +
                          pg_quote_lit(jsonb) + "::jsonb ->> " +
                          pg_quote_lit(col.name);
        auto* r = pg_query(c, sql);
        bool is_null = PQgetvalue(r, 0, 0)[0] == 't';
        const char* text = PQgetvalue(r, 0, 1);
        out.push_back({col.name, value_from_text(col, text, is_null)});
        PQclear(r);
    }
    return out;
}

std::string bind_value_sql(const Value& v) {
    return std::visit([](const auto& val) -> std::string {
        using T = std::decay_t<decltype(val)>;
        if constexpr (std::is_same_v<T, std::monostate>)
            return "NULL";
        else if constexpr (std::is_same_v<T, std::int64_t>)
            return std::to_string(val);
        else if constexpr (std::is_same_v<T, double>) {
            std::ostringstream oss;
            oss.precision(17);
            oss << val;
            return oss.str();
        } else if constexpr (std::is_same_v<T, std::string>)
            return pg_quote_lit(val);
        else {
            std::string hex = "'\\x";
            static const char* d = "0123456789abcdef";
            for (auto b : val) {
                hex.push_back(d[b >> 4]);
                hex.push_back(d[b & 0xf]);
            }
            hex += "'::bytea";
            return hex;
        }
    }, v);
}

void apply_pg_op(PGconn* c, const PgOp& op, ReplicaConfig& cfg,
                 const std::vector<PgTable>& tables) {
    auto* tbl = find_table(tables, op.table);
    auto pk_col = [&]() -> std::string {
        if (tbl && !tbl->pk.empty()) return tbl->pk;
        if (!op.new_row.empty()) {
            for (const auto& f : op.new_row) {
                if (auto* i = std::get_if<std::int64_t>(&f.value);
                    i && *i == op.pk)
                    return f.name;
            }
            return op.new_row[0].name;
        }
        if (!op.old_row.empty()) {
            for (const auto& f : op.old_row) {
                if (auto* i = std::get_if<std::int64_t>(&f.value);
                    i && *i == op.pk)
                    return f.name;
            }
            return op.old_row[0].name;
        }
        return "id";
    };

    if (op.op == OpType::Insert) {
        auto* r = pg_query(c,
            "SELECT 1 FROM " + pg_quote_id(op.table) + " WHERE " +
            pg_quote_id(pk_col()) + " = " + std::to_string(op.pk));
        bool conflict = PQntuples(r) > 0;
        PQclear(r);
        if (conflict) {
            if (!cfg.on_conflict) {
                throw Error(ErrorCode::ProtocolError,
                            "insert conflict on " + op.table);
            }
            ChangeEvent ev;
            ev.table = op.table;
            ev.op = OpType::Insert;
            if (cfg.on_conflict(ConflictType::Conflict, ev) == ConflictAction::Abort)
                throw Error(ErrorCode::ProtocolError, "insert conflict aborted");
            return;
        }
        std::string sql = "INSERT INTO " + pg_quote_id(op.table) + " (";
        std::string vals = " VALUES (";
        for (size_t i = 0; i < op.new_row.size(); ++i) {
            if (i) { sql += ", "; vals += ", "; }
            sql += pg_quote_id(op.new_row[i].name);
            vals += bind_value_sql(op.new_row[i].value);
        }
        sql += ")" + vals + ")";
        pg_exec(c, sql);
    } else if (op.op == OpType::Update) {
        auto* r = pg_query(c,
            "SELECT 1 FROM " + pg_quote_id(op.table) + " WHERE " +
            pg_quote_id(pk_col()) + " = " + std::to_string(op.pk));
        bool found = PQntuples(r) > 0;
        PQclear(r);
        if (!found) {
            if (!cfg.on_conflict) {
                throw Error(ErrorCode::ProtocolError,
                            "update not found on " + op.table);
            }
            ChangeEvent ev;
            ev.table = op.table;
            ev.op = OpType::Update;
            if (cfg.on_conflict(ConflictType::NotFound, ev) == ConflictAction::Abort)
                throw Error(ErrorCode::ProtocolError, "update not found aborted");
            return;
        }
        std::string sql = "UPDATE " + pg_quote_id(op.table) + " SET ";
        for (size_t i = 0; i < op.new_row.size(); ++i) {
            if (i) sql += ", ";
            sql += pg_quote_id(op.new_row[i].name) + " = " +
                   bind_value_sql(op.new_row[i].value);
        }
        sql += " WHERE " + pg_quote_id(pk_col()) + " = " + std::to_string(op.pk);
        pg_exec(c, sql);
    } else {
        pg_exec(c, "DELETE FROM " + pg_quote_id(op.table) +
                       " WHERE " + pg_quote_id(pk_col()) + " = " +
                       std::to_string(op.pk));
    }
}

std::uint64_t hash_pg_row(const std::vector<Value>& vals) {
    std::uint64_t h = detail::kFnv64Offset;
    for (const auto& v : vals)
        detail::hash_value(h, v);
    return h;
}

std::vector<Value> load_row_values(PGconn* c, const PgTable& t,
                                   std::int64_t pk) {
    std::string sql = "SELECT ";
    for (size_t i = 0; i < t.cols.size(); ++i) {
        if (i) sql += ", ";
        sql += pg_quote_id(t.cols[i].name);
    }
    sql += " FROM " + pg_quote_id(t.name) + " WHERE " +
           pg_quote_id(t.pk) + " = " + std::to_string(pk);
    auto* r = pg_query(c, sql);
    std::vector<Value> vals;
    if (PQntuples(r) == 1) {
        for (size_t i = 0; i < t.cols.size(); ++i)
            vals.push_back(value_from_text(
                t.cols[i], PQgetvalue(r, 0, static_cast<int>(i)),
                PQgetisnull(r, 0, static_cast<int>(i))));
    }
    PQclear(r);
    return vals;
}

std::vector<detail::RowHashInfo> pg_row_hashes(PGconn* c, const PgTable& t,
                                       std::int64_t lo, std::int64_t hi) {
    std::string sql = "SELECT " + pg_quote_id(t.pk);
    for (const auto& col : t.cols)
        sql += ", " + pg_quote_id(col.name);
    sql += " FROM " + pg_quote_id(t.name) + " WHERE " + pg_quote_id(t.pk) +
           " >= " + std::to_string(lo) + " AND " + pg_quote_id(t.pk) +
           " <= " + std::to_string(hi) + " ORDER BY " + pg_quote_id(t.pk);
    auto* r = pg_query(c, sql);
    std::vector<detail::RowHashInfo> out;
    int n = PQntuples(r);
    for (int i = 0; i < n; ++i) {
        std::int64_t pk = std::stoll(PQgetvalue(r, i, 0));
        std::vector<Value> vals;
        for (size_t c = 0; c < t.cols.size(); ++c)
            vals.push_back(value_from_text(
                t.cols[c], PQgetvalue(r, i, static_cast<int>(c + 1)),
                PQgetisnull(r, i, static_cast<int>(c + 1))));
        out.push_back({pk, hash_pg_row(vals)});
    }
    PQclear(r);
    return out;
}

std::vector<BucketHashEntry> pg_all_buckets(PGconn* c,
                                            const std::vector<PgTable>& tables,
                                            std::int64_t bucket_size) {
    std::vector<BucketHashEntry> out;
    for (const auto& t : tables) {
        auto* r = pg_query(c, "SELECT MIN(" + pg_quote_id(t.pk) + "), MAX(" +
                                  pg_quote_id(t.pk) + ") FROM " +
                                  pg_quote_id(t.name));
        if (PQntuples(r) == 0 || PQgetisnull(r, 0, 0)) {
            PQclear(r);
            continue;
        }
        auto min_pk = std::stoll(PQgetvalue(r, 0, 0));
        auto max_pk = std::stoll(PQgetvalue(r, 0, 1));
        PQclear(r);
        auto lo_b = min_pk / bucket_size;
        if (min_pk < 0) lo_b = (min_pk - bucket_size + 1) / bucket_size;
        auto hi_b = max_pk / bucket_size;
        if (max_pk < 0) hi_b = (max_pk - bucket_size + 1) / bucket_size;
        for (auto k = lo_b; k <= hi_b; ++k) {
            auto blo = k * bucket_size;
            auto bhi = blo + bucket_size - 1;
            auto rows = pg_row_hashes(c, t, blo, bhi);
            std::uint64_t bh = 0;
            for (const auto& row : rows)
                bh ^= detail::hash_bucket_entry(row.rowid, row.hash);
            out.push_back({t.name, blo, bhi, bh,
                           static_cast<std::int64_t>(rows.size())});
        }
    }
    return out;
}

ChangeEvent event_from_op(const PgOp& op) {
    ChangeEvent ev;
    ev.table = op.table;
    ev.op = op.op;
    for (const auto& f : op.old_row) ev.old_values.push_back(f.value);
    for (const auto& f : op.new_row) ev.new_values.push_back(f.value);
    return ev;
}

} // namespace

inline std::vector<std::string> pg_list_user_tables(
        PGconn* c, const std::set<std::string>* filter) {
    std::vector<std::string> names;
    for (const auto& t : pg_discover(c, filter))
        names.push_back(t.name);
    return names;
}

struct PgMasterState {
    PGconn* pg;
    MasterConfig config;
    std::vector<PgTable> tables;
    Seq seq = 0;
    SchemaVersion cached_sv;
    enum class HSState : std::uint8_t {
        Idle, WaitBucketHashes, WaitRowHashes, Live
    };
    HSState hs_state = HSState::Idle;
    std::vector<NeedBucketRange> pending_ranges;
    struct Queued { Seq seq; Changeset data; };
    std::deque<Queued> changeset_queue;

    explicit PgMasterState(PGconn* c, MasterConfig cfg)
        : pg(c), config(std::move(cfg)) {
        pg_ensure_catalog(pg);
        seq = pg_read_seq(pg, config.seq_key);
        rescan();
        cached_sv = fingerprint();
        SQLPIPE_LOG(config.on_log, LogLevel::Info,
                    "pg master initialized at seq={}", seq);
    }

    const std::set<std::string>* filter() const {
        return config.table_filter ? &*config.table_filter : nullptr;
    }

    void rescan() {
        tables = pg_discover(pg, filter());
        pg_install_triggers(pg, tables);
    }

    SchemaVersion fingerprint() {
        return detail::compute_schema_fingerprint_pg(make_sqlift_exec(pg));
    }

    void enqueue(Seq s, const Changeset& data) {
        if (config.changeset_queue_size == 0) return;
        changeset_queue.push_back({s, data});
        while (changeset_queue.size() > config.changeset_queue_size)
            changeset_queue.pop_front();
    }

    Changeset drain_outbox() {
        auto* r = pg_query(pg,
            "SELECT id, table_name, op, pk, old_row::text, new_row::text "
            "FROM sqlpipe.outbox ORDER BY id");
        std::vector<PgOp> ops;
        std::vector<std::string> ids;
        int n = PQntuples(r);
        for (int i = 0; i < n; ++i) {
            ids.emplace_back(PQgetvalue(r, i, 0));
            PgOp op;
            op.table = PQgetvalue(r, i, 1);
            op.op = static_cast<OpType>(std::stoi(PQgetvalue(r, i, 2)));
            op.pk = std::stoll(PQgetvalue(r, i, 3));
            auto* tbl = find_table(tables, op.table);
            if (!tbl) continue;
            op.old_row = fields_from_jsonb(pg, *tbl, PQgetvalue(r, i, 4),
                                           PQgetisnull(r, i, 4));
            op.new_row = fields_from_jsonb(pg, *tbl, PQgetvalue(r, i, 5),
                                           PQgetisnull(r, i, 5));
            ops.push_back(std::move(op));
        }
        PQclear(r);
        if (ops.empty()) return {};
        pg_exec(pg, "DELETE FROM sqlpipe.outbox");
        return encode_pg_ops(ops);
    }

    std::vector<OutMessage> flush() {
        auto sv = fingerprint();
        if (sv != cached_sv) {
            cached_sv = sv;
            rescan();
        }
        auto cs = drain_outbox();
        if (cs.empty()) return {};
        seq++;
        pg_write_seq(pg, seq, config.seq_key);
        enqueue(seq, cs);
        SQLPIPE_LOG(config.on_log, LogLevel::Debug,
                    "pg flushed changeset seq={} ({} bytes)", seq, cs.size());
        return {tagged(Message{ChangesetMsg{seq, std::move(cs)}})};
    }

    void exec(const std::string& sql) {
        pg_exec(pg, sql);
        if (config.on_flush) {
            auto msgs = flush();
            if (!msgs.empty()) config.on_flush(msgs);
        }
    }

    void absorb_outbox() {
        auto cs = drain_outbox();
        if (cs.empty()) return;
        seq++;
        pg_write_seq(pg, seq, config.seq_key);
        enqueue(seq, cs);
    }

    std::vector<OutMessage> handle_hello(const HelloMsg& hello) {
        absorb_outbox();
        if (hello.protocol_version != kPostgresProtocolVersion) {
            return {tagged(Message{ErrorMsg{ErrorCode::ProtocolError,
                "unsupported protocol version: " +
                std::to_string(hello.protocol_version)}})};
        }
        auto my_sv = fingerprint();
        if (hello.schema_version != my_sv) {
            return {tagged(Message{ErrorMsg{ErrorCode::SchemaMismatch,
                "schema mismatch", my_sv, ""}})};
        }
        if (hello.last_seq > 0 && hello.last_seq == seq) {
            hs_state = HSState::Live;
            return {tagged(Message{HelloMsg{kPostgresProtocolVersion, my_sv, {}, seq}})};
        }
        if (hello.last_seq > 0 && !changeset_queue.empty() &&
            hello.last_seq >= changeset_queue.front().seq - 1) {
            std::vector<OutMessage> result;
            result.push_back(tagged(Message{
                HelloMsg{kPostgresProtocolVersion, my_sv, {}, hello.last_seq}}));
            std::size_t replayed = 0;
            for (const auto& qc : changeset_queue) {
                if (qc.seq > hello.last_seq) {
                    result.push_back(tagged(Message{ChangesetMsg{qc.seq, qc.data}}));
                    ++replayed;
                }
            }
            if (replayed > 0) {
                hs_state = HSState::Live;
                return result;
            }
        }
        hs_state = HSState::WaitBucketHashes;
        return {tagged(Message{HelloMsg{kPostgresProtocolVersion, my_sv, {}, -1}})};
    }

    std::vector<OutMessage> handle_bucket_hashes(const BucketHashesMsg& msg) {
        absorb_outbox();
        pending_ranges.clear();
        if (msg.protocol_version != 0 &&
            msg.protocol_version != kPostgresProtocolVersion) {
            return {tagged(Message{ErrorMsg{ErrorCode::ProtocolError,
                "unsupported protocol version: " +
                std::to_string(msg.protocol_version)}})};
        }
        if (!msg.schema_version.empty() && msg.schema_version != fingerprint()) {
            return {tagged(Message{ErrorMsg{ErrorCode::SchemaMismatch,
                "schema mismatch", fingerprint(), ""}})};
        }
        auto mine = pg_all_buckets(pg, tables, config.bucket_size);
        std::map<std::tuple<std::string, std::int64_t, std::int64_t>,
                 BucketHashEntry> theirs;
        for (const auto& b : msg.buckets)
            theirs[{b.table, b.bucket_lo, b.bucket_hi}] = b;
        std::vector<NeedBucketRange> need;
        for (const auto& b : mine) {
            auto it = theirs.find({b.table, b.bucket_lo, b.bucket_hi});
            if (it == theirs.end() || it->second.hash != b.hash)
                need.push_back({b.table, b.bucket_lo, b.bucket_hi});
        }
        for (const auto& [key, b] : theirs) {
            bool found = false;
            for (const auto& m : mine)
                if (m.table == b.table && m.bucket_lo == b.bucket_lo &&
                    m.bucket_hi == b.bucket_hi) {
                    found = true;
                    break;
                }
            if (!found)
                need.push_back({b.table, b.bucket_lo, b.bucket_hi});
        }
        pending_ranges = need;
        if (need.empty()) {
            hs_state = HSState::Live;
            return {tagged(Message{NeedBucketsMsg{}}),
                    tagged(Message{DiffReadyMsg{seq, {}, {}}})};
        }
        hs_state = HSState::WaitRowHashes;
        return {tagged(Message{NeedBucketsMsg{std::move(need)}})};
    }

    std::vector<OutMessage> handle_row_hashes(const RowHashesMsg& msg) {
        std::vector<Changeset> patch_ops;
        std::vector<TableDeletes> deletes;
        std::vector<PgOp> upserts;
        for (const auto& e : msg.entries) {
            auto* tbl = find_table(tables, e.table);
            if (!tbl) continue;
            std::map<std::int64_t, std::uint64_t> replica;
            for (const auto& run : e.runs) {
                for (std::int64_t i = 0; i < run.count; ++i)
                    replica[run.start_rowid + i] = run.hashes[static_cast<size_t>(i)];
            }
            auto mine = pg_row_hashes(pg, *tbl, e.lo, e.hi);
            std::set<std::int64_t> master_pks;
            for (const auto& row : mine) {
                master_pks.insert(row.rowid);
                auto it = replica.find(row.rowid);
                if (it == replica.end() || it->second != row.hash) {
                    auto vals = load_row_values(pg, *tbl, row.rowid);
                    PgOp op;
                    op.op = OpType::Insert;
                    op.table = tbl->name;
                    op.pk = row.rowid;
                    for (size_t i = 0; i < tbl->cols.size(); ++i)
                        op.new_row.push_back({tbl->cols[i].name, vals[i]});
                    upserts.push_back(std::move(op));
                }
            }
            std::vector<std::int64_t> del;
            for (const auto& [pk, _] : replica)
                if (!master_pks.count(pk)) del.push_back(pk);
            if (!del.empty())
                deletes.push_back({e.table, std::move(del)});
        }
        hs_state = HSState::Live;
        pending_ranges.clear();
        return {tagged(Message{DiffReadyMsg{
            seq, encode_pg_ops(upserts), std::move(deletes)}})};
    }

    std::vector<OutMessage> handle_message(const Message& msg) {
        return std::visit([&](const auto& m) -> std::vector<OutMessage> {
            using T = std::decay_t<decltype(m)>;
            if constexpr (std::is_same_v<T, HelloMsg>)
                return handle_hello(m);
            else if constexpr (std::is_same_v<T, BucketHashesMsg>)
                return handle_bucket_hashes(m);
            else if constexpr (std::is_same_v<T, RowHashesMsg>)
                return handle_row_hashes(m);
            else if constexpr (std::is_same_v<T, AckMsg>)
                return {};
            else
                return {tagged(Message{ErrorMsg{ErrorCode::InvalidState,
                    "unexpected message from replica"}})};
        }, msg);
    }
};

struct PgReplicaState {
    PGconn* pg;
    ReplicaConfig config;
    std::vector<PgTable> tables;
    Seq seq = 0;
    Replica::State state = Replica::State::Init;

    explicit PgReplicaState(PGconn* c, ReplicaConfig cfg)
        : pg(c), config(std::move(cfg)) {
        pg_ensure_catalog(pg);
        seq = pg_read_seq(pg, config.seq_key);
        tables = pg_discover(pg, config.table_filter ? &*config.table_filter
                                                     : nullptr);
        // Same triggers as the master so sqlift fingerprints match. Apply
        // uses session_replication_role = replica so these do not fire.
        pg_install_triggers(pg, tables);
        SQLPIPE_LOG(config.on_log, LogLevel::Info,
                    "pg replica initialized at seq={}", seq);
    }

    SchemaVersion fingerprint() {
        return detail::compute_schema_fingerprint_pg(make_sqlift_exec(pg));
    }

    OutMessage hello() {
        state = Replica::State::Handshake;
        return tagged(Message{HelloMsg{kPostgresProtocolVersion, fingerprint(),
                                       {}, seq}});
    }

    std::vector<OutMessage> converge() {
        auto buckets = pg_all_buckets(pg, tables, config.bucket_size);
        state = Replica::State::DiffBuckets;
        return {tagged(Message{BucketHashesMsg{
            std::move(buckets), seq, kPostgresProtocolVersion, fingerprint()}})};
    }

    std::vector<ChangeEvent> apply_ops(const std::vector<PgOp>& ops, Seq new_seq,
                                       bool check_seq) {
        if (check_seq && new_seq != seq + 1) {
            throw Error(ErrorCode::ProtocolError,
                        "changeset seq gap: expected " +
                        std::to_string(seq + 1) + ", got " +
                        std::to_string(new_seq));
        }
        pg_exec(pg, "BEGIN");
        try {
            pg_exec(pg, "SET LOCAL session_replication_role = replica");
            for (const auto& op : ops)
                apply_pg_op(pg, op, config, tables);
            if (check_seq) {
                seq = new_seq;
                pg_write_seq(pg, seq, config.seq_key);
            }
            pg_exec(pg, "COMMIT");
        } catch (...) {
            try { pg_exec(pg, "ROLLBACK"); } catch (...) {}
            throw;
        }
        std::vector<ChangeEvent> evs;
        for (const auto& op : ops)
            evs.push_back(event_from_op(op));
        return evs;
    }

    HandleResult handle_hello_from_master(const HelloMsg& m) {
        if (state != Replica::State::Handshake) {
            state = Replica::State::Error;
            return {{tagged(Message{ErrorMsg{ErrorCode::InvalidState,
                "received HelloMsg in unexpected state"}})}, {}, {}};
        }
        if (m.protocol_version != kPostgresProtocolVersion) {
            state = Replica::State::Error;
            return {{tagged(Message{ErrorMsg{ErrorCode::ProtocolError,
                "unsupported protocol version"}})}, {}, {}};
        }
        if (m.last_seq > 0 && m.last_seq == seq) {
            state = Replica::State::Live;
            return {{tagged(Message{AckMsg{seq}})}, {}, {}};
        }
        auto buckets = pg_all_buckets(pg, tables, config.bucket_size);
        state = Replica::State::DiffBuckets;
        return {{tagged(Message{BucketHashesMsg{
            std::move(buckets), seq, kPostgresProtocolVersion,
            fingerprint()}})}, {}, {}};
    }

    HandleResult handle_need_buckets(const NeedBucketsMsg& m) {
        if (state != Replica::State::DiffBuckets &&
            state != Replica::State::Live) {
            state = Replica::State::Error;
            return {{tagged(Message{ErrorMsg{ErrorCode::InvalidState,
                "received NeedBucketsMsg in unexpected state"}})}, {}, {}};
        }
        state = Replica::State::DiffRows;
        if (m.ranges.empty())
            return {};
        RowHashesMsg rh;
        for (const auto& range : m.ranges) {
            auto* tbl = find_table(tables, range.table);
            if (!tbl) continue;
            auto rows = pg_row_hashes(pg, *tbl, range.lo, range.hi);
            RowHashesEntry entry;
            entry.table = range.table;
            entry.lo = range.lo;
            entry.hi = range.hi;
            if (!rows.empty()) {
                RowHashRun run;
                run.start_rowid = rows.front().rowid;
                run.count = 0;
                std::int64_t expect = rows.front().rowid;
                for (const auto& row : rows) {
                    if (row.rowid != expect && run.count > 0) {
                        entry.runs.push_back(std::move(run));
                        run = RowHashRun{};
                        run.start_rowid = row.rowid;
                        run.count = 0;
                        expect = row.rowid;
                    }
                    run.hashes.push_back(row.hash);
                    run.count++;
                    expect = row.rowid + 1;
                }
                if (run.count > 0)
                    entry.runs.push_back(std::move(run));
            }
            rh.entries.push_back(std::move(entry));
        }
        return {{tagged(Message{std::move(rh)})}, {}, {}};
    }

    HandleResult handle_diff_ready(const DiffReadyMsg& m) {
        pg_exec(pg, "BEGIN");
        try {
            pg_exec(pg, "SET CONSTRAINTS ALL DEFERRED");
            pg_exec(pg, "SET LOCAL session_replication_role = replica");
            auto ops = decode_pg_ops(m.patchset);
            for (const auto& op : ops)
                apply_pg_op(pg, op, config, tables);
            for (const auto& td : m.deletes) {
                auto* tbl = find_table(tables, td.table);
                std::string pk = tbl ? tbl->pk : "id";
                for (auto rid : td.rowids)
                    pg_exec(pg, "DELETE FROM " + pg_quote_id(td.table) +
                                    " WHERE " + pg_quote_id(pk) + " = " +
                                    std::to_string(rid));
            }
            seq = m.seq;
            pg_write_seq(pg, seq, config.seq_key);
            pg_exec(pg, "COMMIT");
        } catch (...) {
            try { pg_exec(pg, "ROLLBACK"); } catch (...) {}
            throw;
        }
        state = Replica::State::Live;
        std::vector<ChangeEvent> evs;
        for (const auto& op : decode_pg_ops(m.patchset))
            evs.push_back(event_from_op(op));
        return {{tagged(Message{AckMsg{m.seq}})}, std::move(evs), {}};
    }

    HandleResult handle_changeset(const ChangesetMsg& m) {
        auto ops = decode_pg_ops(m.data);
        auto evs = apply_ops(ops, m.seq, true);
        state = Replica::State::Live;
        return {{tagged(Message{AckMsg{m.seq}})}, std::move(evs), {}};
    }

    void reset() {
        state = Replica::State::Init;
        seq = pg_read_seq(pg, config.seq_key);
        tables = pg_discover(pg, config.table_filter ? &*config.table_filter
                                                     : nullptr);
        pg_install_triggers(pg, tables);
    }

    bool in_caller_txn() const {
        return PQtransactionStatus(pg) != PQTRANS_IDLE;
    }

    void begin_prediction() {
        if (in_caller_txn()) {
            throw Error(ErrorCode::InvalidState,
                        "prediction rejected: connection already in a transaction");
        }
        pg_exec(pg, "BEGIN");
        pg_exec(pg, "SAVEPOINT _sqlpipe_prediction");
    }

    void rollback_prediction() {
        try { pg_exec(pg, "ROLLBACK TO SAVEPOINT _sqlpipe_prediction"); }
        catch (...) {}
        try { pg_exec(pg, "ROLLBACK"); } catch (...) {}
    }

    HandleResult handle_message(const Message& msg) {
        return std::visit([&](const auto& m) -> HandleResult {
            using T = std::decay_t<decltype(m)>;
            if constexpr (std::is_same_v<T, HelloMsg>)
                return handle_hello_from_master(m);
            else if constexpr (std::is_same_v<T, NeedBucketsMsg>)
                return handle_need_buckets(m);
            else if constexpr (std::is_same_v<T, DiffReadyMsg>)
                return handle_diff_ready(m);
            else if constexpr (std::is_same_v<T, ChangesetMsg>)
                return handle_changeset(m);
            else if constexpr (std::is_same_v<T, ErrorMsg>) {
                state = Replica::State::Error;
                return {};
            } else {
                state = Replica::State::Error;
                return {{tagged(Message{ErrorMsg{ErrorCode::InvalidState,
                    "unexpected message from master"}})}, {}, {}};
            }
        }, msg);
    }
};

} // namespace sqlpipe

#endif // SQLPIPE_HAVE_POSTGRES
#endif // !EMSCRIPTEN
