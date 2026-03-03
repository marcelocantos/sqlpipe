// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

#pragma once

// sqlift - Declarative SQLite schema migration library

#define SQLIFT_VERSION "0.11.0"
#define SQLIFT_VERSION_MAJOR 0
#define SQLIFT_VERSION_MINOR 11
#define SQLIFT_VERSION_PATCH 0

#include <cstdint>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>
#include <sqlite3.h>

namespace sqlift {

// --- error.h ---




class Error : public std::runtime_error {
    using std::runtime_error::runtime_error;
};

class ParseError : public Error {
    using Error::Error;
};

class ExtractError : public Error {
    using Error::Error;
};

class DiffError : public Error {
    using Error::Error;
};

class ApplyError : public Error {
    using Error::Error;
};

class DriftError : public Error {
    using Error::Error;
};

class DestructiveError : public Error {
    using Error::Error;
};

class BreakingChangeError : public Error {
    using Error::Error;
};

class JsonError : public Error {
    using Error::Error;
};


// --- sqlite_util.h ---




// RAII wrapper for sqlite3*.
class Database {
public:
    explicit Database(const std::string& path,
                      int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
    ~Database();

    Database(Database&& other) noexcept;
    Database& operator=(Database&& other) noexcept;
    Database(const Database&) = delete;
    Database& operator=(const Database&) = delete;

    sqlite3* get() const { return db_; }
    operator sqlite3*() const { return db_; }

    // Execute SQL with no result. Throws Error on failure.
    void exec(const std::string& sql);

private:
    sqlite3* db_ = nullptr;
};

// RAII wrapper for sqlite3_stmt*.
class Statement {
public:
    Statement(sqlite3* db, const std::string& sql);
    ~Statement();

    Statement(Statement&& other) noexcept;
    Statement& operator=(Statement&& other) noexcept;
    Statement(const Statement&) = delete;
    Statement& operator=(const Statement&) = delete;

    // Step. Returns true if SQLITE_ROW, false if SQLITE_DONE. Throws on error.
    bool step();

    int64_t column_int(int col) const;
    std::string column_text(int col) const;

    void bind_text(int param, const std::string& value);
    void bind_int(int param, int64_t value);

    sqlite3_stmt* get() const { return stmt_; }

private:
    sqlite3_stmt* stmt_ = nullptr;
};


// --- schema.h ---




// Matches SQLite's table_xinfo hidden field values.
enum class GeneratedType {
    Normal  = 0,
    Virtual = 2,
    Stored  = 3,
};

struct Column {
    std::string name;
    std::string type;            // Uppercase. Empty if untyped.
    bool notnull = false;
    std::string default_value;   // Raw SQL expression; empty if no default.
    int pk = 0;                  // 0 = not PK, 1+ = position in composite PK.
    std::string collation;       // e.g. "NOCASE"; empty = default (BINARY).
    GeneratedType generated = GeneratedType::Normal;
    std::string generated_expr;  // e.g. "first_name || ' ' || last_name"; empty if not generated.

    bool operator==(const Column&) const = default;
};

struct CheckConstraint {
    std::string name;         // empty if unnamed
    std::string expression;   // e.g. "age > 0"
    bool operator==(const CheckConstraint&) const = default;
};

struct ForeignKey {
    std::string constraint_name;             // empty if unnamed
    std::vector<std::string> from_columns;
    std::string to_table;
    std::vector<std::string> to_columns;
    std::string on_update = "NO ACTION";
    std::string on_delete = "NO ACTION";

    // Structural equality — excludes constraint_name (cosmetic).
    bool operator==(const ForeignKey& o) const {
        return from_columns == o.from_columns && to_table == o.to_table &&
               to_columns == o.to_columns && on_update == o.on_update &&
               on_delete == o.on_delete;
    }
};

struct Table {
    std::string name;
    std::vector<Column> columns;           // Ordered by cid.
    std::vector<ForeignKey> foreign_keys;
    std::vector<CheckConstraint> check_constraints;
    std::string pk_constraint_name;        // empty if unnamed (cosmetic, excluded from ==).
    bool without_rowid = false;
    bool strict = false;
    std::string raw_sql;                   // Original CREATE TABLE from sqlite_master.

    // Structural equality — excludes raw_sql (which SQLite doesn't update after
    // ALTER TABLE ADD COLUMN, so it can't be relied on for comparison).
    bool operator==(const Table& o) const {
        return name == o.name && columns == o.columns &&
               foreign_keys == o.foreign_keys &&
               check_constraints == o.check_constraints &&
               without_rowid == o.without_rowid &&
               strict == o.strict;
    }
};

struct Index {
    std::string name;
    std::string table_name;
    std::vector<std::string> columns;
    bool unique = false;
    std::string where_clause;   // Partial index; empty if not partial.
    std::string raw_sql;        // Original CREATE INDEX from sqlite_master.

    // Structural equality — excludes raw_sql.
    bool operator==(const Index& o) const {
        return name == o.name && table_name == o.table_name &&
               columns == o.columns && unique == o.unique &&
               where_clause == o.where_clause;
    }
};

struct View {
    std::string name;
    std::string sql;

    bool operator==(const View&) const = default;
};

struct Trigger {
    std::string name;
    std::string table_name;
    std::string sql;

    bool operator==(const Trigger&) const = default;
};

struct Schema {
    std::map<std::string, Table>   tables;
    std::map<std::string, Index>   indexes;
    std::map<std::string, View>    views;
    std::map<std::string, Trigger> triggers;

    bool operator==(const Schema&) const = default;

    // Deterministic SHA-256 hash of the schema.
    std::string hash() const;
};


// --- parse.h ---




// Parse SQL DDL statements into a Schema.
// Loads the SQL into a :memory: database and extracts the resulting schema.
Schema parse(const std::string& sql);


// --- extract.h ---




// Extract the current schema from a live database.
Schema extract(sqlite3* db);


// --- diff.h ---




enum class WarningType {
    RedundantIndex,
};

struct Warning {
    WarningType type;
    std::string message;        // Human-readable description.
    std::string index_name;     // The redundant index.
    std::string covered_by;     // The covering index name, or "PRIMARY KEY".
    std::string table_name;
};

enum class OpType {
    CreateTable,
    DropTable,
    RebuildTable,
    AddColumn,
    CreateIndex,
    DropIndex,
    CreateView,
    DropView,
    CreateTrigger,
    DropTrigger,
};

struct Operation {
    OpType type;
    std::string object_name;
    std::string description;
    std::vector<std::string> sql;
    bool destructive = false;
};

class MigrationPlan {
public:
    const std::vector<Operation>& operations() const { return ops_; }
    const std::vector<Warning>& warnings() const { return warnings_; }
    bool has_destructive_operations() const;
    bool empty() const { return ops_.empty(); }

private:
    friend MigrationPlan diff(const Schema& current, const Schema& desired);
    friend MigrationPlan from_json(const std::string& json_str);
    std::vector<Operation> ops_;
    std::vector<Warning> warnings_;
};

// Pure function: compare two schemas and produce a migration plan.
MigrationPlan diff(const Schema& current, const Schema& desired);

// Detect redundant indexes in a schema (prefix-duplicate and PK-duplicate).
std::vector<Warning> detect_redundant_indexes(const Schema& schema);


// --- apply.h ---




struct ApplyOptions {
    bool allow_destructive = false;
};

// Apply a migration plan to a live database.
void apply(sqlite3* db, const MigrationPlan& plan, const ApplyOptions& opts = {});

// Return the migration version counter (0 if no migrations have run).
int64_t migration_version(sqlite3* db);


// --- json.h ---




// Convert an OpType to its string representation (e.g. OpType::CreateTable -> "CreateTable").
std::string to_string(OpType type);

// Parse a string into an OpType. Throws JsonError if unrecognized.
OpType op_type_from_string(const std::string& s);

// Serialize a MigrationPlan to a JSON string.
std::string to_json(const MigrationPlan& plan);

// Deserialize a MigrationPlan from a JSON string. Throws JsonError on failure.
MigrationPlan from_json(const std::string& json_str);


} // namespace sqlift
