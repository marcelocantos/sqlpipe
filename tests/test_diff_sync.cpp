// Copyright 2026 The sqlpipe Authors
// SPDX-License-Identifier: Apache-2.0
#include <doctest.h>
#include <sqlpipe.h>

#include <sqlite3.h>

using namespace sqlpipe;

namespace {

struct DB {
    sqlite3* db = nullptr;
    DB() { sqlite3_open(":memory:", &db); }
    ~DB() { if (db) sqlite3_close(db); }
    void exec(const char* sql) {
        char* err = nullptr;
        int rc = sqlite3_exec(db, sql, nullptr, nullptr, &err);
        if (rc != SQLITE_OK) {
            std::string msg = err ? err : "error";
            sqlite3_free(err);
            throw std::runtime_error(msg);
        }
    }
    int count(const char* table) {
        std::string sql = std::string("SELECT COUNT(*) FROM ") + table;
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
        sqlite3_step(stmt);
        int n = sqlite3_column_int(stmt, 0);
        sqlite3_finalize(stmt);
        return n;
    }
    std::string query_val(const char* sql) {
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
        std::string result;
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            auto* text = reinterpret_cast<const char*>(
                sqlite3_column_text(stmt, 0));
            if (text) result = text;
        }
        sqlite3_finalize(stmt);
        return result;
    }
};

// Full handshake including diff exchange.
void handshake(Master& master, Replica& replica) {
    auto hello = replica.hello();
    auto resp = master.handle_message(hello);
    HandleResult r;
    for (const auto& m : resp) {
        auto result = replica.handle_message(m);
        r.messages.insert(r.messages.end(),
                          result.messages.begin(), result.messages.end());
    }
    for (const auto& m : r.messages) {
        auto result = master.handle_message(m);
        HandleResult r2;
        for (const auto& m2 : result) {
            auto result2 = replica.handle_message(m2);
            r2.messages.insert(r2.messages.end(),
                               result2.messages.begin(), result2.messages.end());
        }
        for (const auto& m3 : r2.messages) {
            auto result3 = master.handle_message(m3);
            for (const auto& m4 : result3) {
                replica.handle_message(m4);
            }
        }
    }
}

HandleResult deliver(const std::vector<Message>& msgs, Replica& handler) {
    HandleResult result;
    for (const auto& m : msgs) {
        auto resp = handler.handle_message(m);
        result.messages.insert(result.messages.end(),
                               resp.messages.begin(), resp.messages.end());
        result.changes.insert(result.changes.end(),
                              resp.changes.begin(), resp.changes.end());
    }
    return result;
}

} // namespace

TEST_CASE("diff sync: schema mismatch produces ErrorMsg") {
    DB master_db, replica_db;
    master_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    // Replica has a DIFFERENT schema (extra column) → fingerprint mismatch.
    replica_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT, extra TEXT)");

    Master master(master_db.db);
    Replica replica(replica_db.db);

    auto hello = replica.hello();
    auto master_resp = master.handle_message(hello);

    // Master should detect schema mismatch and send ErrorMsg.
    REQUIRE(master_resp.size() == 1);
    CHECK(std::holds_alternative<ErrorMsg>(master_resp[0]));
    auto& err = std::get<ErrorMsg>(master_resp[0]);
    CHECK(err.code == ErrorCode::SchemaMismatch);
    CHECK(err.remote_schema_version == master.schema_version());
    CHECK(!err.remote_schema_sql.empty());
}

TEST_CASE("diff sync: populated master vs empty replica") {
    DB master_db, replica_db;
    master_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    replica_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");

    Master master(master_db.db);
    master_db.exec("INSERT INTO t1 VALUES (1, 'a')");
    master.flush();
    master_db.exec("INSERT INTO t1 VALUES (2, 'b')");
    master.flush();

    Replica replica(replica_db.db);
    handshake(master, replica);

    CHECK(replica.state() == Replica::State::Live);
    CHECK(replica_db.count("t1") == 2);
    CHECK(replica_db.query_val("SELECT val FROM t1 WHERE id=1") == "a");
    CHECK(replica_db.query_val("SELECT val FROM t1 WHERE id=2") == "b");
}

TEST_CASE("diff sync: empty master vs populated replica (deletes all)") {
    DB master_db, replica_db;
    master_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    replica_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");

    Master master(master_db.db);

    // Replica has data that master doesn't — diff should delete on replica.
    replica_db.exec("INSERT INTO t1 VALUES (1, 'stale')");
    replica_db.exec("INSERT INTO t1 VALUES (2, 'old')");

    Replica replica(replica_db.db);
    handshake(master, replica);

    CHECK(replica.state() == Replica::State::Live);
    CHECK(replica_db.count("t1") == 0);
}

TEST_CASE("diff sync: both populated with overlap") {
    DB master_db, replica_db;
    master_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    replica_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");

    // Master has rows 1, 2, 3.
    master_db.exec("INSERT INTO t1 VALUES (1, 'a')");
    master_db.exec("INSERT INTO t1 VALUES (2, 'b')");
    master_db.exec("INSERT INTO t1 VALUES (3, 'c')");

    Master master(master_db.db);
    master.flush();

    // Replica has rows 2 (stale), 3 (current), 4 (extra).
    replica_db.exec("INSERT INTO t1 VALUES (2, 'OLD')");
    replica_db.exec("INSERT INTO t1 VALUES (3, 'c')");
    replica_db.exec("INSERT INTO t1 VALUES (4, 'extra')");

    Replica replica(replica_db.db);
    handshake(master, replica);

    CHECK(replica.state() == Replica::State::Live);
    CHECK(replica_db.count("t1") == 3);
    CHECK(replica_db.query_val("SELECT val FROM t1 WHERE id=1") == "a");   // inserted
    CHECK(replica_db.query_val("SELECT val FROM t1 WHERE id=2") == "b");   // updated
    CHECK(replica_db.query_val("SELECT val FROM t1 WHERE id=3") == "c");   // unchanged
    // Row 4 should be deleted.
    CHECK(replica_db.query_val("SELECT val FROM t1 WHERE id=4") == "");
}

TEST_CASE("diff sync: already in sync") {
    DB master_db, replica_db;
    master_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    replica_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");

    // Same data on both sides.
    master_db.exec("INSERT INTO t1 VALUES (1, 'a')");
    master_db.exec("INSERT INTO t1 VALUES (2, 'b')");
    replica_db.exec("INSERT INTO t1 VALUES (1, 'a')");
    replica_db.exec("INSERT INTO t1 VALUES (2, 'b')");

    Master master(master_db.db);
    master.flush();

    Replica replica(replica_db.db);
    handshake(master, replica);

    CHECK(replica.state() == Replica::State::Live);
    CHECK(replica_db.count("t1") == 2);
}

TEST_CASE("diff sync: then live streaming continues") {
    DB master_db, replica_db;
    master_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    replica_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");

    Master master(master_db.db);
    master_db.exec("INSERT INTO t1 VALUES (1, 'before')");
    master.flush();

    Replica replica(replica_db.db);
    handshake(master, replica);

    CHECK(replica.state() == Replica::State::Live);
    CHECK(replica_db.count("t1") == 1);

    // Now do live streaming.
    master_db.exec("INSERT INTO t1 VALUES (2, 'after')");
    auto msgs = master.flush();
    auto result = deliver(msgs, replica);

    CHECK(replica_db.count("t1") == 2);
    CHECK(replica_db.query_val("SELECT val FROM t1 WHERE id=2") == "after");
    REQUIRE(!result.changes.empty());
    CHECK(result.changes[0].op == OpType::Insert);
}
