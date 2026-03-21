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

TEST_CASE("diff sync: auto-migrate empty replica to master schema") {
    DB master_db, replica_db;

    // Master has schema and data; replica is completely empty.
    master_db.exec(
        "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT NOT NULL, value REAL);"
        "INSERT INTO items VALUES (1, 'hello', 3.14);"
        "INSERT INTO items VALUES (2, 'world', 2.72)");

    Master master(master_db.db);
    Replica replica(replica_db.db);  // no schema, no tables

    // First handshake attempt: schema mismatch → auto-migration → reset.
    auto pending = master.handle_message(replica.hello());
    REQUIRE(pending.size() == 1);  // ErrorMsg with schema SQL

    auto result = replica.handle_message(pending[0]);
    // Auto-migration should have resolved the mismatch and reset to Init.
    CHECK(replica.state() == Replica::State::Init);

    // Second handshake: schemas now match → proceed to diff sync → live.
    sync_handshake(master, replica);
    CHECK(replica.state() == Replica::State::Live);

    // Verify data was replicated.
    CHECK(replica_db.count("items") == 2);
    CHECK(replica_db.query_val("SELECT name FROM items WHERE id=1") == "hello");
}

TEST_CASE("diff sync: auto-migrate adds new column") {
    DB master_db, replica_db;

    // Both start with same schema.
    master_db.exec("CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT)");
    replica_db.exec("CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT)");

    Master master(master_db.db);
    Replica replica(replica_db.db);

    // Initial sync.
    sync_handshake(master, replica);
    CHECK(replica.state() == Replica::State::Live);

    // Master evolves schema — add a column and insert data.
    master_db.exec("ALTER TABLE t ADD COLUMN score REAL DEFAULT 0");
    master_db.exec("INSERT INTO t VALUES (1, 'alice', 95.5)");

    // Replica reconnects with old schema.
    replica.reset();
    Master master2(master_db.db);  // new master with evolved schema

    auto pending = master2.handle_message(replica.hello());
    REQUIRE(pending.size() == 1);  // ErrorMsg

    auto result = replica.handle_message(pending[0]);
    CHECK(replica.state() == Replica::State::Init);  // auto-migrated

    sync_handshake(master2, replica);
    CHECK(replica.state() == Replica::State::Live);
    CHECK(replica_db.count("t") == 1);
}

TEST_CASE("diff sync: fast reconnect when seq matches (no diff messages)") {
    DB master_db, replica_db;
    master_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    replica_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");

    // Initial sync with data.
    Master master(master_db.db);
    Replica replica(replica_db.db);
    sync_handshake(master, replica);
    master_db.exec("INSERT INTO t1 VALUES (1, 'hello')");
    auto msgs = master.flush();
    for (auto& m : msgs) replica.handle_message(m);
    CHECK(replica.current_seq() == 1);

    // Simulate reconnect with no changes — seqs match.
    Master master2(master_db.db);
    Replica replica2(replica_db.db);

    // Track what messages are exchanged.
    auto hello = replica2.hello();
    auto resp = master2.handle_message(hello);

    // Master should respond with a single HelloMsg (fast path).
    REQUIRE(resp.size() == 1);
    CHECK(std::holds_alternative<HelloMsg>(resp[0]));
    auto& hm = std::get<HelloMsg>(resp[0]);
    CHECK(hm.last_seq == 1);  // confirms fast path

    // Replica receives the HelloMsg and goes straight to Live.
    auto result = replica2.handle_message(resp[0]);
    CHECK(replica2.state() == Replica::State::Live);

    // No BucketHashesMsg — just an AckMsg back.
    REQUIRE(result.messages.size() == 1);
    CHECK(std::holds_alternative<AckMsg>(result.messages[0]));

    // Data is still there.
    CHECK(replica_db.count("t1") == 1);
}

TEST_CASE("diff sync: no fast reconnect when seq differs") {
    DB master_db, replica_db;
    master_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    replica_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");

    // Initial sync.
    Master master(master_db.db);
    Replica replica(replica_db.db);
    sync_handshake(master, replica);
    master_db.exec("INSERT INTO t1 VALUES (1, 'hello')");
    auto msgs = master.flush();
    for (auto& m : msgs) replica.handle_message(m);

    // Master adds more data (seq=2), replica stays at seq=1.
    {
        Master m2(master_db.db);
        master_db.exec("INSERT INTO t1 VALUES (2, 'world')");
        m2.flush();
    }

    // Reconnect — seqs don't match, full diff sync.
    Master master3(master_db.db);
    Replica replica3(replica_db.db);
    sync_handshake(master3, replica3);
    CHECK(replica3.state() == Replica::State::Live);
    CHECK(replica_db.count("t1") == 2);
}
