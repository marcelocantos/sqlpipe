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

/// Deliver all messages from src to handler, collecting responses.
std::vector<Message> deliver(const std::vector<Message>& msgs,
                             auto& handler) {
    std::vector<Message> responses;
    for (const auto& m : msgs) {
        auto resp = handler.handle_message(m);
        responses.insert(responses.end(), resp.begin(), resp.end());
    }
    return responses;
}

} // namespace

TEST_CASE("integration: fresh start, live streaming") {
    // Both databases start empty with the same schema.
    DB master_db, replica_db;
    master_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    replica_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");

    std::vector<ChangeEvent> events;
    ReplicaConfig rcfg;
    rcfg.on_change = [&](const ChangeEvent& e) {
        events.push_back(e);
        return true;
    };

    Master master(master_db.db);
    Replica replica(replica_db.db, rcfg);

    // Handshake.
    auto hello = replica.hello();
    auto master_resp = master.handle_message(hello);
    auto replica_resp = deliver(master_resp, replica);

    CHECK(replica.state() == Replica::State::Live);
    CHECK(replica.current_seq() == 0);

    // Master inserts a row.
    master_db.exec("INSERT INTO t1 VALUES (1, 'hello')");
    auto changeset_msgs = master.flush();
    REQUIRE(changeset_msgs.size() == 1);

    // Deliver to replica.
    auto acks = deliver(changeset_msgs, replica);
    REQUIRE(acks.size() == 1);
    CHECK(std::holds_alternative<AckMsg>(acks[0]));
    CHECK(std::get<AckMsg>(acks[0]).seq == 1);

    // Verify replica has the data.
    CHECK(replica_db.count("t1") == 1);
    CHECK(replica_db.query_val("SELECT val FROM t1 WHERE id=1") == "hello");
    CHECK(replica.current_seq() == 1);

    // Verify change events.
    REQUIRE(events.size() == 1);
    CHECK(events[0].table == "t1");
    CHECK(events[0].op == OpType::Insert);
}

TEST_CASE("integration: catchup after disconnect") {
    DB master_db, replica_db;
    master_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    replica_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");

    Master master(master_db.db);

    // Master accumulates some changes while replica is disconnected.
    master_db.exec("INSERT INTO t1 VALUES (1, 'a')");
    master.flush();
    master_db.exec("INSERT INTO t1 VALUES (2, 'b')");
    master.flush();
    master_db.exec("INSERT INTO t1 VALUES (3, 'c')");
    master.flush();

    CHECK(master.current_seq() == 3);

    // Now replica connects.
    Replica replica(replica_db.db);
    auto hello = replica.hello();
    auto master_resp = master.handle_message(hello);

    // Deliver all master messages to replica.
    auto acks = deliver(master_resp, replica);

    CHECK(replica.state() == Replica::State::Live);
    CHECK(replica.current_seq() == 3);
    CHECK(replica_db.count("t1") == 3);
    CHECK(replica_db.query_val("SELECT val FROM t1 WHERE id=2") == "b");
}

TEST_CASE("integration: update and delete replication") {
    DB master_db, replica_db;
    master_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    replica_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");

    std::vector<ChangeEvent> events;
    ReplicaConfig rcfg;
    rcfg.on_change = [&](const ChangeEvent& e) {
        events.push_back(e);
        return true;
    };

    Master master(master_db.db);
    Replica replica(replica_db.db, rcfg);

    // Handshake.
    auto hello = replica.hello();
    deliver(master.handle_message(hello), replica);

    // Insert.
    master_db.exec("INSERT INTO t1 VALUES (1, 'hello')");
    deliver(master.flush(), replica);

    // Update.
    events.clear();
    master_db.exec("UPDATE t1 SET val='world' WHERE id=1");
    deliver(master.flush(), replica);

    CHECK(replica_db.query_val("SELECT val FROM t1 WHERE id=1") == "world");
    REQUIRE(events.size() == 1);
    CHECK(events[0].op == OpType::Update);

    // Delete.
    events.clear();
    master_db.exec("DELETE FROM t1 WHERE id=1");
    deliver(master.flush(), replica);

    CHECK(replica_db.count("t1") == 0);
    REQUIRE(events.size() == 1);
    CHECK(events[0].op == OpType::Delete);
}

TEST_CASE("integration: multiple tables") {
    DB master_db, replica_db;
    master_db.exec("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)");
    master_db.exec("CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INTEGER, item TEXT)");
    replica_db.exec("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)");
    replica_db.exec("CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INTEGER, item TEXT)");

    Master master(master_db.db);
    Replica replica(replica_db.db);

    // Handshake.
    deliver(master.handle_message(replica.hello()), replica);

    // Insert into both tables in same transaction.
    master_db.exec("BEGIN");
    master_db.exec("INSERT INTO users VALUES (1, 'Alice')");
    master_db.exec("INSERT INTO orders VALUES (1, 1, 'widget')");
    master_db.exec("COMMIT");
    deliver(master.flush(), replica);

    CHECK(replica_db.count("users") == 1);
    CHECK(replica_db.count("orders") == 1);
    CHECK(replica_db.query_val("SELECT name FROM users WHERE id=1") == "Alice");
    CHECK(replica_db.query_val("SELECT item FROM orders WHERE id=1") == "widget");
}
