// Copyright 2026 The sqlpipe Authors
// SPDX-License-Identifier: Apache-2.0
#include <doctest.h>
#include <sqlpipe.h>

using namespace sqlpipe;

TEST_CASE("database: open and exec") {
    Database db(":memory:", "CREATE TABLE t (id INTEGER PRIMARY KEY, val TEXT)");
    db.exec("INSERT INTO t VALUES (1, 'hello')");
    auto r = db.query("SELECT val FROM t WHERE id = 1");
    REQUIRE(r.rows.size() == 1);
    CHECK(std::get<std::string>(r.rows[0][0]) == "hello");
}

TEST_CASE("database: schema migration creates tables") {
    Database db(":memory:");
    // No tables yet.
    auto r1 = db.query("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='t'");
    CHECK(std::get<int64_t>(r1.rows[0][0]) == 0);

    // Reopen with schema DDL — sqlift should create the table.
    Database db2(":memory:", "CREATE TABLE t (id INTEGER PRIMARY KEY, val TEXT)");
    auto r2 = db2.query("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='t'");
    CHECK(std::get<int64_t>(r2.rows[0][0]) == 1);
}

TEST_CASE("database: subscription fires on change") {
    Database db(":memory:", "CREATE TABLE t (id INTEGER PRIMARY KEY, val TEXT)");
    int fired = 0;
    int64_t last_count = -1;
    auto sub = db.subscribe("SELECT count(*) FROM t", [&](const QueryResult& r) {
        fired++;
        last_count = std::get<int64_t>(r.rows[0][0]);
    });

    // Initial fire.
    CHECK(fired == 1);
    CHECK(last_count == 0);

    db.exec("INSERT INTO t VALUES (1, 'a')");
    CHECK(fired == 2);
    CHECK(last_count == 1);

    db.exec("INSERT INTO t VALUES (2, 'b')");
    CHECK(fired == 3);
    CHECK(last_count == 2);
}

TEST_CASE("database: subscription does not fire when result unchanged") {
    Database db(":memory:", "CREATE TABLE t (id INTEGER PRIMARY KEY, val TEXT)");
    int fired = 0;
    auto sub = db.subscribe("SELECT count(*) FROM t WHERE val = 'x'",
                            [&](const QueryResult&) { fired++; });

    // Initial fire (count=0).
    CHECK(fired == 1);

    // Insert a row that doesn't match the predicate.
    db.exec("INSERT INTO t VALUES (1, 'a')");
    // QueryWatch detects result unchanged (still 0), so no fire.
    CHECK(fired == 1);

    // Insert a matching row.
    db.exec("INSERT INTO t VALUES (2, 'x')");
    CHECK(fired == 2);
}

TEST_CASE("database: subscription auto-unsubscribes on destruction") {
    Database db(":memory:", "CREATE TABLE t (id INTEGER PRIMARY KEY, val TEXT)");
    int fired = 0;
    {
        auto sub = db.subscribe("SELECT count(*) FROM t",
                                [&](const QueryResult&) { fired++; });
        CHECK(fired == 1); // initial
        db.exec("INSERT INTO t VALUES (1, 'a')");
        CHECK(fired == 2);
    }
    // Subscription destroyed — no more callbacks.
    db.exec("INSERT INTO t VALUES (2, 'b')");
    CHECK(fired == 2);
}

TEST_CASE("database: subscription is move-safe") {
    Database db(":memory:", "CREATE TABLE t (id INTEGER PRIMARY KEY, val TEXT)");
    int fired = 0;
    auto sub1 = db.subscribe("SELECT count(*) FROM t",
                             [&](const QueryResult&) { fired++; });
    CHECK(fired == 1);

    auto sub2 = std::move(sub1);
    db.exec("INSERT INTO t VALUES (1, 'a')");
    CHECK(fired == 2); // still fires via sub2
}

TEST_CASE("database: handle() works with Master/Replica") {
    Database master_db(":memory:",
        "CREATE TABLE t (id INTEGER PRIMARY KEY, val TEXT)");
    Database replica_db(":memory:",
        "CREATE TABLE t (id INTEGER PRIMARY KEY, val TEXT)");

    Master master(master_db.handle());
    Replica replica(replica_db.handle());
    sync_handshake(master, replica);

    // Subscribe on replica side.
    int fired = 0;
    int64_t last_count = -1;
    auto sub = replica_db.subscribe("SELECT count(*) FROM t",
        [&](const QueryResult& r) {
            fired++;
            last_count = std::get<int64_t>(r.rows[0][0]);
        });
    CHECK(fired == 1); // initial (count=0)

    // Insert on master side.
    master_db.exec("INSERT INTO t VALUES (1, 'hello')");
    auto msgs = master.flush();

    // Apply on replica side.
    for (auto& msg : msgs) {
        replica.handle_message(msg);
    }
    // Notify replica_db so subscriptions fire.
    replica_db.notify();

    CHECK(fired == 2);
    CHECK(last_count == 1);
}

TEST_CASE("database: generate_migration static method") {
    auto plan = Database::migration(
        "",
        "CREATE TABLE t (id INTEGER PRIMARY KEY, val TEXT)");
    // sqlift returns a JSON plan for creating the table.
    CHECK(!plan.empty());
}

TEST_CASE("database: query returns correct columns") {
    Database db(":memory:", "CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT)");
    db.exec("INSERT INTO t VALUES (1, 'Alice')");
    auto r = db.query("SELECT id, name FROM t");
    REQUIRE(r.columns.size() == 2);
    CHECK(r.columns[0] == "id");
    CHECK(r.columns[1] == "name");
    REQUIRE(r.rows.size() == 1);
    CHECK(std::get<int64_t>(r.rows[0][0]) == 1);
    CHECK(std::get<std::string>(r.rows[0][1]) == "Alice");
}

TEST_CASE("database: sqldeep transpilation is automatic") {
    Database db(":memory:",
        "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT, qty INTEGER)");
    db.exec("INSERT INTO items VALUES (1, 'Widget', 10)");
    db.exec("INSERT INTO items VALUES (2, 'Gadget', 25)");

    // sqldeep object syntax: SELECT {col, col} → json_object(...)
    auto r = db.query("SELECT {id, name, qty} FROM items ORDER BY id");
    REQUIRE(r.rows.size() == 2);
    // The result should be a JSON string from json_object().
    auto& val = std::get<std::string>(r.rows[0][0]);
    CHECK(val.find("Widget") != std::string::npos);
}

TEST_CASE("database: sqldeep subscription works") {
    Database db(":memory:",
        "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT)");
    int fired = 0;
    std::string last_json;
    auto sub = db.subscribe("SELECT {id, name} FROM items ORDER BY id",
        [&](const QueryResult& r) {
            fired++;
            if (!r.rows.empty()) {
                last_json = std::get<std::string>(r.rows[0][0]);
            }
        });
    CHECK(fired == 1); // initial (empty)

    db.exec("INSERT INTO items VALUES (1, 'Alice')");
    CHECK(fired == 2);
    CHECK(last_json.find("Alice") != std::string::npos);
}

TEST_CASE("database: sqldeep mixed columns with object literal") {
    Database db(":memory:",
        "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT, qty INTEGER)");
    db.exec("INSERT INTO items VALUES (1, 'Widget', 10)");
    db.exec("INSERT INTO items VALUES (2, 'Gadget', 25)");

    // Mix plain columns with sqldeep object literal.
    auto r = db.query("SELECT id, {name, qty} FROM items ORDER BY id");
    REQUIRE(r.rows.size() == 2);
    // First column should be the plain id.
    CHECK(std::get<int64_t>(r.rows[0][0]) == 1);
    // Second column should be a JSON object string.
    auto& json = std::get<std::string>(r.rows[0][1]);
    CHECK(json.find("Widget") != std::string::npos);
    CHECK(json.find("10") != std::string::npos);
}
