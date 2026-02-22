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
};

} // namespace

TEST_CASE("master: initial state") {
    DB d;
    d.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    Master m(d.db);
    CHECK(m.current_seq() == 0);
}

TEST_CASE("master: flush with no changes returns empty") {
    DB d;
    d.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    Master m(d.db);
    auto msgs = m.flush();
    CHECK(msgs.empty());
}

TEST_CASE("master: flush after insert returns changeset") {
    DB d;
    d.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    Master m(d.db);

    d.exec("INSERT INTO t1 VALUES (1, 'hello')");
    auto msgs = m.flush();
    REQUIRE(msgs.size() == 1);
    CHECK(std::holds_alternative<ChangesetMsg>(msgs[0]));
    CHECK(std::get<ChangesetMsg>(msgs[0]).seq == 1);
    CHECK(m.current_seq() == 1);
}

TEST_CASE("master: multiple flushes increment seq") {
    DB d;
    d.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    Master m(d.db);

    d.exec("INSERT INTO t1 VALUES (1, 'a')");
    m.flush();
    d.exec("INSERT INTO t1 VALUES (2, 'b')");
    auto msgs = m.flush();

    REQUIRE(msgs.size() == 1);
    CHECK(std::get<ChangesetMsg>(msgs[0]).seq == 2);
    CHECK(m.current_seq() == 2);
}

TEST_CASE("master: flush after no-op change returns empty") {
    DB d;
    d.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    Master m(d.db);

    d.exec("INSERT INTO t1 VALUES (1, 'a')");
    m.flush();

    // Update to same value — session sees no net change.
    d.exec("UPDATE t1 SET val='a' WHERE id=1");
    auto msgs = m.flush();
    CHECK(msgs.empty());
}

TEST_CASE("master: handle_hello up-to-date") {
    DB d;
    d.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    Master m(d.db);
    d.exec("INSERT INTO t1 VALUES (1, 'a')");
    m.flush();

    auto sv = m.schema_version();
    auto msgs = m.handle_message(HelloMsg{kProtocolVersion, 1, sv});

    // Should get HelloMsg + CatchupEndMsg.
    REQUIRE(msgs.size() == 2);
    CHECK(std::holds_alternative<HelloMsg>(msgs[0]));
    CHECK(std::holds_alternative<CatchupEndMsg>(msgs[1]));
}

TEST_CASE("master: handle_hello with catchup") {
    DB d;
    d.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    Master m(d.db);

    d.exec("INSERT INTO t1 VALUES (1, 'a')");
    m.flush();
    d.exec("INSERT INTO t1 VALUES (2, 'b')");
    m.flush();
    d.exec("INSERT INTO t1 VALUES (3, 'c')");
    m.flush();

    auto sv = m.schema_version();
    // Replica at seq=1, master at seq=3 → catchup 2..3.
    auto msgs = m.handle_message(HelloMsg{kProtocolVersion, 1, sv});

    // HelloMsg + CatchupBegin + 2 Changesets + CatchupEnd.
    REQUIRE(msgs.size() == 5);
    CHECK(std::holds_alternative<HelloMsg>(msgs[0]));
    CHECK(std::holds_alternative<CatchupBeginMsg>(msgs[1]));
    CHECK(std::get<CatchupBeginMsg>(msgs[1]).from_seq == 2);
    CHECK(std::get<CatchupBeginMsg>(msgs[1]).to_seq == 3);
    CHECK(std::holds_alternative<ChangesetMsg>(msgs[2]));
    CHECK(std::get<ChangesetMsg>(msgs[2]).seq == 2);
    CHECK(std::holds_alternative<ChangesetMsg>(msgs[3]));
    CHECK(std::get<ChangesetMsg>(msgs[3]).seq == 3);
    CHECK(std::holds_alternative<CatchupEndMsg>(msgs[4]));
}
