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

TEST_CASE("master: handle_hello returns HelloMsg") {
    DB d;
    d.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    Master m(d.db);

    auto sv = m.schema_version();
    auto msgs = m.handle_message(HelloMsg{kProtocolVersion, sv, {}});

    // Should get HelloMsg back.
    REQUIRE(msgs.size() == 1);
    CHECK(std::holds_alternative<HelloMsg>(msgs[0]));
    auto& reply = std::get<HelloMsg>(msgs[0]);
    CHECK(reply.schema_version == sv);
}

TEST_CASE("master: schema mismatch returns ErrorMsg") {
    DB d;
    d.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    Master m(d.db);

    // Send a hello with wrong schema version.
    auto msgs = m.handle_message(HelloMsg{kProtocolVersion, 99999, {}});

    REQUIRE(msgs.size() == 1);
    CHECK(std::holds_alternative<ErrorMsg>(msgs[0]));
    auto& err = std::get<ErrorMsg>(msgs[0]);
    CHECK(err.code == ErrorCode::SchemaMismatch);
    CHECK(err.remote_schema_version == m.schema_version());
    CHECK(!err.remote_schema_sql.empty());
}

TEST_CASE("master: bucket hashes all match produces empty DiffReady") {
    DB d;
    d.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    d.exec("INSERT INTO t1 VALUES (1, 'a')");
    d.exec("INSERT INTO t1 VALUES (2, 'b')");
    Master m(d.db);
    m.flush();
    m.flush(); // get seq up

    auto sv = m.schema_version();

    // Handshake: send HelloMsg.
    auto hello_resp = m.handle_message(HelloMsg{kProtocolVersion, sv, {}});
    REQUIRE(!hello_resp.empty());
    CHECK(std::holds_alternative<HelloMsg>(hello_resp[0]));

    // Now simulate replica sending matching bucket hashes.
    // We need to compute the same bucket hashes the master has.
    // Easiest: create a "replica" DB with same data and compute buckets.
    DB r;
    r.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    r.exec("INSERT INTO t1 VALUES (1, 'a')");
    r.exec("INSERT INTO t1 VALUES (2, 'b')");
    Replica replica(r.db);
    replica.hello();
    // Deliver master's HelloMsg to get BucketHashesMsg.
    auto replica_result = replica.handle_message(hello_resp[0]);
    REQUIRE(!replica_result.messages.empty());
    CHECK(std::holds_alternative<BucketHashesMsg>(replica_result.messages[0]));

    // Send those bucket hashes to master.
    auto bh_resp = m.handle_message(replica_result.messages[0]);
    // Should get NeedBucketsMsg (empty) + DiffReadyMsg (empty).
    REQUIRE(bh_resp.size() == 2);
    CHECK(std::holds_alternative<NeedBucketsMsg>(bh_resp[0]));
    CHECK(std::get<NeedBucketsMsg>(bh_resp[0]).ranges.empty());
    CHECK(std::holds_alternative<DiffReadyMsg>(bh_resp[1]));
    auto& dr = std::get<DiffReadyMsg>(bh_resp[1]);
    CHECK(dr.patchset.empty());
    CHECK(dr.deletes.empty());
}
