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
    CHECK(std::holds_alternative<ChangesetMsg>(msgs[0].msg));
    CHECK(std::get<ChangesetMsg>(msgs[0].msg).seq == 1);
    CHECK(msgs[0].delivery == Delivery::Reliable);
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
    CHECK(std::get<ChangesetMsg>(msgs[0].msg).seq == 2);
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
    CHECK(std::holds_alternative<HelloMsg>(msgs[0].msg));
    auto& reply = std::get<HelloMsg>(msgs[0].msg);
    CHECK(reply.schema_version == sv);
    CHECK(msgs[0].delivery == Delivery::Reliable);
}

TEST_CASE("master: schema mismatch returns ErrorMsg") {
    DB d;
    d.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    Master m(d.db);

    // Send a hello with wrong schema version.
    auto msgs = m.handle_message(HelloMsg{kProtocolVersion, 99999, {}});

    REQUIRE(msgs.size() == 1);
    CHECK(std::holds_alternative<ErrorMsg>(msgs[0].msg));
    auto& err = std::get<ErrorMsg>(msgs[0].msg);
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
    CHECK(std::holds_alternative<HelloMsg>(hello_resp[0].msg));

    // Now simulate replica sending matching bucket hashes.
    DB r;
    r.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    r.exec("INSERT INTO t1 VALUES (1, 'a')");
    r.exec("INSERT INTO t1 VALUES (2, 'b')");
    Replica replica(r.db);
    replica.hello();
    // Deliver master's HelloMsg to get BucketHashesMsg.
    auto replica_result = replica.handle_message(hello_resp[0].msg);
    REQUIRE(!replica_result.messages.empty());
    CHECK(std::holds_alternative<BucketHashesMsg>(replica_result.messages[0].msg));

    // Send those bucket hashes to master.
    auto bh_resp = m.handle_message(replica_result.messages[0].msg);
    // Should get NeedBucketsMsg (empty) + DiffReadyMsg (empty).
    REQUIRE(bh_resp.size() == 2);
    CHECK(std::holds_alternative<NeedBucketsMsg>(bh_resp[0].msg));
    CHECK(std::get<NeedBucketsMsg>(bh_resp[0].msg).ranges.empty());
    CHECK(bh_resp[0].delivery == Delivery::BestEffort);
    CHECK(std::holds_alternative<DiffReadyMsg>(bh_resp[1].msg));
    auto& dr = std::get<DiffReadyMsg>(bh_resp[1].msg);
    CHECK(dr.patchset.empty());
    CHECK(dr.deletes.empty());
    CHECK(bh_resp[1].delivery == Delivery::Reliable);
}

TEST_CASE("master: on_flush fires automatically on commit") {
    DB d;
    d.exec("CREATE TABLE t (id INTEGER PRIMARY KEY, val TEXT)");

    std::vector<std::vector<OutMessage>> received;
    MasterConfig cfg;
    cfg.on_flush = [&](const std::vector<OutMessage>& msgs) {
        received.push_back(msgs);
    };
    Master master(d.db, cfg);

    CHECK(received.empty());

    // Single insert via master.exec — auto-flush fires.
    master.exec("INSERT INTO t VALUES (1, 'hello')");
    REQUIRE(received.size() == 1);
    REQUIRE(received[0].size() == 1);
    CHECK(std::holds_alternative<ChangesetMsg>(received[0][0].msg));
    CHECK(std::get<ChangesetMsg>(received[0][0].msg).seq == 1);

    // Another insert — seq increments.
    master.exec("INSERT INTO t VALUES (2, 'world')");
    REQUIRE(received.size() == 2);
    CHECK(std::get<ChangesetMsg>(received[1][0].msg).seq == 2);

    // No-op — on_flush should NOT fire.
    master.exec("SELECT 1");
    CHECK(received.size() == 2);
}

TEST_CASE("master: on_flush delivers to replica") {
    DB master_db, replica_db;
    const char* schema = "CREATE TABLE t (id INTEGER PRIMARY KEY, val TEXT)";
    master_db.exec(schema);
    replica_db.exec(schema);

    Replica replica(replica_db.db);

    // Accumulate messages from on_flush.
    std::vector<OutMessage> pending;
    MasterConfig cfg;
    cfg.on_flush = [&](const std::vector<OutMessage>& msgs) {
        pending.insert(pending.end(), msgs.begin(), msgs.end());
    };
    Master master(master_db.db, cfg);

    // Handshake (manual — on_flush only fires on data commits).
    sync_handshake(master, replica);
    CHECK(replica.state() == Replica::State::Live);

    // Write via master.exec triggers auto-flush.
    master.exec("INSERT INTO t VALUES (1, 'hello')");
    REQUIRE(pending.size() == 1);

    // Feed to replica.
    auto result = replica.handle_message(pending[0].msg);
    CHECK(result.changes.size() == 1);
    CHECK(result.changes[0].table == "t");
    CHECK(replica.current_seq() == 1);
}

TEST_CASE("master: on_flush transaction rollback produces nothing") {
    DB d;
    d.exec("CREATE TABLE t (id INTEGER PRIMARY KEY, val TEXT)");

    std::vector<std::vector<OutMessage>> received;
    MasterConfig cfg;
    cfg.on_flush = [&](const std::vector<OutMessage>& msgs) {
        received.push_back(msgs);
    };
    Master master(d.db, cfg);

    master.exec("BEGIN");
    master.exec("INSERT INTO t VALUES (1, 'hello')");
    master.exec("ROLLBACK");
    CHECK(received.empty());  // nothing committed, no flush
}

TEST_CASE("master: changeset queue replay on reconnect") {
    DB master_db, replica_db;
    const char* schema = "CREATE TABLE t (id INTEGER PRIMARY KEY, val TEXT)";
    master_db.exec(schema);
    replica_db.exec(schema);

    MasterConfig cfg;
    cfg.changeset_queue_size = 16;
    Master master(master_db.db, cfg);
    Replica replica(replica_db.db);

    // Initial handshake.
    sync_handshake(master, replica);
    CHECK(replica.state() == Replica::State::Live);

    // Write two changesets.
    master_db.exec("INSERT INTO t VALUES (1, 'a')");
    auto msgs1 = master.flush();
    auto result1 = replica.handle_message(msgs1[0].msg);
    CHECK(replica.current_seq() == 1);

    master_db.exec("INSERT INTO t VALUES (2, 'b')");
    auto msgs2 = master.flush();
    auto result2 = replica.handle_message(msgs2[0].msg);
    CHECK(replica.current_seq() == 2);

    // Now write more changesets WITHOUT delivering to replica.
    master_db.exec("INSERT INTO t VALUES (3, 'c')");
    auto msgs3 = master.flush();
    master_db.exec("INSERT INTO t VALUES (4, 'd')");
    auto msgs4 = master.flush();
    CHECK(master.current_seq() == 4);

    // Reset replica for reconnect.
    replica.reset();
    CHECK(replica.state() == Replica::State::Init);
    CHECK(replica.current_seq() == 2);

    // Reconnect: replica sends hello with seq=2, master has queue with 1-4.
    auto hello = replica.hello();
    auto reconnect_resp = master.handle_message(hello.msg);

    // Master should replay changesets 3,4 from queue (seq 3 and 4),
    // plus HelloMsg at the front.
    REQUIRE(reconnect_resp.size() == 3);
    CHECK(std::holds_alternative<HelloMsg>(reconnect_resp[0].msg));
    CHECK(std::holds_alternative<ChangesetMsg>(reconnect_resp[1].msg));
    CHECK(std::get<ChangesetMsg>(reconnect_resp[1].msg).seq == 3);
    CHECK(std::holds_alternative<ChangesetMsg>(reconnect_resp[2].msg));
    CHECK(std::get<ChangesetMsg>(reconnect_resp[2].msg).seq == 4);

    // Apply to replica — should go Live.
    for (const auto& om : reconnect_resp) {
        replica.handle_message(om.msg);
    }
    CHECK(replica.current_seq() == 4);
    CHECK(replica.state() == Replica::State::Live);
}

TEST_CASE("master: changeset queue disabled (size=0) falls back to diff") {
    DB master_db, replica_db;
    const char* schema = "CREATE TABLE t (id INTEGER PRIMARY KEY, val TEXT)";
    master_db.exec(schema);
    replica_db.exec(schema);

    MasterConfig cfg;
    cfg.changeset_queue_size = 0;
    Master master(master_db.db, cfg);
    Replica replica(replica_db.db);

    sync_handshake(master, replica);

    // Write and deliver seq 1.
    master_db.exec("INSERT INTO t VALUES (1, 'a')");
    auto msgs1 = master.flush();
    replica.handle_message(msgs1[0].msg);

    // Write seq 2 without delivering.
    master_db.exec("INSERT INTO t VALUES (2, 'b')");
    master.flush();

    // Reconnect — with queue disabled, should fall through to diff sync.
    replica.reset();
    auto hello = replica.hello();
    auto resp = master.handle_message(hello.msg);
    REQUIRE(!resp.empty());
    // Should get a HelloMsg (starting diff sync), NOT queue replay.
    CHECK(std::holds_alternative<HelloMsg>(resp[0].msg));
    auto& h = std::get<HelloMsg>(resp[0].msg);
    CHECK(h.last_seq == -1);  // diff sync, not fast reconnect
}
