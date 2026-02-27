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

// Perform a full handshake (including diff exchange) between master and replica.
void handshake(Master& master, Replica& replica) {
    // replica → HelloMsg → master
    auto hello = replica.hello();
    auto resp = master.handle_message(hello);
    // master → HelloMsg → replica → BucketHashesMsg
    HandleResult r;
    for (const auto& m : resp) {
        auto result = replica.handle_message(m);
        r.messages.insert(r.messages.end(),
                          result.messages.begin(), result.messages.end());
    }
    // replica → BucketHashesMsg → master → NeedBucketsMsg (possibly + DiffReadyMsg)
    for (const auto& m : r.messages) {
        auto result = master.handle_message(m);
        HandleResult r2;
        for (const auto& m2 : result) {
            auto result2 = replica.handle_message(m2);
            r2.messages.insert(r2.messages.end(),
                               result2.messages.begin(), result2.messages.end());
        }
        // If NeedBucketsMsg had ranges, replica sends RowHashesMsg → master → DiffReadyMsg.
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
        result.subscriptions.insert(result.subscriptions.end(),
                                    resp.subscriptions.begin(),
                                    resp.subscriptions.end());
    }
    return result;
}

} // namespace

TEST_CASE("integration: fresh start, live streaming") {
    // Both databases start empty with the same schema.
    DB master_db, replica_db;
    master_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    replica_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");

    Master master(master_db.db);
    Replica replica(replica_db.db);

    handshake(master, replica);
    CHECK(replica.state() == Replica::State::Live);

    // Master inserts a row.
    master_db.exec("INSERT INTO t1 VALUES (1, 'hello')");
    auto changeset_msgs = master.flush();
    REQUIRE(changeset_msgs.size() == 1);

    // Deliver to replica.
    auto result = deliver(changeset_msgs, replica);
    REQUIRE(result.messages.size() == 1);
    CHECK(std::holds_alternative<AckMsg>(result.messages[0]));
    CHECK(std::get<AckMsg>(result.messages[0]).seq == 1);

    // Verify replica has the data.
    CHECK(replica_db.count("t1") == 1);
    CHECK(replica_db.query_val("SELECT val FROM t1 WHERE id=1") == "hello");
    CHECK(replica.current_seq() == 1);

    // Verify change events.
    REQUIRE(result.changes.size() == 1);
    CHECK(result.changes[0].table == "t1");
    CHECK(result.changes[0].op == OpType::Insert);
}

TEST_CASE("integration: diff sync after disconnect") {
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

    // Now replica connects — diff sync will discover the missing rows.
    Replica replica(replica_db.db);
    handshake(master, replica);

    CHECK(replica.state() == Replica::State::Live);
    CHECK(replica_db.count("t1") == 3);
    CHECK(replica_db.query_val("SELECT val FROM t1 WHERE id=2") == "b");
}

TEST_CASE("integration: update and delete replication") {
    DB master_db, replica_db;
    master_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    replica_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");

    Master master(master_db.db);
    Replica replica(replica_db.db);

    handshake(master, replica);

    // Insert.
    master_db.exec("INSERT INTO t1 VALUES (1, 'hello')");
    deliver(master.flush(), replica);

    // Update.
    master_db.exec("UPDATE t1 SET val='world' WHERE id=1");
    auto result = deliver(master.flush(), replica);

    CHECK(replica_db.query_val("SELECT val FROM t1 WHERE id=1") == "world");
    REQUIRE(result.changes.size() == 1);
    CHECK(result.changes[0].op == OpType::Update);

    // Delete.
    master_db.exec("DELETE FROM t1 WHERE id=1");
    result = deliver(master.flush(), replica);

    CHECK(replica_db.count("t1") == 0);
    REQUIRE(result.changes.size() == 1);
    CHECK(result.changes[0].op == OpType::Delete);
}

TEST_CASE("integration: multiple tables") {
    DB master_db, replica_db;
    master_db.exec("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)");
    master_db.exec("CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INTEGER, item TEXT)");
    replica_db.exec("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)");
    replica_db.exec("CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INTEGER, item TEXT)");

    Master master(master_db.db);
    Replica replica(replica_db.db);

    handshake(master, replica);

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

TEST_CASE("subscription: fires after live changeset") {
    DB master_db, replica_db;
    master_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    replica_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");

    Master master(master_db.db);
    Replica replica(replica_db.db);
    handshake(master, replica);

    // Subscribe to a query on the replica.
    auto qr = replica.subscribe("SELECT id, val FROM t1 ORDER BY id");
    CHECK(qr.rows.empty());  // nothing yet

    // Master inserts a row.
    master_db.exec("INSERT INTO t1 VALUES (1, 'hello')");
    auto result = deliver(master.flush(), replica);

    // Subscription should fire with the updated result.
    REQUIRE(result.subscriptions.size() == 1);
    CHECK(result.subscriptions[0].id == qr.id);
    REQUIRE(result.subscriptions[0].rows.size() == 1);
    CHECK(std::get<std::int64_t>(result.subscriptions[0].rows[0][0]) == 1);
    CHECK(std::get<std::string>(result.subscriptions[0].rows[0][1]) == "hello");
}

TEST_CASE("subscription: does not fire for unrelated table") {
    DB master_db, replica_db;
    master_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    master_db.exec("CREATE TABLE t2 (id INTEGER PRIMARY KEY, val TEXT)");
    replica_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    replica_db.exec("CREATE TABLE t2 (id INTEGER PRIMARY KEY, val TEXT)");

    Master master(master_db.db);
    Replica replica(replica_db.db);
    handshake(master, replica);

    // Subscribe to t1 only.
    replica.subscribe("SELECT * FROM t1");

    // Change t2 only.
    master_db.exec("INSERT INTO t2 VALUES (1, 'x')");
    auto result = deliver(master.flush(), replica);

    // Subscription should NOT fire.
    CHECK(result.subscriptions.empty());
}

TEST_CASE("subscription: multiple subscriptions, only relevant fires") {
    DB master_db, replica_db;
    master_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    master_db.exec("CREATE TABLE t2 (id INTEGER PRIMARY KEY, val TEXT)");
    replica_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    replica_db.exec("CREATE TABLE t2 (id INTEGER PRIMARY KEY, val TEXT)");

    Master master(master_db.db);
    Replica replica(replica_db.db);
    handshake(master, replica);

    auto sub1 = replica.subscribe("SELECT * FROM t1");
    auto sub2 = replica.subscribe("SELECT * FROM t2");

    // Change t1 only.
    master_db.exec("INSERT INTO t1 VALUES (1, 'a')");
    auto result = deliver(master.flush(), replica);

    // Only sub1 should fire.
    REQUIRE(result.subscriptions.size() == 1);
    CHECK(result.subscriptions[0].id == sub1.id);
}

TEST_CASE("subscription: JOIN query fires on either table") {
    DB master_db, replica_db;
    const char* schema =
        "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT);"
        "CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INTEGER, item TEXT)";
    master_db.exec(schema);
    replica_db.exec(schema);

    Master master(master_db.db);
    Replica replica(replica_db.db);
    handshake(master, replica);

    auto sub = replica.subscribe(
        "SELECT u.name, o.item FROM users u JOIN orders o ON o.user_id = u.id");
    CHECK(sub.rows.empty());

    // Insert into users only — JOIN still returns 0 rows (no orders yet),
    // so the subscription should NOT fire (result unchanged).
    master_db.exec("INSERT INTO users VALUES (1, 'Alice')");
    auto result = deliver(master.flush(), replica);
    CHECK(result.subscriptions.empty());

    // Insert into orders — now the JOIN produces a row, so it fires.
    master_db.exec("INSERT INTO orders VALUES (1, 1, 'widget')");
    result = deliver(master.flush(), replica);
    REQUIRE(result.subscriptions.size() == 1);
    CHECK(result.subscriptions[0].id == sub.id);
    CHECK(result.subscriptions[0].rows.size() == 1);
    CHECK(std::get<std::string>(result.subscriptions[0].rows[0][0]) == "Alice");
    CHECK(std::get<std::string>(result.subscriptions[0].rows[0][1]) == "widget");
}

TEST_CASE("subscription: unsubscribe prevents firing") {
    DB master_db, replica_db;
    master_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    replica_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");

    Master master(master_db.db);
    Replica replica(replica_db.db);
    handshake(master, replica);

    auto sub = replica.subscribe("SELECT * FROM t1");
    replica.unsubscribe(sub.id);

    master_db.exec("INSERT INTO t1 VALUES (1, 'a')");
    auto result = deliver(master.flush(), replica);

    CHECK(result.subscriptions.empty());
}

TEST_CASE("subscription: suppressed when result unchanged") {
    DB master_db, replica_db;
    master_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    replica_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");

    Master master(master_db.db);
    Replica replica(replica_db.db);
    handshake(master, replica);

    // Subscribe to a filtered query.
    auto sub = replica.subscribe("SELECT val FROM t1 WHERE id = 1");
    CHECK(sub.rows.empty());

    // Insert matching row — subscription fires.
    master_db.exec("INSERT INTO t1 VALUES (1, 'hello')");
    auto result = deliver(master.flush(), replica);
    REQUIRE(result.subscriptions.size() == 1);
    CHECK(std::get<std::string>(result.subscriptions[0].rows[0][0]) == "hello");

    // Insert a different row (id=2) — t1 changed but the query result didn't.
    master_db.exec("INSERT INTO t1 VALUES (2, 'world')");
    result = deliver(master.flush(), replica);
    CHECK(result.subscriptions.empty());

    // Update the matching row — result changes, fires again.
    master_db.exec("UPDATE t1 SET val='goodbye' WHERE id=1");
    result = deliver(master.flush(), replica);
    REQUIRE(result.subscriptions.size() == 1);
    CHECK(std::get<std::string>(result.subscriptions[0].rows[0][0]) == "goodbye");
}

TEST_CASE("integration: replica reset preserves subscriptions") {
    DB master_db, replica_db;
    master_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    replica_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");

    Master master(master_db.db);
    Replica replica(replica_db.db);

    handshake(master, replica);
    CHECK(replica.state() == Replica::State::Live);

    // Subscribe and deliver a row.
    auto sub = replica.subscribe("SELECT id, val FROM t1 ORDER BY id");
    CHECK(sub.rows.empty());

    master_db.exec("INSERT INTO t1 VALUES (1, 'hello')");
    auto result = deliver(master.flush(), replica);
    REQUIRE(result.subscriptions.size() == 1);
    CHECK(result.subscriptions[0].id == sub.id);

    // Simulate disconnect: reset replica and re-handshake.
    replica.reset();
    CHECK(replica.state() == Replica::State::Init);

    // Master adds a row while "disconnected".
    master_db.exec("INSERT INTO t1 VALUES (2, 'world')");
    master.flush();

    // Re-handshake — diff sync discovers the new row.
    handshake(master, replica);
    CHECK(replica.state() == Replica::State::Live);
    CHECK(replica_db.count("t1") == 2);

    // Subscription survived the reset — verify by triggering a new change.
    master_db.exec("INSERT INTO t1 VALUES (3, 'again')");
    result = deliver(master.flush(), replica);
    REQUIRE(result.subscriptions.size() == 1);
    CHECK(result.subscriptions[0].id == sub.id);
    CHECK(result.subscriptions[0].rows.size() == 3);
}

TEST_CASE("integration: diff sync progress callbacks") {
    DB master_db, replica_db;
    master_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    replica_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");

    // Master accumulates data while replica is disconnected.
    std::vector<DiffProgress> master_progress, replica_progress;

    MasterConfig mc;
    mc.on_progress = [&](const DiffProgress& p) {
        master_progress.push_back(p);
    };
    Master master(master_db.db, mc);

    master_db.exec("INSERT INTO t1 VALUES (1, 'a')");
    master.flush();
    master_db.exec("INSERT INTO t1 VALUES (2, 'b')");
    master.flush();

    ReplicaConfig rc;
    rc.on_progress = [&](const DiffProgress& p) {
        replica_progress.push_back(p);
    };
    Replica replica(replica_db.db, rc);
    handshake(master, replica);

    CHECK(replica.state() == Replica::State::Live);

    // Master should have reported: ComputingBuckets, ComparingBuckets,
    // ComputingRowHashes, BuildingPatchset.
    auto has_phase = [](const std::vector<DiffProgress>& v, DiffPhase ph) {
        for (const auto& p : v) if (p.phase == ph) return true;
        return false;
    };
    CHECK(has_phase(master_progress, DiffPhase::ComputingBuckets));
    CHECK(has_phase(master_progress, DiffPhase::ComparingBuckets));
    CHECK(has_phase(master_progress, DiffPhase::ComputingRowHashes));
    CHECK(has_phase(master_progress, DiffPhase::BuildingPatchset));

    // Replica should have reported: ComputingBuckets, ComputingRowHashes,
    // ApplyingPatchset.
    CHECK(has_phase(replica_progress, DiffPhase::ComputingBuckets));
    CHECK(has_phase(replica_progress, DiffPhase::ComputingRowHashes));
    CHECK(has_phase(replica_progress, DiffPhase::ApplyingPatchset));
}

TEST_CASE("integration: master schema migration hook resolves mismatch") {
    DB master_db, replica_db;
    // Replica has an extra column that the master lacks.
    master_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    replica_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT, extra TEXT)");

    bool callback_called = false;
    MasterConfig mc;
    mc.on_schema_mismatch = [&](SchemaVersion, SchemaVersion,
                                const std::string&) {
        callback_called = true;
        // Migrate: add the extra column to match the replica.
        master_db.exec("ALTER TABLE t1 ADD COLUMN extra TEXT");
        return true;
    };
    Master master(master_db.db, mc);
    Replica replica(replica_db.db);

    handshake(master, replica);

    CHECK(callback_called);
    CHECK(replica.state() == Replica::State::Live);
}

TEST_CASE("integration: master schema migration hook returns false") {
    DB master_db, replica_db;
    master_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    replica_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT, extra TEXT)");

    MasterConfig mc;
    mc.on_schema_mismatch = [&](SchemaVersion, SchemaVersion,
                                const std::string&) {
        return false;  // decline to fix
    };
    Master master(master_db.db, mc);
    Replica replica(replica_db.db);

    auto hello = replica.hello();
    auto resp = master.handle_message(hello);

    REQUIRE(resp.size() == 1);
    CHECK(std::holds_alternative<ErrorMsg>(resp[0]));
    CHECK(std::get<ErrorMsg>(resp[0]).code == ErrorCode::SchemaMismatch);
}

TEST_CASE("integration: replica schema migration hook resolves mismatch") {
    DB master_db, replica_db;
    master_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT, extra TEXT)");
    replica_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");

    Master master(master_db.db);

    bool callback_called = false;
    SchemaVersion received_remote_sv = 0;
    std::string received_remote_sql;
    ReplicaConfig rc;
    rc.on_schema_mismatch = [&](SchemaVersion remote_sv, SchemaVersion,
                                const std::string& remote_schema_sql) {
        callback_called = true;
        received_remote_sv = remote_sv;
        received_remote_sql = remote_schema_sql;
        // Migrate: add the missing column to match the master.
        replica_db.exec("ALTER TABLE t1 ADD COLUMN extra TEXT");
        return true;
    };
    Replica replica(replica_db.db, rc);

    // First handshake attempt: master sends ErrorMsg, replica callback fires.
    auto hello = replica.hello();
    auto master_resp = master.handle_message(hello);
    REQUIRE(master_resp.size() == 1);
    CHECK(std::holds_alternative<ErrorMsg>(master_resp[0]));

    auto result = replica.handle_message(master_resp[0]);
    CHECK(callback_called);
    // Replica callback must receive the master's real fingerprint and schema.
    CHECK(received_remote_sv == master.schema_version());
    CHECK(received_remote_sql.find("extra TEXT") != std::string::npos);
    // Replica should have reset to Init (not Error).
    CHECK(replica.state() == Replica::State::Init);

    // Second handshake should succeed now that schemas match.
    handshake(master, replica);
    CHECK(replica.state() == Replica::State::Live);
}

TEST_CASE("integration: batched handle_messages defers subscriptions") {
    DB master_db, replica_db;
    master_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    replica_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");

    Master master(master_db.db);
    Replica replica(replica_db.db);
    handshake(master, replica);

    auto sub = replica.subscribe("SELECT id, val FROM t1 ORDER BY id");
    CHECK(sub.rows.empty());

    // Generate 3 separate changesets.
    master_db.exec("INSERT INTO t1 VALUES (1, 'a')");
    auto m1 = master.flush();
    master_db.exec("INSERT INTO t1 VALUES (2, 'b')");
    auto m2 = master.flush();
    master_db.exec("INSERT INTO t1 VALUES (3, 'c')");
    auto m3 = master.flush();

    // Batch them all.
    std::vector<Message> batch;
    batch.insert(batch.end(), m1.begin(), m1.end());
    batch.insert(batch.end(), m2.begin(), m2.end());
    batch.insert(batch.end(), m3.begin(), m3.end());

    auto result = replica.handle_messages(batch);

    // All 3 changes should be applied.
    CHECK(result.changes.size() == 3);
    CHECK(replica_db.count("t1") == 3);

    // Subscription should fire exactly once with all 3 rows.
    REQUIRE(result.subscriptions.size() == 1);
    CHECK(result.subscriptions[0].rows.size() == 3);
}

TEST_CASE("integration: crash recovery after aborted changeset") {
    // Use temporary file-backed databases.
    std::string master_path = "/tmp/sqlpipe_test_master.db";
    std::string replica_path = "/tmp/sqlpipe_test_replica.db";
    std::remove(master_path.c_str());
    std::remove(replica_path.c_str());

    sqlite3* mdb = nullptr;
    sqlite3* rdb = nullptr;
    sqlite3_open(master_path.c_str(), &mdb);
    sqlite3_open(replica_path.c_str(), &rdb);

    auto exec = [](sqlite3* db, const char* sql) {
        char* err = nullptr;
        int rc = sqlite3_exec(db, sql, nullptr, nullptr, &err);
        if (rc != SQLITE_OK) {
            std::string msg = err ? err : "error";
            sqlite3_free(err);
            throw std::runtime_error(msg);
        }
    };

    exec(mdb, "CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    exec(rdb, "CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");

    // First session: normal sync.
    {
        Master master(mdb);
        Replica replica(rdb);
        handshake(master, replica);

        exec(mdb, "INSERT INTO t1 VALUES (1, 'hello')");
        auto msgs = master.flush();
        deliver(msgs, replica);
    }

    // Add more data while "disconnected".
    exec(mdb, "INSERT INTO t1 VALUES (2, 'world')");
    {
        Master m(mdb);
        m.flush();
    }

    // Close and reopen databases (simulating process restart).
    sqlite3_close(rdb);
    sqlite3_close(mdb);
    sqlite3_open(master_path.c_str(), &mdb);
    sqlite3_open(replica_path.c_str(), &rdb);

    // Re-sync should succeed.
    {
        Master master(mdb);
        Replica replica(rdb);
        handshake(master, replica);

        CHECK(replica.state() == Replica::State::Live);

        // Verify both rows are present.
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(rdb, "SELECT COUNT(*) FROM t1", -1, &stmt, nullptr);
        sqlite3_step(stmt);
        CHECK(sqlite3_column_int(stmt, 0) == 2);
        sqlite3_finalize(stmt);
    }

    sqlite3_close(rdb);
    sqlite3_close(mdb);
    std::remove(master_path.c_str());
    std::remove(replica_path.c_str());
}
