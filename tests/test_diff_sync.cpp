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

// ── Convergence loop tests ─────────────────────────────────────────

TEST_CASE("convergence: replica-initiated sync without hello") {
    DB master_db, replica_db;
    master_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    replica_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");

    // Populate master.
    master_db.exec("INSERT INTO t1 VALUES (1, 'a')");
    master_db.exec("INSERT INTO t1 VALUES (2, 'b')");
    Master master(master_db.db);
    master.flush();
    master.flush();

    Replica replica(replica_db.db);

    // Instead of hello → handshake, use converge() directly.
    auto bucket_msgs = replica.converge();
    REQUIRE(!bucket_msgs.empty());
    CHECK(std::holds_alternative<BucketHashesMsg>(bucket_msgs[0]));

    // Feed bucket hashes to master — no prior HelloMsg needed.
    auto master_resp = master.handle_message(bucket_msgs[0]);
    REQUIRE(!master_resp.empty());

    // Master responds with NeedBuckets (+ maybe DiffReady).
    // Feed all responses to replica.
    for (const auto& om : master_resp) {
        auto hr = replica.handle_message(om);
        // Feed replica responses back to master.
        for (const auto& rom : hr.messages) {
            auto mr = master.handle_message(rom);
            // Continue relay if needed.
            for (const auto& m : mr) {
                replica.handle_message(m);
            }
        }
    }

    // Replica should reach Live and have the data.
    CHECK(replica.state() == Replica::State::Live);
    CHECK(replica_db.count("t1") == 2);
}

TEST_CASE("convergence: re-convergence check while live") {
    DB master_db, replica_db;
    master_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    replica_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");

    Master master(master_db.db);
    Replica replica(replica_db.db);
    sync_handshake(master, replica);
    CHECK(replica.state() == Replica::State::Live);

    // Insert and deliver one row.
    master_db.exec("INSERT INTO t1 VALUES (1, 'hello')");
    auto msgs = master.flush();
    for (const auto& om : msgs) replica.handle_message(om);
    CHECK(replica_db.count("t1") == 1);

    // Run a convergence check while already Live.
    // This verifies the master and replica are still in sync.
    auto bucket_msgs = replica.converge();
    REQUIRE(!bucket_msgs.empty());

    auto master_resp = master.handle_message(bucket_msgs[0]);
    // All buckets should match — master responds with empty NeedBuckets + DiffReady.
    REQUIRE(master_resp.size() == 2);
    CHECK(std::holds_alternative<NeedBucketsMsg>(master_resp[0]));
    CHECK(std::get<NeedBucketsMsg>(master_resp[0]).ranges.empty());
    CHECK(std::holds_alternative<DiffReadyMsg>(master_resp[1]));
    auto& dr = std::get<DiffReadyMsg>(master_resp[1]);
    CHECK(dr.patchset.empty());
    CHECK(dr.deletes.empty());

    // Feed back to replica — should stay Live and data unchanged.
    for (const auto& om : master_resp) {
        replica.handle_message(om);
    }
    CHECK(replica.state() == Replica::State::Live);
    CHECK(replica_db.count("t1") == 1);
}

TEST_CASE("convergence: queue replay via converge()") {
    DB master_db, replica_db;
    master_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    replica_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");

    MasterConfig cfg;
    cfg.changeset_queue_size = 16;
    Master master(master_db.db, cfg);
    Replica replica(replica_db.db);

    // Initial sync.
    sync_handshake(master, replica);
    CHECK(replica.state() == Replica::State::Live);

    // Deliver first changeset normally.
    master_db.exec("INSERT INTO t1 VALUES (1, 'a')");
    auto msgs = master.flush();
    for (const auto& om : msgs) replica.handle_message(om);
    CHECK(replica.current_seq() == 1);

    // Master writes more, but we "lose" the delivery.
    master_db.exec("INSERT INTO t1 VALUES (2, 'b')");
    master.flush();
    master_db.exec("INSERT INTO t1 VALUES (3, 'c')");
    master.flush();
    CHECK(master.current_seq() == 3);
    CHECK(replica.current_seq() == 1);

    // Replica converges — seq=1 is in the queue, so master replays
    // changesets 2 and 3 from the queue instead of doing full diff.
    auto bucket_msgs = replica.converge();
    auto master_resp = master.handle_message(bucket_msgs[0]);

    // Should get: NeedBuckets(empty) + DiffReady(empty) + Changeset(2) + Changeset(3).
    REQUIRE(master_resp.size() == 4);
    CHECK(std::holds_alternative<NeedBucketsMsg>(master_resp[0]));
    CHECK(std::holds_alternative<DiffReadyMsg>(master_resp[1]));
    CHECK(std::holds_alternative<ChangesetMsg>(master_resp[2]));
    CHECK(std::get<ChangesetMsg>(master_resp[2]).seq == 2);
    CHECK(std::holds_alternative<ChangesetMsg>(master_resp[3]));
    CHECK(std::get<ChangesetMsg>(master_resp[3]).seq == 3);

    // Feed to replica.
    for (const auto& om : master_resp) {
        replica.handle_message(om);
    }
    CHECK(replica.state() == Replica::State::Live);
    CHECK(replica.current_seq() == 3);
    CHECK(replica_db.count("t1") == 3);
}

TEST_CASE("convergence: repeated converge() calls are safe") {
    DB master_db, replica_db;
    master_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    replica_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");

    master_db.exec("INSERT INTO t1 VALUES (1, 'a')");
    Master master(master_db.db);
    master.flush();

    Replica replica(replica_db.db);

    // Call converge() multiple times before any response arrives.
    // Each call should be safe — just recomputes and resends.
    auto msgs1 = replica.converge();
    auto msgs2 = replica.converge();  // overwrites DiffBuckets state
    auto msgs3 = replica.converge();  // again

    CHECK(replica.state() == Replica::State::DiffBuckets);

    // Only the last round's BucketHashes matters — process it.
    auto master_resp = master.handle_message(msgs3[0]);

    // Feed responses back. The relay loop should converge.
    for (const auto& om : master_resp) {
        auto hr = replica.handle_message(om);
        for (const auto& rom : hr.messages) {
            auto mr = master.handle_message(rom);
            for (const auto& m : mr) {
                replica.handle_message(m);
            }
        }
    }

    CHECK(replica.state() == Replica::State::Live);
    CHECK(replica_db.count("t1") == 1);

    // Now deliver the old round's BucketHashes (msgs1) — stale.
    // The master sees last_seq=0 (stale), detects it's behind, and
    // responds (queue replay or fresh diff). Either way it's safe —
    // the replica is already converged, so applying the response
    // is a no-op or idempotent.
    auto stale_resp = master.handle_message(msgs1[0]);
    CHECK(!stale_resp.empty());  // master responds (not a silent drop)
}

TEST_CASE("convergence: re-convergence discovers missed changes") {
    DB master_db, replica_db;
    master_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    replica_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");

    Master master(master_db.db);
    Replica replica(replica_db.db);
    sync_handshake(master, replica);

    // Master writes but we "lose" the changeset (don't deliver).
    master_db.exec("INSERT INTO t1 VALUES (1, 'lost')");
    master.flush();  // changesets generated but not delivered
    master_db.exec("INSERT INTO t1 VALUES (2, 'also lost')");
    master.flush();

    CHECK(master_db.count("t1") == 2);
    CHECK(replica_db.count("t1") == 0);

    // Replica initiates convergence — discovers the gap.
    auto bucket_msgs = replica.converge();
    auto master_resp = master.handle_message(bucket_msgs[0]);

    // Relay the diff exchange.
    for (const auto& om : master_resp) {
        auto hr = replica.handle_message(om);
        for (const auto& rom : hr.messages) {
            auto mr = master.handle_message(rom);
            for (const auto& m : mr) {
                replica.handle_message(m);
            }
        }
    }

    // Replica should now have both rows.
    CHECK(replica.state() == Replica::State::Live);
    CHECK(replica_db.count("t1") == 2);
}

// ── Edge cases from TLA+ model ─────────────────────────────────────

TEST_CASE("convergence: live changeset during convergence round") {
    // Convergence round overlapping with live changeset delivery.
    // The master sends a changeset via flush() while also processing
    // a convergence probe. The replica should get both.
    DB master_db, replica_db;
    master_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    replica_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");

    Master master(master_db.db);
    Replica replica(replica_db.db);
    sync_handshake(master, replica);

    // Deliver one row normally.
    master_db.exec("INSERT INTO t1 VALUES (1, 'a')");
    auto msgs = master.flush();
    for (const auto& om : msgs) replica.handle_message(om);
    CHECK(replica.current_seq() == 1);

    // Master writes row 2 but we "lose" the changeset.
    master_db.exec("INSERT INTO t1 VALUES (2, 'b')");
    auto lost = master.flush();
    // Don't deliver.

    // Master writes row 3 and flushes (this one we keep).
    master_db.exec("INSERT INTO t1 VALUES (3, 'c')");
    auto kept = master.flush();

    // Meanwhile, replica starts a convergence round (stale — missing row 2).
    auto probe = replica.converge();
    auto master_resp = master.handle_message(probe[0]);

    // Master's response: queue replay for seq 2 and 3 (if queue covers),
    // or a diff patchset. Either way, feed it all to the replica.
    for (const auto& om : master_resp) {
        auto hr = replica.handle_message(om);
        for (const auto& rom : hr.messages) {
            master.handle_message(rom);
        }
    }

    // Also deliver the kept changeset (seq 3) — may be duplicate if
    // queue replay already delivered it. Should be safe (seq check).
    for (const auto& om : kept) {
        // Seq may not match if queue replay already advanced past it.
        // The replica handles seq gaps by throwing, so catch and ignore
        // if the seq was already applied.
        try {
            replica.handle_message(om);
        } catch (...) {
            // Expected: seq gap or duplicate.
        }
    }

    CHECK(replica.state() == Replica::State::Live);
    CHECK(replica_db.count("t1") == 3);
}

TEST_CASE("convergence: master writes during queue replay response") {
    // Master writes a new row after producing queue replay messages
    // but before the replica processes them.
    DB master_db, replica_db;
    master_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    replica_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");

    MasterConfig cfg;
    cfg.changeset_queue_size = 16;
    Master master(master_db.db, cfg);
    Replica replica(replica_db.db);
    sync_handshake(master, replica);

    // Deliver seq 1.
    master_db.exec("INSERT INTO t1 VALUES (1, 'a')");
    for (const auto& om : master.flush()) replica.handle_message(om);

    // Master writes 2 and 3, not delivered.
    master_db.exec("INSERT INTO t1 VALUES (2, 'b')");
    master.flush();
    master_db.exec("INSERT INTO t1 VALUES (3, 'c')");
    master.flush();

    // Replica converges — gets queue replay for 2 and 3.
    auto probe = replica.converge();
    auto replay = master.handle_message(probe[0]);

    // Master writes 4 AFTER producing the replay response.
    master_db.exec("INSERT INTO t1 VALUES (4, 'd')");
    auto new_flush = master.flush();

    // Deliver the replay, then the new changeset.
    for (const auto& om : replay) replica.handle_message(om);
    CHECK(replica.current_seq() == 3);

    for (const auto& om : new_flush) replica.handle_message(om);
    CHECK(replica.current_seq() == 4);
    CHECK(replica_db.count("t1") == 4);
}

TEST_CASE("convergence: stale DiffReady after queue replay") {
    // Replica converges twice. First round produces a DiffReady via full
    // diff. Second round uses queue replay. The stale DiffReady from
    // round 1 arrives after queue replay has already converged.
    DB master_db, replica_db;
    master_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    replica_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");

    MasterConfig cfg;
    cfg.changeset_queue_size = 16;
    Master master(master_db.db, cfg);
    Replica replica(replica_db.db);
    sync_handshake(master, replica);

    // Deliver seq 1.
    master_db.exec("INSERT INTO t1 VALUES (1, 'a')");
    for (const auto& om : master.flush()) replica.handle_message(om);

    // Master writes 2, not delivered.
    master_db.exec("INSERT INTO t1 VALUES (2, 'b')");
    master.flush();

    // Round 1: converge via full diff. Capture the master's response
    // but DON'T deliver to replica.
    auto probe1 = replica.converge();
    auto diff_resp = master.handle_message(probe1[0]);

    // Round 2: converge again. This time, master does queue replay.
    auto probe2 = replica.converge();
    auto replay_resp = master.handle_message(probe2[0]);

    // Deliver round 2 (queue replay) first.
    for (const auto& om : replay_resp) replica.handle_message(om);
    CHECK(replica.state() == Replica::State::Live);
    CHECK(replica_db.count("t1") == 2);

    // Now deliver round 1's stale diff response. Replica is already
    // Live and has all the data. Messages from the stale round are
    // processed — some may be no-ops, others may trigger benign errors
    // (e.g., patchset applying already-present rows). Either way, the
    // replica's data should remain correct.
    for (const auto& om : diff_resp) {
        try {
            replica.handle_message(om);
        } catch (const Error&) {
            // Stale patchset on already-converged data — benign.
        }
    }
    CHECK(replica_db.count("t1") == 2);
}

TEST_CASE("convergence: schema mismatch via converge()") {
    // Schema mismatch detected through converge() rather than hello().
    DB master_db, replica_db;
    master_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    replica_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT, extra INT)");

    Master master(master_db.db);
    Replica replica(replica_db.db);

    // converge() sends BucketHashes with schema_version.
    auto probe = replica.converge();
    auto resp = master.handle_message(probe[0]);

    // Master should detect schema mismatch and return ErrorMsg.
    REQUIRE(!resp.empty());
    CHECK(std::holds_alternative<ErrorMsg>(resp[0]));
    auto& err = std::get<ErrorMsg>(resp[0]);
    CHECK(err.code == ErrorCode::SchemaMismatch);
    CHECK(!err.remote_schema_sql.empty());
}
