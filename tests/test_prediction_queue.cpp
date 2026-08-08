// Copyright 2026 The sqlpipe Authors
// SPDX-License-Identifier: Apache-2.0
//
// Edge-case suite for ReplicaConfig::queue_while_predicting and
// end_prediction() drain ordering.

#include <doctest.h>
#include <sqlpipe.h>

#include <sqlite3.h>

#include <memory>
#include <string>
#include <variant>
#include <vector>

using namespace sqlpipe;

namespace {

struct DB {
    sqlite3* db = nullptr;
    DB() { sqlite3_open(":memory:", &db); }
    ~DB() {
        if (db) sqlite3_close(db);
    }
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

const char* kSchema = "CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)";

struct Setup {
    DB master_db;
    DB replica_db;
    std::unique_ptr<Master> master;
    std::unique_ptr<Replica> replica;

    explicit Setup(bool queue_while_predicting = true) {
        master_db.exec(kSchema);
        replica_db.exec(kSchema);
        master = std::make_unique<Master>(master_db.db);
        ReplicaConfig c;
        c.queue_while_predicting = queue_while_predicting;
        replica = std::make_unique<Replica>(replica_db.db, c);
        sync_handshake(*master, *replica);
        REQUIRE(replica->state() == Replica::State::Live);
    }

    void predict_insert(int64_t id, const char* val) {
        replica->begin_prediction();
        std::string sql = "INSERT INTO t1 VALUES (" + std::to_string(id) +
                          ", '" + val + "')";
        replica_db.exec(sql.c_str());
    }

    void predict_insert_and_commit(int64_t id, const char* val) {
        predict_insert(id, val);
        replica->commit_prediction();
    }

    /// Master insert + flush; deliver each message to replica.
    /// Returns outbound messages from handle_message (empty when queued).
    HandleResult server_insert(int64_t id, const char* val) {
        std::string sql = "INSERT INTO t1 VALUES (" + std::to_string(id) +
                          ", '" + val + "')";
        master_db.exec(sql.c_str());
        auto msgs = master->flush();
        HandleResult combined;
        for (const auto& out : msgs) {
            auto hr = replica->handle_message(out.msg);
            combined.messages.insert(combined.messages.end(),
                                     hr.messages.begin(), hr.messages.end());
            combined.changes.insert(combined.changes.end(),
                                    hr.changes.begin(), hr.changes.end());
            combined.subscriptions.insert(combined.subscriptions.end(),
                                          hr.subscriptions.begin(),
                                          hr.subscriptions.end());
        }
        return combined;
    }

    /// Master update + flush + deliver.
    HandleResult server_update(int64_t id, const char* val) {
        std::string sql = "UPDATE t1 SET val = '" + std::string(val) +
                          "' WHERE id = " + std::to_string(id);
        master_db.exec(sql.c_str());
        auto msgs = master->flush();
        HandleResult combined;
        for (const auto& out : msgs) {
            auto hr = replica->handle_message(out.msg);
            combined.messages.insert(combined.messages.end(),
                                     hr.messages.begin(), hr.messages.end());
            combined.changes.insert(combined.changes.end(),
                                    hr.changes.begin(), hr.changes.end());
            combined.subscriptions.insert(combined.subscriptions.end(),
                                          hr.subscriptions.begin(),
                                          hr.subscriptions.end());
        }
        return combined;
    }

    std::vector<Seq> ack_seqs(const HandleResult& hr) {
        std::vector<Seq> seqs;
        for (const auto& out : hr.messages) {
            if (std::holds_alternative<AckMsg>(out.msg)) {
                seqs.push_back(std::get<AckMsg>(out.msg).seq);
            }
        }
        return seqs;
    }
};

}  // namespace

// ── Drafting vs Committed queueing ─────────────────────────────────

TEST_CASE("prediction queue: defers apply while still Drafting") {
    Setup s;
    s.predict_insert(1, "draft");
    // Do NOT commit — still Drafting.
    CHECK(s.replica_db.count("t1") == 1);

    auto hr = s.server_insert(2, "other");
    CHECK(hr.changes.empty());
    CHECK(hr.messages.empty());
    CHECK(s.replica->prediction_queue_size() == 1);
    CHECK(s.replica_db.count("t1") == 1);
    CHECK(s.replica_db.query_val("SELECT val FROM t1 WHERE id=1") == "draft");
    CHECK(s.replica_db.count("t1") == 1);

    // Commit then end — drain applies server row; draft overlay is gone
    // unless server also wrote it.
    s.replica->commit_prediction();
    auto end = s.replica->end_prediction();
    CHECK(s.replica->prediction_queue_size() == 0);
    CHECK(s.replica_db.count("t1") == 1);
    CHECK(s.replica_db.query_val("SELECT val FROM t1 WHERE id=2") == "other");
    CHECK(end.changes.size() >= 1);
}

TEST_CASE("prediction queue: defers apply while Committed") {
    Setup s;
    s.predict_insert_and_commit(1, "local");
    auto hr = s.server_insert(9, "remote");
    CHECK(hr.changes.empty());
    CHECK(s.replica->prediction_queue_size() == 1);
    CHECK(s.replica_db.query_val("SELECT val FROM t1 WHERE id=1") == "local");
    CHECK(s.replica_db.count("t1") == 1);

    s.replica->end_prediction();
    CHECK(s.replica_db.count("t1") == 1);
    CHECK(s.replica_db.query_val("SELECT val FROM t1 WHERE id=9") == "remote");
}

// ── Ordering of multiple queued changesets ─────────────────────────

TEST_CASE("prediction queue: drain preserves inbound order (A then B)") {
    Setup s;
    s.predict_insert_and_commit(1, "pred");

    s.server_insert(10, "A");
    s.server_insert(20, "B");
    s.server_insert(30, "C");
    CHECK(s.replica->prediction_queue_size() == 3);
    CHECK(s.replica_db.count("t1") == 1);  // still only prediction

    auto end = s.replica->end_prediction();
    CHECK(s.replica->prediction_queue_size() == 0);
    CHECK(s.replica_db.count("t1") == 3);
    CHECK(s.replica_db.query_val("SELECT val FROM t1 WHERE id=10") == "A");
    CHECK(s.replica_db.query_val("SELECT val FROM t1 WHERE id=20") == "B");
    CHECK(s.replica_db.query_val("SELECT val FROM t1 WHERE id=30") == "C");

    // Acks for each applied changeset, in seq order.
    auto acks = s.ack_seqs(end);
    REQUIRE(acks.size() == 3);
    CHECK(acks[0] + 1 == acks[1]);
    CHECK(acks[1] + 1 == acks[2]);
    CHECK(s.replica->current_seq() == acks.back());
}

TEST_CASE("prediction queue: truth-before-unrelated order on drain") {
    Setup s;
    s.predict_insert_and_commit(1, "predicted");

    // Matching truth first, then unrelated.
    s.server_insert(1, "predicted");
    s.server_insert(2, "other");
    CHECK(s.replica->prediction_queue_size() == 2);

    s.replica->end_prediction();
    CHECK(s.replica_db.count("t1") == 2);
    CHECK(s.replica_db.query_val("SELECT val FROM t1 WHERE id=1") == "predicted");
    CHECK(s.replica_db.query_val("SELECT val FROM t1 WHERE id=2") == "other");
}

TEST_CASE("prediction queue: unrelated-before-truth order on drain") {
    Setup s;
    s.predict_insert_and_commit(1, "predicted");

    s.server_insert(2, "other");
    s.server_insert(1, "predicted");
    CHECK(s.replica->prediction_queue_size() == 2);

    s.replica->end_prediction();
    CHECK(s.replica_db.count("t1") == 2);
    CHECK(s.replica_db.query_val("SELECT val FROM t1 WHERE id=1") == "predicted");
    CHECK(s.replica_db.query_val("SELECT val FROM t1 WHERE id=2") == "other");
}

TEST_CASE("prediction queue: server overwrites predicted value on drain") {
    Setup s;
    s.predict_insert_and_commit(1, "guess");

    s.server_insert(1, "authoritative");
    CHECK(s.replica_db.query_val("SELECT val FROM t1 WHERE id=1") == "guess");

    s.replica->end_prediction();
    CHECK(s.replica_db.count("t1") == 1);
    CHECK(s.replica_db.query_val("SELECT val FROM t1 WHERE id=1") ==
          "authoritative");
}

// ── handle_messages batch path ─────────────────────────────────────

TEST_CASE("prediction queue: handle_messages batches into the queue") {
    Setup s;
    s.predict_insert_and_commit(1, "p");

    s.master_db.exec("INSERT INTO t1 VALUES (2, 'x')");
    auto m1 = s.master->flush();
    s.master_db.exec("INSERT INTO t1 VALUES (3, 'y')");
    auto m2 = s.master->flush();
    REQUIRE(m1.size() == 1);
    REQUIRE(m2.size() == 1);

    std::vector<Message> batch{m1[0].msg, m2[0].msg};
    auto hr = s.replica->handle_messages(batch);
    CHECK(hr.changes.empty());
    CHECK(hr.messages.empty());
    CHECK(s.replica->prediction_queue_size() == 2);
    CHECK(s.replica_db.count("t1") == 1);

    s.replica->end_prediction();
    CHECK(s.replica_db.count("t1") == 2);
    CHECK(s.replica_db.query_val("SELECT val FROM t1 WHERE id=2") == "x");
    CHECK(s.replica_db.query_val("SELECT val FROM t1 WHERE id=3") == "y");
}

// ── Empty queue / lifecycle API ────────────────────────────────────

TEST_CASE("prediction queue: end with empty queue restores pre-prediction") {
    Setup s;
    s.predict_insert_and_commit(1, "only-local");
    CHECK(s.replica_db.count("t1") == 1);

    auto end = s.replica->end_prediction();
    CHECK(end.changes.empty());
    CHECK(end.messages.empty());
    CHECK(s.replica->prediction_queue_size() == 0);
    CHECK(s.replica_db.count("t1") == 0);
}

TEST_CASE("prediction queue: end while Drafting without commit") {
    Setup s;
    s.predict_insert(1, "draft-only");
    s.server_insert(2, "remote");
    CHECK(s.replica->prediction_queue_size() == 1);

    s.replica->end_prediction();
    CHECK(s.replica_db.count("t1") == 1);
    CHECK(s.replica_db.query_val("SELECT val FROM t1 WHERE id=2") == "remote");
}

TEST_CASE("prediction queue: rollback_prediction drains queue") {
    Setup s;
    s.predict_insert_and_commit(1, "cancel-me");
    s.server_insert(5, "kept");
    CHECK(s.replica->prediction_queue_size() == 1);

    s.replica->rollback_prediction();
    CHECK(s.replica->prediction_queue_size() == 0);
    CHECK(s.replica_db.count("t1") == 1);
    CHECK(s.replica_db.query_val("SELECT val FROM t1 WHERE id=5") == "kept");
}

TEST_CASE("prediction queue: end_prediction throws when none active") {
    Setup s;
    CHECK_THROWS_AS(s.replica->end_prediction(), Error);
}

TEST_CASE("prediction queue: double end throws") {
    Setup s;
    s.predict_insert_and_commit(1, "x");
    s.replica->end_prediction();
    CHECK_THROWS_AS(s.replica->end_prediction(), Error);
}

TEST_CASE("prediction queue: commit without begin throws") {
    Setup s;
    CHECK_THROWS_AS(s.replica->commit_prediction(), Error);
}

TEST_CASE("prediction queue: double begin throws") {
    Setup s;
    s.replica->begin_prediction();
    CHECK_THROWS_AS(s.replica->begin_prediction(), Error);
    s.replica->end_prediction();
}

// ── After drain: normal streaming resumes ──────────────────────────

TEST_CASE("prediction queue: after end, live apply is immediate again") {
    Setup s;
    s.predict_insert_and_commit(1, "p");
    s.server_insert(1, "p");
    s.replica->end_prediction();
    CHECK(s.replica->prediction_queue_size() == 0);

    auto hr = s.server_insert(2, "live");
    CHECK(s.replica->prediction_queue_size() == 0);
    CHECK(!hr.changes.empty());
    CHECK(s.replica_db.count("t1") == 2);
    CHECK(s.replica_db.query_val("SELECT val FROM t1 WHERE id=2") == "live");
}

TEST_CASE("prediction queue: sequential predictions each queue independently") {
    Setup s;

    // First gesture.
    s.predict_insert_and_commit(1, "a");
    s.server_insert(1, "a");
    s.replica->end_prediction();
    CHECK(s.replica_db.count("t1") == 1);

    // Second gesture — queue must start empty.
    s.predict_insert_and_commit(2, "b");
    CHECK(s.replica->prediction_queue_size() == 0);
    s.server_insert(2, "b");
    CHECK(s.replica->prediction_queue_size() == 1);
    s.replica->end_prediction();
    CHECK(s.replica_db.count("t1") == 2);
    CHECK(s.replica_db.query_val("SELECT val FROM t1 WHERE id=2") == "b");
}

// ── Interleaved local edits during open prediction ─────────────────

TEST_CASE("prediction queue: local writes while Drafting then remote queue") {
    Setup s;
    s.replica->begin_prediction();
    s.replica_db.exec("INSERT INTO t1 VALUES (1, 'v1')");
    s.replica_db.exec("UPDATE t1 SET val = 'v2' WHERE id = 1");
    CHECK(s.replica_db.query_val("SELECT val FROM t1 WHERE id=1") == "v2");

    s.server_insert(99, "noise");
    CHECK(s.replica->prediction_queue_size() == 1);
    // Local prediction still visible.
    CHECK(s.replica_db.query_val("SELECT val FROM t1 WHERE id=1") == "v2");

    s.replica->commit_prediction();
    s.server_insert(1, "v2");  // matching truth
    s.replica->end_prediction();
    CHECK(s.replica_db.count("t1") == 2);
    CHECK(s.replica_db.query_val("SELECT val FROM t1 WHERE id=1") == "v2");
    CHECK(s.replica_db.query_val("SELECT val FROM t1 WHERE id=99") == "noise");
}

TEST_CASE("prediction queue: remote updates while predicting leave paint intact") {
    Setup s;
    // Seed committed truth both sides.
    s.master_db.exec("INSERT INTO t1 VALUES (1, 'seed')");
    auto seed = s.master->flush();
    for (const auto& m : seed) s.replica->handle_message(m.msg);
    CHECK(s.replica_db.query_val("SELECT val FROM t1 WHERE id=1") == "seed");

    s.replica->begin_prediction();
    s.replica_db.exec("UPDATE t1 SET val = 'painting' WHERE id = 1");
    s.replica->commit_prediction();
    CHECK(s.replica_db.query_val("SELECT val FROM t1 WHERE id=1") == "painting");

    s.server_update(1, "from-server");
    CHECK(s.replica->prediction_queue_size() == 1);
    // Still shows local paint until end.
    CHECK(s.replica_db.query_val("SELECT val FROM t1 WHERE id=1") == "painting");

    s.replica->end_prediction();
    CHECK(s.replica_db.query_val("SELECT val FROM t1 WHERE id=1") ==
          "from-server");
}

// ── Subscriptions on drain ─────────────────────────────────────────

TEST_CASE("prediction queue: subscriptions fire on drain not while queued") {
    Setup s;
    auto sub = s.replica->subscribe("SELECT id, val FROM t1 ORDER BY id");

    s.predict_insert_and_commit(1, "p");
    // Local prediction may or may not notify via subscribe path (subscribe
    // results arrive on handle_message). Queue a server insert.
    auto queued = s.server_insert(2, "s");
    CHECK(queued.subscriptions.empty());

    auto end = s.replica->end_prediction();
    // Drain applied server row; subscription should re-evaluate.
    bool saw_sub = false;
    for (const auto& q : end.subscriptions) {
        if (q.id == sub) {
            saw_sub = true;
            // After drain: prediction rolled back, only server row 2 unless
            // we also queued row 1. Only row 2 was sent from server.
            CHECK(q.rows.size() == 1);
        }
    }
    CHECK(saw_sub);
}

TEST_CASE("prediction queue: subscription sees full truth after multi-drain") {
    Setup s;
    auto sub = s.replica->subscribe("SELECT COUNT(*) FROM t1");

    s.predict_insert_and_commit(1, "a");
    s.server_insert(1, "a");
    s.server_insert(2, "b");
    s.server_insert(3, "c");

    auto end = s.replica->end_prediction();
    CHECK(s.replica_db.count("t1") == 3);

    bool saw = false;
    for (const auto& q : end.subscriptions) {
        if (q.id == sub) {
            saw = true;
            REQUIRE(!q.rows.empty());
            REQUIRE(!q.rows[0].empty());
            CHECK(std::get<int64_t>(q.rows[0][0]) == 3);
        }
    }
    CHECK(saw);
}

// ── reset / reconnect interaction ──────────────────────────────────

TEST_CASE("prediction queue: reset drops queue; reconnect recovers truth") {
    Setup s;
    s.predict_insert_and_commit(1, "local");
    s.server_insert(2, "queued-lost");
    CHECK(s.replica->prediction_queue_size() == 1);

    s.replica->reset();
    CHECK(s.replica->prediction_queue_size() == 0);
    CHECK(s.replica_db.count("t1") == 0);

    // Master still has only row 2 (never got matching truth for 1).
    // Re-handshake / converge to pick up master state.
    sync_handshake(*s.master, *s.replica);
    // After handshake, replica should match master (row 2 only if master
    // never had row 1). Master has row 2 only.
    CHECK(s.master_db.count("t1") == 1);
    CHECK(s.replica_db.count("t1") == 1);
    CHECK(s.replica_db.query_val("SELECT val FROM t1 WHERE id=2") ==
          "queued-lost");
}

TEST_CASE("prediction queue: begin after reset with dropped queue is ok") {
    Setup s;
    s.predict_insert_and_commit(1, "x");
    s.server_insert(2, "y");
    s.replica->reset();
    sync_handshake(*s.master, *s.replica);

    s.replica->begin_prediction();
    s.replica_db.exec("INSERT INTO t1 VALUES (3, 'z')");
    s.replica->commit_prediction();
    CHECK(s.replica->prediction_queue_size() == 0);
    s.replica->end_prediction();
    // Prediction discarded; master never had 3.
    CHECK(s.replica_db.query_val("SELECT val FROM t1 WHERE id=2") == "y");
}

// ── Seq continuity ─────────────────────────────────────────────────

TEST_CASE("prediction queue: seq advances only on drain, then continuously") {
    Setup s;
    Seq seq0 = s.replica->current_seq();

    s.predict_insert_and_commit(1, "p");
    s.server_insert(10, "a");
    s.server_insert(20, "b");
    // Queued — seq must not advance yet.
    CHECK(s.replica->current_seq() == seq0);

    auto end = s.replica->end_prediction();
    auto acks = s.ack_seqs(end);
    REQUIRE(acks.size() == 2);
    CHECK(s.replica->current_seq() == seq0 + 2);

    s.server_insert(30, "c");
    CHECK(s.replica->current_seq() == seq0 + 3);
}

// ── Default (no queue) still clobbers mid-Committed ────────────────

TEST_CASE("prediction queue: disabled flag keeps auto-rollback semantics") {
    Setup s(/*queue_while_predicting=*/false);
    CHECK_FALSE(s.replica->queues_while_predicting());

    s.predict_insert_and_commit(1, "local");
    auto hr = s.server_insert(2, "remote");
    CHECK(s.replica->prediction_queue_size() == 0);
    CHECK(!hr.changes.empty());
    CHECK(s.replica_db.count("t1") == 1);
    CHECK(s.replica_db.query_val("SELECT val FROM t1 WHERE id=2") == "remote");
    // end_prediction must fail — already auto-cleared.
    CHECK_THROWS_AS(s.replica->end_prediction(), Error);
}

// ── Mixed: queue during Drafting, more after Commit ────────────────

TEST_CASE("prediction queue: messages across Drafting and Committed coalesce") {
    Setup s;
    s.predict_insert(1, "d");
    s.server_insert(2, "during-draft");
    CHECK(s.replica->prediction_queue_size() == 1);

    s.replica->commit_prediction();
    s.server_insert(3, "during-committed");
    CHECK(s.replica->prediction_queue_size() == 2);
    CHECK(s.replica_db.count("t1") == 1);

    s.replica->end_prediction();
    CHECK(s.replica_db.count("t1") == 2);
    CHECK(s.replica_db.query_val("SELECT val FROM t1 WHERE id=2") ==
          "during-draft");
    CHECK(s.replica_db.query_val("SELECT val FROM t1 WHERE id=3") ==
          "during-committed");
}

// ── Delete on server while predicting insert ───────────────────────

TEST_CASE("prediction queue: server delete of other row while predicting") {
    Setup s;
    s.master_db.exec("INSERT INTO t1 VALUES (5, 'keep')");
    auto seed = s.master->flush();
    for (const auto& m : seed) s.replica->handle_message(m.msg);
    CHECK(s.replica_db.count("t1") == 1);

    s.predict_insert_and_commit(1, "new");
    s.master_db.exec("DELETE FROM t1 WHERE id = 5");
    auto del = s.master->flush();
    for (const auto& m : del) {
        auto hr = s.replica->handle_message(m.msg);
        CHECK(hr.changes.empty());
    }
    CHECK(s.replica->prediction_queue_size() == 1);
    // Predicted insert still visible; seed row still visible (delete deferred).
    CHECK(s.replica_db.count("t1") == 2);

    s.server_insert(1, "new");
    s.replica->end_prediction();
    // Seed deleted, new row present.
    CHECK(s.replica_db.count("t1") == 1);
    CHECK(s.replica_db.query_val("SELECT val FROM t1 WHERE id=1") == "new");
}
