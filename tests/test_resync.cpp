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

TEST_CASE("resync: schema mismatch triggers full resync") {
    DB master_db, replica_db;
    master_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");

    Master master(master_db.db);

    master_db.exec("INSERT INTO t1 VALUES (1, 'a')");
    master.flush();
    master_db.exec("INSERT INTO t1 VALUES (2, 'b')");
    master.flush();

    // Replica has a DIFFERENT schema (extra column) → fingerprint mismatch.
    replica_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT, extra TEXT)");

    Replica replica(replica_db.db);
    auto hello = replica.hello();
    auto master_resp = master.handle_message(hello);

    // Master should detect schema mismatch and send resync.
    REQUIRE(!master_resp.empty());
    CHECK(std::holds_alternative<ResyncBeginMsg>(master_resp[0]));

    auto acks = deliver(master_resp, replica);
    CHECK(replica.state() == Replica::State::Live);
    CHECK(replica_db.count("t1") == 2);
    CHECK(replica_db.query_val("SELECT val FROM t1 WHERE id=1") == "a");
    CHECK(replica_db.query_val("SELECT val FROM t1 WHERE id=2") == "b");
}

TEST_CASE("resync: generate_resync produces valid messages") {
    DB master_db;
    master_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    master_db.exec("INSERT INTO t1 VALUES (1, 'hello')");
    master_db.exec("INSERT INTO t1 VALUES (2, 'world')");

    Master master(master_db.db);
    master.flush();

    auto msgs = master.generate_resync();

    // Should have ResyncBegin, ResyncTable(t1), ResyncEnd.
    REQUIRE(msgs.size() >= 3);
    CHECK(std::holds_alternative<ResyncBeginMsg>(msgs[0]));
    CHECK(std::holds_alternative<ResyncEndMsg>(msgs.back()));

    // At least one ResyncTableMsg.
    bool found_table = false;
    for (const auto& m : msgs) {
        if (auto* rt = std::get_if<ResyncTableMsg>(&m)) {
            CHECK(rt->table_name == "t1");
            CHECK(!rt->data.empty());
            found_table = true;
        }
    }
    CHECK(found_table);
}

TEST_CASE("resync: log pruning forces resync") {
    DB master_db, replica_db;
    master_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    replica_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");

    MasterConfig cfg;
    cfg.max_log_entries = 2;  // keep only 2 entries
    Master master(master_db.db, cfg);

    // Generate 5 changesets; with max_log=2, only seq 4,5 remain.
    for (int i = 1; i <= 5; ++i) {
        master_db.exec(("INSERT INTO t1 VALUES (" + std::to_string(i) +
                         ", 'v" + std::to_string(i) + "')").c_str());
        master.flush();
    }

    // Replica connects at seq=0, log starts at seq=4 → gap → resync.
    Replica replica(replica_db.db);
    auto hello = replica.hello();
    auto master_resp = master.handle_message(hello);

    REQUIRE(!master_resp.empty());
    CHECK(std::holds_alternative<ResyncBeginMsg>(master_resp[0]));

    deliver(master_resp, replica);
    CHECK(replica.state() == Replica::State::Live);
    CHECK(replica_db.count("t1") == 5);
}

TEST_CASE("resync: replica receives change events during resync") {
    DB master_db, replica_db;
    master_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    replica_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");

    MasterConfig mcfg;
    mcfg.max_log_entries = 0;  // force resync for empty-log case

    Master master(master_db.db, mcfg);
    master_db.exec("INSERT INTO t1 VALUES (1, 'x')");
    master.flush();

    // Prune the only entry to force resync.
    // Actually, max_log_entries=0 means unlimited. Let's use 1.
    // Re-do with proper pruning:
    DB master_db2;
    master_db2.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    MasterConfig mcfg2;
    mcfg2.max_log_entries = 1;
    Master master2(master_db2.db, mcfg2);

    master_db2.exec("INSERT INTO t1 VALUES (1, 'x')");
    master2.flush();
    master_db2.exec("INSERT INTO t1 VALUES (2, 'y')");
    master2.flush();
    // Log now has only seq=2; replica at seq=0 needs seq=1 → gap → resync.

    std::vector<ChangeEvent> events;
    ReplicaConfig rcfg;
    rcfg.on_change = [&](const ChangeEvent& e) {
        events.push_back(e);
        return true;
    };

    Replica replica(replica_db.db, rcfg);
    auto hello = replica.hello();
    auto resp = master2.handle_message(hello);
    deliver(resp, replica);

    // Should have received INSERT events during resync.
    CHECK(!events.empty());
    for (const auto& e : events) {
        CHECK(e.op == OpType::Insert);
    }
}
