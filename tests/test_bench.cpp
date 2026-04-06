// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0
#include <doctest.h>
#include <sqlpipe.h>

#include <sqlite3.h>

#include <chrono>
#include <cstdio>
#include <string>

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
};

// Populate both databases with identical rows so they are fully in sync.
void populate(DB& master_db, DB& replica_db, Master& master, int rows) {
    master_db.exec("BEGIN");
    for (int i = 1; i <= rows; ++i) {
        char buf[256];
        std::snprintf(buf, sizeof(buf),
            "INSERT INTO t1 VALUES (%d, 'value_%d', %d)", i, i, i * 100);
        master_db.exec(buf);
    }
    master_db.exec("COMMIT");
    master.flush();

    // Replicate the same data into the replica DB directly so the
    // diff protocol sees no differences.
    replica_db.exec("BEGIN");
    for (int i = 1; i <= rows; ++i) {
        char buf[256];
        std::snprintf(buf, sizeof(buf),
            "INSERT INTO t1 VALUES (%d, 'value_%d', %d)", i, i, i * 100);
        replica_db.exec(buf);
    }
    replica_db.exec("COMMIT");
}

using Clock = std::chrono::steady_clock;

double elapsed_ms(Clock::time_point start) {
    auto end = Clock::now();
    return std::chrono::duration<double, std::milli>(end - start).count();
}

} // namespace

TEST_CASE("bench: diff sync 10k rows already in sync") {
    DB master_db, replica_db;
    const char* schema =
        "CREATE TABLE t1 (id INTEGER PRIMARY KEY, name TEXT, score INTEGER)";
    master_db.exec(schema);
    replica_db.exec(schema);

    Master master(master_db.db);
    populate(master_db, replica_db, master, 10000);

    CHECK(master_db.count("t1") == 10000);
    CHECK(replica_db.count("t1") == 10000);

    Replica replica(replica_db.db);

    auto start = Clock::now();
    sync_handshake(master, replica);
    double ms = elapsed_ms(start);

    MESSAGE("diff sync (10k rows, in sync): " << ms << " ms");
    CHECK(ms < 1000.0);  // Must complete under 1 second
    CHECK(replica_db.count("t1") == 10000);
}

TEST_CASE("bench: diff sync 10k rows with 1% differences") {
    DB master_db, replica_db;
    const char* schema =
        "CREATE TABLE t1 (id INTEGER PRIMARY KEY, name TEXT, score INTEGER)";
    master_db.exec(schema);
    replica_db.exec(schema);

    Master master(master_db.db);
    populate(master_db, replica_db, master, 10000);

    // Mutate 1% of rows on master (every 100th row).
    master_db.exec("BEGIN");
    for (int i = 1; i <= 10000; i += 100) {
        char buf[256];
        std::snprintf(buf, sizeof(buf),
            "UPDATE t1 SET name = 'updated_%d', score = %d WHERE id = %d",
            i, i * 999, i);
        master_db.exec(buf);
    }
    master_db.exec("COMMIT");
    master.flush();

    Replica replica(replica_db.db);

    auto start = Clock::now();
    sync_handshake(master, replica);
    double ms = elapsed_ms(start);

    MESSAGE("diff sync (10k rows, 1% diff): " << ms << " ms");
    CHECK(ms < 1000.0);
    CHECK(replica_db.count("t1") == 10000);
}

TEST_CASE("bench: diff sync 100k rows already in sync") {
    DB master_db, replica_db;
    const char* schema =
        "CREATE TABLE t1 (id INTEGER PRIMARY KEY, name TEXT, score INTEGER)";
    master_db.exec(schema);
    replica_db.exec(schema);

    Master master(master_db.db);
    populate(master_db, replica_db, master, 100000);

    CHECK(master_db.count("t1") == 100000);
    CHECK(replica_db.count("t1") == 100000);

    Replica replica(replica_db.db);

    auto start = Clock::now();
    sync_handshake(master, replica);
    double ms = elapsed_ms(start);

    MESSAGE("diff sync (100k rows, in sync): " << ms << " ms");
    CHECK(ms < 5000.0);  // 5 second budget for 100k
    CHECK(replica_db.count("t1") == 100000);
}
