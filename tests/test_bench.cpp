// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0
#include <doctest.h>
#include <sqlpipe.h>

#include <sqlite3.h>

#include <chrono>
#include <cstdio>
#include <string>
#include <vector>

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
    void exec(const std::string& sql) { exec(sql.c_str()); }
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

std::vector<Message> deliver_to_replica(const std::vector<Message>& msgs,
                                        Replica& replica) {
    std::vector<Message> back;
    for (const auto& m : msgs) {
        auto result = replica.handle_message(m);
        back.insert(back.end(), result.messages.begin(), result.messages.end());
    }
    return back;
}

std::vector<Message> deliver_to_master(const std::vector<Message>& msgs,
                                       Master& master) {
    std::vector<Message> responses;
    for (const auto& m : msgs) {
        auto result = master.handle_message(m);
        responses.insert(responses.end(), result.begin(), result.end());
    }
    return responses;
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

TEST_CASE("bench: diff sync 1M rows already in sync") {
    DB master_db, replica_db;
    const char* schema =
        "CREATE TABLE t1 (id INTEGER PRIMARY KEY, name TEXT, score INTEGER)";
    master_db.exec(schema);
    replica_db.exec(schema);

    Master master(master_db.db);
    populate(master_db, replica_db, master, 1000000);

    CHECK(master_db.count("t1") == 1000000);
    CHECK(replica_db.count("t1") == 1000000);

    Replica replica(replica_db.db);

    auto start = Clock::now();
    sync_handshake(master, replica);
    double ms = elapsed_ms(start);

    MESSAGE("diff sync (1M rows, in sync): " << ms << " ms");
    CHECK(ms < 30000.0);  // 30 second budget for 1M
    CHECK(replica_db.count("t1") == 1000000);
}

TEST_CASE("bench: diff sync 10k rows with continuous writes during handshake") {
    DB master_db, replica_db;
    master_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    replica_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");

    // Phase 1: bring master and replica to sync with 10k rows via live streaming.
    Master master(master_db.db);
    Replica replica(replica_db.db);
    sync_handshake(master, replica);
    REQUIRE(replica.state() == Replica::State::Live);

    const int batch_size = 500;
    int next_id = 1;
    while (next_id <= 10000) {
        master_db.exec("BEGIN");
        for (int k = 0; k < batch_size && next_id <= 10000; ++k, ++next_id) {
            master_db.exec("INSERT INTO t1 VALUES (" +
                           std::to_string(next_id) + ", 'val" +
                           std::to_string(next_id) + "')");
        }
        master_db.exec("COMMIT");
        auto msgs = master.flush();
        for (const auto& m : msgs) {
            replica.handle_message(m);
        }
    }
    REQUIRE(master_db.count("t1") == 10000);
    REQUIRE(replica_db.count("t1") == 10000);

    // Phase 2: simulate reconnect with writes during the handshake.
    Master master2(master_db.db);
    Replica replica2(replica_db.db);
    std::vector<Message> queued_flushes;

    auto start = Clock::now();

    auto write_and_queue = [&]() {
        master_db.exec("INSERT INTO t1 VALUES (" +
                       std::to_string(next_id) + ", 'live" +
                       std::to_string(next_id) + "')");
        ++next_id;
        auto msgs = master2.flush();
        queued_flushes.insert(queued_flushes.end(), msgs.begin(), msgs.end());
    };

    // Round 1: HelloMsg
    auto hello = replica2.hello();
    write_and_queue();
    auto master_hello_resp = deliver_to_master({hello}, master2);
    write_and_queue();

    // Round 2: BucketHashesMsg
    auto replica_resp = deliver_to_replica(master_hello_resp, replica2);
    write_and_queue();
    auto master_resp2 = deliver_to_master(replica_resp, master2);
    write_and_queue();

    // Round 3: RowHashesMsg (if needed)
    auto replica_resp2 = deliver_to_replica(master_resp2, replica2);
    write_and_queue();
    auto master_resp3 = deliver_to_master(replica_resp2, master2);
    write_and_queue();

    // Round 4: DiffReady → Ack
    auto replica_resp3 = deliver_to_replica(master_resp3, replica2);
    write_and_queue();
    if (!replica_resp3.empty()) {
        auto master_resp4 = deliver_to_master(replica_resp3, master2);
        write_and_queue();
        deliver_to_replica(master_resp4, replica2);
    }

    // Phase 3: deliver queued flush messages (stale ones silently skipped).
    for (const auto& m : queued_flushes) {
        try {
            replica2.handle_message(m);
        } catch (const Error&) {
            // Stale changeset: seq already covered by DiffReady.
        }
    }

    double ms = elapsed_ms(start);

    CHECK(replica2.state() == Replica::State::Live);
    int writes_during = next_id - 10001;
    int expected_total = 10000 + writes_during;
    CHECK(master_db.count("t1") == expected_total);
    CHECK(replica_db.count("t1") == expected_total);
    CHECK(ms < 5000.0);

    MESSAGE("diff sync (10k rows, continuous writes): " << ms << " ms");
    MESSAGE("rows written during handshake: " << writes_during);
    MESSAGE("total rows: " << expected_total);
}

TEST_CASE("bench: diff sync reconnect after 10k rows accumulated") {
    constexpr int kInitialRows = 1000;
    constexpr int kAccumRows = 10000;
    constexpr int kBatchSize = 1000;

    DB master_db, replica_db;
    const char* schema =
        "CREATE TABLE t1 (id INTEGER PRIMARY KEY, name TEXT, score INTEGER)";
    master_db.exec(schema);
    replica_db.exec(schema);

    // Phase 1: initial sync of 1k rows.
    {
        Master master(master_db.db);
        master_db.exec("BEGIN");
        for (int i = 1; i <= kInitialRows; ++i) {
            char buf[256];
            std::snprintf(buf, sizeof(buf),
                "INSERT INTO t1 VALUES (%d, 'name_%d', %d)", i, i, i * 10);
            master_db.exec(buf);
        }
        master_db.exec("COMMIT");
        master.flush();

        Replica replica(replica_db.db);
        sync_handshake(master, replica);
        CHECK(replica.state() == Replica::State::Live);
        CHECK(replica_db.count("t1") == kInitialRows);
    }

    // Phase 2: accumulate 10k more rows while "disconnected".
    {
        Master master(master_db.db);
        for (int batch = 0; batch < kAccumRows / kBatchSize; ++batch) {
            master_db.exec("BEGIN");
            for (int i = 0; i < kBatchSize; ++i) {
                int id = kInitialRows + batch * kBatchSize + i + 1;
                char buf[256];
                std::snprintf(buf, sizeof(buf),
                    "INSERT INTO t1 VALUES (%d, 'name_%d', %d)", id, id, id * 10);
                master_db.exec(buf);
            }
            master_db.exec("COMMIT");
            master.flush();
        }
    }
    CHECK(master_db.count("t1") == kInitialRows + kAccumRows);

    // Phase 3: reconnect — diff sync from stale replica.
    Master master(master_db.db);
    Replica new_replica(replica_db.db);

    auto start = Clock::now();
    sync_handshake(master, new_replica);
    double ms = elapsed_ms(start);

    MESSAGE("diff sync reconnect (1k→11k): " << ms << " ms");
    CHECK(new_replica.state() == Replica::State::Live);
    CHECK(replica_db.count("t1") == kInitialRows + kAccumRows);
    CHECK(ms < 5000.0);
}
