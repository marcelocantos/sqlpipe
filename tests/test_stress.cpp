// Copyright 2026 The sqlpipe Authors
// SPDX-License-Identifier: Apache-2.0
#include <doctest.h>
#include <sqlpipe.h>

#include <sqlite3.h>

#include <random>
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
    // Get all rows from a table as "id:val" strings, sorted by id.
    std::vector<std::string> rows(const char* table) {
        std::string sql = std::string("SELECT id, val FROM ") +
                          table + " ORDER BY id";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
        std::vector<std::string> result;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            int id = sqlite3_column_int(stmt, 0);
            auto* text = reinterpret_cast<const char*>(
                sqlite3_column_text(stmt, 1));
            result.push_back(std::to_string(id) + ":" +
                             (text ? text : "NULL"));
        }
        sqlite3_finalize(stmt);
        return result;
    }
};

// Perform a full handshake between master and replica.
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
                               result2.messages.begin(),
                               result2.messages.end());
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

PeerHandleResult deliver(const std::vector<PeerMessage>& msgs, Peer& handler) {
    PeerHandleResult result;
    for (const auto& m : msgs) {
        auto resp = handler.handle_message(m);
        result.messages.insert(result.messages.end(),
                               resp.messages.begin(), resp.messages.end());
        result.changes.insert(result.changes.end(),
                              resp.changes.begin(), resp.changes.end());
    }
    return result;
}

void exchange(Peer& a, Peer& b, const std::vector<PeerMessage>& initial) {
    auto msgs = initial;
    while (!msgs.empty()) {
        auto resp_b = deliver(msgs, b);
        msgs.clear();
        if (!resp_b.messages.empty()) {
            auto resp_a = deliver(resp_b.messages, a);
            msgs = std::move(resp_a.messages);
        }
    }
}

std::string random_string(std::mt19937& rng, int maxlen = 20) {
    std::uniform_int_distribution<int> len_dist(1, maxlen);
    std::uniform_int_distribution<int> char_dist('a', 'z');
    int len = len_dist(rng);
    std::string s;
    s.reserve(static_cast<std::size_t>(len));
    for (int i = 0; i < len; ++i) {
        s.push_back(static_cast<char>(char_dist(rng)));
    }
    return s;
}

// Verify two databases have identical content in the given table.
void check_convergence(DB& a, DB& b, const char* table) {
    auto rows_a = a.rows(table);
    auto rows_b = b.rows(table);
    CHECK(rows_a == rows_b);
}

} // namespace

TEST_CASE("stress: random live streaming converges") {
    DB master_db, replica_db;
    master_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    replica_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");

    Master master(master_db.db);
    Replica replica(replica_db.db);
    handshake(master, replica);

    std::mt19937 rng(42);
    std::uniform_int_distribution<int> op_dist(0, 2);  // insert, update, delete
    std::uniform_int_distribution<int> id_dist(1, 50);

    int next_id = 1;
    std::set<int> existing_ids;

    for (int i = 0; i < 200; ++i) {
        int op = existing_ids.empty() ? 0 : op_dist(rng);

        if (op == 0) {
            // INSERT
            int id = next_id++;
            std::string val = random_string(rng);
            master_db.exec(("INSERT INTO t1 VALUES (" +
                            std::to_string(id) + ", '" + val + "')").c_str());
            existing_ids.insert(id);
        } else if (op == 1) {
            // UPDATE a random existing row.
            auto it = existing_ids.begin();
            std::advance(it,
                std::uniform_int_distribution<int>(
                    0, static_cast<int>(existing_ids.size()) - 1)(rng));
            std::string val = random_string(rng);
            master_db.exec(("UPDATE t1 SET val='" + val +
                            "' WHERE id=" + std::to_string(*it)).c_str());
        } else {
            // DELETE a random existing row.
            auto it = existing_ids.begin();
            std::advance(it,
                std::uniform_int_distribution<int>(
                    0, static_cast<int>(existing_ids.size()) - 1)(rng));
            master_db.exec(("DELETE FROM t1 WHERE id=" +
                            std::to_string(*it)).c_str());
            existing_ids.erase(it);
        }

        auto msgs = master.flush();
        auto result = deliver(msgs, replica);
        // Feed acks back to master.
        for (const auto& m : result.messages) {
            master.handle_message(m);
        }
    }

    check_convergence(master_db, replica_db, "t1");
}

TEST_CASE("stress: random operations with diff sync") {
    DB master_db, replica_db;
    master_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    replica_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");

    std::mt19937 rng(123);

    // Populate master with random data.
    Master master(master_db.db);
    for (int i = 1; i <= 100; ++i) {
        std::string val = random_string(rng);
        master_db.exec(("INSERT INTO t1 VALUES (" +
                        std::to_string(i) + ", '" + val + "')").c_str());
    }
    master.flush();

    // Populate replica with partially overlapping stale data.
    for (int i = 50; i <= 120; ++i) {
        std::string val = random_string(rng);
        replica_db.exec(("INSERT INTO t1 VALUES (" +
                         std::to_string(i) + ", '" + val + "')").c_str());
    }

    // Diff sync should bring replica in line with master.
    Replica replica(replica_db.db);
    handshake(master, replica);

    CHECK(replica.state() == Replica::State::Live);
    check_convergence(master_db, replica_db, "t1");
}

TEST_CASE("stress: peer bidirectional random operations") {
    DB client_db, server_db;
    const char* schema =
        "CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT);"
        "CREATE TABLE t2 (id INTEGER PRIMARY KEY, val TEXT)";
    client_db.exec(schema);
    server_db.exec(schema);

    PeerConfig client_cfg;
    client_cfg.owned_tables = {"t1"};
    Peer client(client_db.db, client_cfg);

    PeerConfig server_cfg;
    server_cfg.approve_ownership = [](const std::set<std::string>&) {
        return true;
    };
    Peer server(server_db.db, server_cfg);

    auto initial = client.start();
    exchange(client, server, initial);

    std::mt19937 rng(99);
    int next_t1 = 1, next_t2 = 1;

    for (int i = 0; i < 100; ++i) {
        // Client writes to t1.
        std::string val = random_string(rng);
        client_db.exec(("INSERT INTO t1 VALUES (" +
                        std::to_string(next_t1++) + ", '" + val + "')").c_str());
        auto client_msgs = client.flush();
        auto resp = deliver(client_msgs, server);
        deliver(resp.messages, client);

        // Server writes to t2.
        val = random_string(rng);
        server_db.exec(("INSERT INTO t2 VALUES (" +
                        std::to_string(next_t2++) + ", '" + val + "')").c_str());
        auto server_msgs = server.flush();
        resp = deliver(server_msgs, client);
        deliver(resp.messages, server);
    }

    check_convergence(client_db, server_db, "t1");
    check_convergence(client_db, server_db, "t2");
}

TEST_CASE("stress: large dataset live streaming") {
    DB master_db, replica_db;
    master_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    replica_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");

    Master master(master_db.db);
    Replica replica(replica_db.db);
    handshake(master, replica);

    std::mt19937 rng(555);

    // Insert 10K rows in batches of 100.
    for (int batch = 0; batch < 100; ++batch) {
        master_db.exec("BEGIN");
        for (int i = 0; i < 100; ++i) {
            int id = batch * 100 + i + 1;
            std::string val = random_string(rng);
            master_db.exec(("INSERT INTO t1 VALUES (" +
                            std::to_string(id) + ", '" + val + "')").c_str());
        }
        master_db.exec("COMMIT");

        auto msgs = master.flush();
        auto result = deliver(msgs, replica);
        for (const auto& m : result.messages) {
            master.handle_message(m);
        }
    }

    CHECK(master_db.count("t1") == 10000);
    check_convergence(master_db, replica_db, "t1");
}

TEST_CASE("stress: large dataset diff sync") {
    DB master_db, replica_db;
    master_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    replica_db.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");

    std::mt19937 rng(666);

    // Populate master with 10K rows.
    Master master(master_db.db);
    master_db.exec("BEGIN");
    for (int i = 1; i <= 10000; ++i) {
        std::string val = random_string(rng);
        master_db.exec(("INSERT INTO t1 VALUES (" +
                        std::to_string(i) + ", '" + val + "')").c_str());
    }
    master_db.exec("COMMIT");
    master.flush();

    // Replica has a stale/partial subset (rows 5000-7000 with different values).
    replica_db.exec("BEGIN");
    for (int i = 5000; i <= 7000; ++i) {
        std::string val = random_string(rng);  // different seed state = different values
        replica_db.exec(("INSERT INTO t1 VALUES (" +
                         std::to_string(i) + ", '" + val + "')").c_str());
    }
    replica_db.exec("COMMIT");

    Replica replica(replica_db.db);
    handshake(master, replica);

    CHECK(replica.state() == Replica::State::Live);
    CHECK(replica_db.count("t1") == 10000);
    check_convergence(master_db, replica_db, "t1");
}

TEST_CASE("stress: peer diff sync after random divergence") {
    DB client_db, server_db;
    const char* schema =
        "CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT);"
        "CREATE TABLE t2 (id INTEGER PRIMARY KEY, val TEXT)";
    client_db.exec(schema);
    server_db.exec(schema);

    std::mt19937 rng(77);

    // First session: populate some data.
    {
        PeerConfig client_cfg;
        client_cfg.owned_tables = {"t1"};
        Peer client(client_db.db, client_cfg);
        Peer server(server_db.db);
        auto initial = client.start();
        exchange(client, server, initial);

        for (int i = 1; i <= 20; ++i) {
            std::string val = random_string(rng);
            client_db.exec(("INSERT INTO t1 VALUES (" +
                            std::to_string(i) + ", '" + val + "')").c_str());
            auto msgs = client.flush();
            auto resp = deliver(msgs, server);
            deliver(resp.messages, client);
        }
        for (int i = 1; i <= 20; ++i) {
            std::string val = random_string(rng);
            server_db.exec(("INSERT INTO t2 VALUES (" +
                            std::to_string(i) + ", '" + val + "')").c_str());
            auto msgs = server.flush();
            auto resp = deliver(msgs, client);
            deliver(resp.messages, server);
        }
    }

    // While disconnected, add data via raw Masters.
    {
        MasterConfig mc;
        mc.table_filter = std::set<std::string>{"t2"};
        mc.seq_key = "master_seq";
        Master m(server_db.db, mc);
        for (int i = 21; i <= 30; ++i) {
            std::string val = random_string(rng);
            server_db.exec(("INSERT INTO t2 VALUES (" +
                            std::to_string(i) + ", '" + val + "')").c_str());
        }
        m.flush();
    }
    {
        MasterConfig mc;
        mc.table_filter = std::set<std::string>{"t1"};
        mc.seq_key = "master_seq";
        Master m(client_db.db, mc);
        for (int i = 21; i <= 30; ++i) {
            std::string val = random_string(rng);
            client_db.exec(("INSERT INTO t1 VALUES (" +
                            std::to_string(i) + ", '" + val + "')").c_str());
        }
        m.flush();
    }

    // Reconnect: diff sync should catch up.
    {
        PeerConfig client_cfg;
        client_cfg.owned_tables = {"t1"};
        Peer client(client_db.db, client_cfg);
        Peer server(server_db.db);
        auto initial = client.start();
        exchange(client, server, initial);

        CHECK(client.state() == Peer::State::Live);
        CHECK(server.state() == Peer::State::Live);

        check_convergence(client_db, server_db, "t1");
        check_convergence(client_db, server_db, "t2");
    }
}
