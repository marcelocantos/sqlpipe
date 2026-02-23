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

// Deliver all PeerMessages from one peer to another, returning aggregated result.
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

// Exchange messages between two peers until no more messages are produced.
void exchange(Peer& a, Peer& b, const std::vector<PeerMessage>& initial) {
    auto msgs = initial;
    while (!msgs.empty()) {
        // Deliver to b, collect responses.
        auto resp_b = deliver(msgs, b);
        // Deliver b's responses to a.
        msgs.clear();
        if (!resp_b.messages.empty()) {
            auto resp_a = deliver(resp_b.messages, a);
            msgs = std::move(resp_a.messages);
        }
    }
}

} // namespace

TEST_CASE("peer: client start produces hello with owned_tables") {
    DB d;
    d.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    d.exec("CREATE TABLE t2 (id INTEGER PRIMARY KEY, val TEXT)");

    PeerConfig cfg;
    cfg.owned_tables = {"t1"};
    Peer client(d.db, cfg);

    auto msgs = client.start();
    REQUIRE(msgs.size() == 1);
    CHECK(msgs[0].sender_role == SenderRole::AsReplica);
    auto& hello = std::get<HelloMsg>(msgs[0].payload);
    CHECK(hello.owned_tables == std::set<std::string>{"t1"});
    CHECK(client.state() == Peer::State::Negotiating);
}

TEST_CASE("peer: server rejects start()") {
    DB d;
    PeerConfig cfg;
    cfg.approve_ownership = [](const std::set<std::string>&) { return true; };
    Peer server(d.db, cfg);

    CHECK_THROWS_AS(server.start(), Error);
}

TEST_CASE("peer: fresh handshake both sides go live") {
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
    server_cfg.approve_ownership = [](const std::set<std::string>& t) {
        return t == std::set<std::string>{"t1"};
    };
    Peer server(server_db.db, server_cfg);

    auto initial = client.start();
    exchange(client, server, initial);

    CHECK(client.state() == Peer::State::Live);
    CHECK(server.state() == Peer::State::Live);
    CHECK(client.owned_tables() == std::set<std::string>{"t1"});
    CHECK(client.remote_tables() == std::set<std::string>{"t2"});
    CHECK(server.owned_tables() == std::set<std::string>{"t2"});
    CHECK(server.remote_tables() == std::set<std::string>{"t1"});
}

TEST_CASE("peer: ownership rejection") {
    DB client_db, server_db;
    const char* schema =
        "CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)";
    client_db.exec(schema);
    server_db.exec(schema);

    PeerConfig client_cfg;
    client_cfg.owned_tables = {"t1"};
    Peer client(client_db.db, client_cfg);

    PeerConfig server_cfg;
    server_cfg.approve_ownership = [](const std::set<std::string>&) {
        return false;
    };
    Peer server(server_db.db, server_cfg);

    auto initial = client.start();
    auto resp = deliver(initial, server);

    CHECK(server.state() == Peer::State::Error);
    REQUIRE(!resp.messages.empty());
    auto* err = std::get_if<ErrorMsg>(&resp.messages[0].payload);
    REQUIRE(err != nullptr);
    CHECK(err->code == ErrorCode::OwnershipRejected);
}

TEST_CASE("peer: client-owned table live streaming") {
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

    // Client writes to t1 (its owned table).
    client_db.exec("INSERT INTO t1 VALUES (1, 'hello')");
    auto flush_msgs = client.flush();
    REQUIRE(!flush_msgs.empty());

    auto result = deliver(flush_msgs, server);
    // Server should see the change event.
    REQUIRE(!result.changes.empty());
    CHECK(result.changes[0].table == "t1");
    CHECK(result.changes[0].op == OpType::Insert);

    // Server's DB should have the row.
    CHECK(server_db.count("t1") == 1);
    CHECK(server_db.query_val("SELECT val FROM t1 WHERE id=1") == "hello");
}

TEST_CASE("peer: server-owned table live streaming") {
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

    // Server writes to t2 (its owned table).
    server_db.exec("INSERT INTO t2 VALUES (1, 'world')");
    auto flush_msgs = server.flush();
    REQUIRE(!flush_msgs.empty());

    auto result = deliver(flush_msgs, client);
    REQUIRE(!result.changes.empty());
    CHECK(result.changes[0].table == "t2");
    CHECK(result.changes[0].op == OpType::Insert);

    CHECK(client_db.count("t2") == 1);
    CHECK(client_db.query_val("SELECT val FROM t2 WHERE id=1") == "world");
}

TEST_CASE("peer: bidirectional live streaming") {
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

    // Client writes to t1.
    client_db.exec("INSERT INTO t1 VALUES (1, 'from_client')");
    auto client_msgs = client.flush();
    deliver(client_msgs, server);

    // Server writes to t2.
    server_db.exec("INSERT INTO t2 VALUES (1, 'from_server')");
    auto server_msgs = server.flush();
    deliver(server_msgs, client);

    // Both databases should have both rows.
    CHECK(client_db.count("t1") == 1);
    CHECK(client_db.count("t2") == 1);
    CHECK(server_db.count("t1") == 1);
    CHECK(server_db.count("t2") == 1);
    CHECK(client_db.query_val("SELECT val FROM t2 WHERE id=1") == "from_server");
    CHECK(server_db.query_val("SELECT val FROM t1 WHERE id=1") == "from_client");
}

TEST_CASE("peer: auto-approve when callback is null") {
    DB client_db, server_db;
    const char* schema =
        "CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT);"
        "CREATE TABLE t2 (id INTEGER PRIMARY KEY, val TEXT)";
    client_db.exec(schema);
    server_db.exec(schema);

    PeerConfig client_cfg;
    client_cfg.owned_tables = {"t1"};
    Peer client(client_db.db, client_cfg);

    // Server with no approve_ownership callback → auto-approve.
    Peer server(server_db.db);

    auto initial = client.start();
    exchange(client, server, initial);

    CHECK(client.state() == Peer::State::Live);
    CHECK(server.state() == Peer::State::Live);
    CHECK(server.owned_tables() == std::set<std::string>{"t2"});
}

TEST_CASE("peer: flush on non-owned table produces nothing") {
    DB client_db, server_db;
    const char* schema =
        "CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT);"
        "CREATE TABLE t2 (id INTEGER PRIMARY KEY, val TEXT)";
    client_db.exec(schema);
    server_db.exec(schema);

    PeerConfig client_cfg;
    client_cfg.owned_tables = {"t1"};
    Peer client(client_db.db, client_cfg);

    Peer server(server_db.db);
    auto initial = client.start();
    exchange(client, server, initial);

    // Client writes to t2 (NOT its owned table).
    client_db.exec("INSERT INTO t2 VALUES (1, 'sneaky')");
    auto flush_msgs = client.flush();

    // Should produce nothing — Master only tracks t1.
    CHECK(flush_msgs.empty());
}

TEST_CASE("peer: one side owns all tables") {
    DB client_db, server_db;
    const char* schema =
        "CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT);"
        "CREATE TABLE t2 (id INTEGER PRIMARY KEY, val TEXT)";
    client_db.exec(schema);
    server_db.exec(schema);

    // Client owns both tables.
    PeerConfig client_cfg;
    client_cfg.owned_tables = {"t1", "t2"};
    Peer client(client_db.db, client_cfg);

    Peer server(server_db.db);
    auto initial = client.start();
    exchange(client, server, initial);

    CHECK(client.state() == Peer::State::Live);
    CHECK(server.state() == Peer::State::Live);
    CHECK(server.owned_tables().empty());
    CHECK(server.remote_tables() == std::set<std::string>{"t1", "t2"});

    // Client writes, server receives.
    client_db.exec("INSERT INTO t1 VALUES (1, 'a')");
    client_db.exec("INSERT INTO t2 VALUES (1, 'b')");
    auto msgs = client.flush();
    deliver(msgs, server);

    CHECK(server_db.count("t1") == 1);
    CHECK(server_db.count("t2") == 1);

    // Server flush produces nothing (owns no tables).
    server_db.exec("INSERT INTO t1 VALUES (2, 'c')");
    auto server_msgs = server.flush();
    CHECK(server_msgs.empty());
}

TEST_CASE("peer: diff sync after reconnect") {
    DB client_db, server_db;
    const char* schema =
        "CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT);"
        "CREATE TABLE t2 (id INTEGER PRIMARY KEY, val TEXT)";
    client_db.exec(schema);
    server_db.exec(schema);

    // First connection: exchange some data.
    {
        PeerConfig client_cfg;
        client_cfg.owned_tables = {"t1"};
        Peer client(client_db.db, client_cfg);
        Peer server(server_db.db);
        auto initial = client.start();
        exchange(client, server, initial);

        client_db.exec("INSERT INTO t1 VALUES (1, 'a')");
        auto msgs = client.flush();
        auto resp = deliver(msgs, server);
        deliver(resp.messages, client);  // acks

        server_db.exec("INSERT INTO t2 VALUES (1, 'b')");
        msgs = server.flush();
        resp = deliver(msgs, client);
        deliver(resp.messages, server);  // acks
    }

    // After disconnect, server adds more data.
    {
        // Use raw Master to add data to server's t2 while client is disconnected.
        MasterConfig mc;
        mc.table_filter = std::set<std::string>{"t2"};
        mc.seq_key = "master_seq";
        Master m(server_db.db, mc);
        server_db.exec("INSERT INTO t2 VALUES (2, 'c')");
        m.flush();
    }

    // Second connection: diff sync discovers the missing data.
    {
        PeerConfig client_cfg;
        client_cfg.owned_tables = {"t1"};
        Peer client(client_db.db, client_cfg);
        Peer server(server_db.db);
        auto initial = client.start();
        exchange(client, server, initial);

        CHECK(client.state() == Peer::State::Live);
        CHECK(server.state() == Peer::State::Live);

        // Client should have caught up on t2.
        CHECK(client_db.count("t2") == 2);
        CHECK(client_db.query_val("SELECT val FROM t2 WHERE id=2") == "c");
    }
}

TEST_CASE("peer: reset and reconnect") {
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

    // First session.
    auto initial = client.start();
    exchange(client, server, initial);
    CHECK(client.state() == Peer::State::Live);

    client_db.exec("INSERT INTO t1 VALUES (1, 'a')");
    auto resp = deliver(client.flush(), server);
    deliver(resp.messages, client);

    // Simulate disconnect: reset both peers.
    client.reset();
    server.reset();
    CHECK(client.state() == Peer::State::Init);
    CHECK(server.state() == Peer::State::Init);

    // Server adds data while "disconnected" (via raw Master).
    {
        MasterConfig mc;
        mc.table_filter = std::set<std::string>{"t2"};
        mc.seq_key = "master_seq";
        Master m(server_db.db, mc);
        server_db.exec("INSERT INTO t2 VALUES (1, 'b')");
        m.flush();
    }

    // Reconnect via reset peers.
    initial = client.start();
    exchange(client, server, initial);
    CHECK(client.state() == Peer::State::Live);
    CHECK(server.state() == Peer::State::Live);

    // Client should have the new t2 row via diff sync.
    CHECK(client_db.count("t2") == 1);
    CHECK(client_db.query_val("SELECT val FROM t2 WHERE id=1") == "b");

    // Server should still have the t1 row.
    CHECK(server_db.count("t1") == 1);
}
