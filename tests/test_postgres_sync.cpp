// Copyright 2026 The sqlpipe Authors
// SPDX-License-Identifier: Apache-2.0
//
// Live Postgres Master/Replica loopback (protocol v8). Built with
// -DSQLPIPE_HAVE_POSTGRES when libpq is available. `make gate` starts an
// ephemeral postgres:16 container and points PG* at it. Bare `cv test`
// without PG* skips so the SQLite suite stays green.

#include <doctest.h>
#include <sqlpipe.h>

#include <cstdlib>
#include <stdexcept>
#include <string>
#include <string_view>
#include <variant>

#ifndef SQLPIPE_HAVE_POSTGRES

TEST_CASE("postgres sync (T34)") {
    MESSAGE("SQLPIPE_HAVE_POSTGRES not set — live Postgres suite skipped "
            "(install libpq and rebuild)");
}

#else

#include <libpq-fe.h>

using namespace sqlpipe;

namespace {

std::string conninfo_for(const char* dbname) {
    std::string s = "dbname=";
    s += dbname;
    return s;
}

void pq_must(PGconn* c, const char* sql) {
    PGresult* r = PQexec(c, sql);
    auto st = PQresultStatus(r);
    if (st != PGRES_COMMAND_OK && st != PGRES_TUPLES_OK) {
        std::string msg = PQresultErrorMessage(r);
        PQclear(r);
        throw std::runtime_error(msg + " [" + sql + "]");
    }
    PQclear(r);
}

bool ensure_database(const char* name) {
    const char* admin = std::getenv("PGDATABASE");
    std::string info = "dbname=";
    info += (admin && *admin) ? admin : "postgres";
    PGconn* c = PQconnectdb(info.c_str());
    if (!c || PQstatus(c) != CONNECTION_OK) {
        if (c) PQfinish(c);
        return false;
    }
    std::string sql = "SELECT 1 FROM pg_database WHERE datname = '";
    sql += name;
    sql += "'";
    PGresult* r = PQexec(c, sql.c_str());
    bool exists = PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0;
    PQclear(r);
    if (!exists) {
        std::string create = "CREATE DATABASE ";
        create += name;
        PGresult* cr = PQexec(c, create.c_str());
        if (PQresultStatus(cr) != PGRES_COMMAND_OK) {
            PQclear(cr);
            PQfinish(c);
            return false;
        }
        PQclear(cr);
    }
    PQfinish(c);
    return true;
}

struct Pg {
    PGconn* conn = nullptr;
    explicit Pg(const char* dbname) {
        conn = PQconnectdb(conninfo_for(dbname).c_str());
        if (!conn || PQstatus(conn) != CONNECTION_OK) {
            std::string msg = conn ? PQerrorMessage(conn) : "no conn";
            if (conn) PQfinish(conn);
            conn = nullptr;
            throw std::runtime_error("PQconnectdb: " + msg);
        }
        reset();
    }
    ~Pg() {
        if (conn) PQfinish(conn);
    }
    Pg(const Pg&) = delete;
    Pg& operator=(const Pg&) = delete;

    void reset() {
        pq_must(conn, "DROP SCHEMA IF EXISTS sqlpipe CASCADE");
        pq_must(conn, "DROP SCHEMA public CASCADE");
        pq_must(conn, "CREATE SCHEMA public");
        pq_must(conn, "SET search_path TO public");
    }

    void exec(const char* sql) { pq_must(conn, sql); }

    std::string scalar(const char* sql) {
        PGresult* r = PQexec(conn, sql);
        if (PQresultStatus(r) != PGRES_TUPLES_OK || PQntuples(r) < 1) {
            std::string msg = PQresultErrorMessage(r);
            PQclear(r);
            throw std::runtime_error(msg);
        }
        std::string v = PQgetisnull(r, 0, 0) ? "" : PQgetvalue(r, 0, 0);
        PQclear(r);
        return v;
    }

    int count(const char* table) {
        std::string sql = "SELECT COUNT(*) FROM ";
        sql += table;
        return std::stoi(scalar(sql.c_str()));
    }
};

void handshake(Master& master, Replica& replica) {
    auto hello = replica.hello();
    auto resp = master.handle_message(hello.msg);
    HandleResult r;
    for (const auto& m : resp) {
        auto result = replica.handle_message(m.msg);
        r.messages.insert(r.messages.end(),
                          result.messages.begin(), result.messages.end());
    }
    for (const auto& m : r.messages) {
        auto result = master.handle_message(m.msg);
        HandleResult r2;
        for (const auto& m2 : result) {
            auto result2 = replica.handle_message(m2.msg);
            r2.messages.insert(r2.messages.end(),
                               result2.messages.begin(), result2.messages.end());
        }
        for (const auto& m3 : r2.messages) {
            auto result3 = master.handle_message(m3.msg);
            for (const auto& m4 : result3) {
                replica.handle_message(m4.msg);
            }
        }
    }
}

HandleResult deliver(const std::vector<OutMessage>& msgs, Replica& handler) {
    HandleResult result;
    for (const auto& om : msgs) {
        auto r = handler.handle_message(om.msg);
        result.messages.insert(result.messages.end(),
                               r.messages.begin(), r.messages.end());
        result.changes.insert(result.changes.end(),
                              r.changes.begin(), r.changes.end());
        result.subscriptions.insert(result.subscriptions.end(),
                                    r.subscriptions.begin(),
                                    r.subscriptions.end());
    }
    return result;
}

bool server_ready() {
    return ensure_database("sqlpipe_m") && ensure_database("sqlpipe_r");
}

const char* kItems =
    "CREATE TABLE items ("
    "id BIGINT PRIMARY KEY, name TEXT NOT NULL, qty INTEGER)";

} // namespace

TEST_CASE("postgres fingerprint uses SqliftPgSha256 (T34.2)") {
    if (!server_ready()) {
        MESSAGE("no Postgres server — skipped");
        return;
    }
    Pg a("sqlpipe_m");
    Pg b("sqlpipe_r");
    a.exec(kItems);
    b.exec(kItems);
    Master ma(a.conn);
    Master mb(b.conn);
    auto fa = ma.schema_version();
    auto fb = mb.schema_version();
    REQUIRE_FALSE(fa.empty());
    CHECK(fa[0] == static_cast<std::uint8_t>(
        SchemaFingerprintAlgo::SqliftPgSha256));
    CHECK(fa == fb);
    b.exec("CREATE TABLE extra (id BIGINT PRIMARY KEY, v TEXT)");
    REQUIRE(b.scalar("SELECT to_regclass('public.extra')") == "extra");
    Master mb2(b.conn);
    CHECK(ma.schema_version() != mb2.schema_version());
}

TEST_CASE("postgres live insert/update/delete (T34.3)") {
    if (!server_ready()) {
        MESSAGE("no Postgres server — skipped");
        return;
    }
    Pg master_db("sqlpipe_m");
    Pg replica_db("sqlpipe_r");
    master_db.exec(kItems);
    replica_db.exec(kItems);

    Master master(master_db.conn);
    Replica replica(replica_db.conn);
    handshake(master, replica);
    CHECK(replica.state() == Replica::State::Live);
    CHECK(master.schema_version()[0] ==
          static_cast<std::uint8_t>(SchemaFingerprintAlgo::SqliftPgSha256));

    master.exec("INSERT INTO items (id, name, qty) VALUES (1, 'apple', 3)");
    auto flushed = master.flush();
    REQUIRE(flushed.size() == 1);
    REQUIRE(std::holds_alternative<ChangesetMsg>(flushed[0].msg));
    const auto& cs = std::get<ChangesetMsg>(flushed[0].msg);
    REQUIRE_FALSE(cs.data.empty());
    CHECK(cs.data[0] == 1); // v1 DML patch, not a SQLite session blob
    deliver(flushed, replica);
    CHECK(replica_db.count("items") == 1);
    CHECK(replica_db.scalar("SELECT name FROM items WHERE id = 1") == "apple");

    master.exec("UPDATE items SET qty = 9 WHERE id = 1");
    deliver(master.flush(), replica);
    CHECK(replica_db.scalar("SELECT qty FROM items WHERE id = 1") == "9");

    master.exec("DELETE FROM items WHERE id = 1");
    deliver(master.flush(), replica);
    CHECK(replica_db.count("items") == 0);
}

TEST_CASE("postgres diff sync after disconnect (T34.3)") {
    if (!server_ready()) {
        MESSAGE("no Postgres server — skipped");
        return;
    }
    Pg master_db("sqlpipe_m");
    Pg replica_db("sqlpipe_r");
    master_db.exec(kItems);
    replica_db.exec(kItems);

    {
        Master master(master_db.conn);
        Replica replica(replica_db.conn);
        handshake(master, replica);
        master.exec("INSERT INTO items (id, name, qty) VALUES (1, 'a', 1)");
        deliver(master.flush(), replica);
    }

    master_db.exec("INSERT INTO items (id, name, qty) VALUES (2, 'b', 2)");
    master_db.exec("UPDATE items SET name = 'A' WHERE id = 1");
    master_db.exec("INSERT INTO items (id, name, qty) VALUES (3, 'c', 3)");

    Master master2(master_db.conn);
    Replica replica2(replica_db.conn);
    handshake(master2, replica2);
    CHECK(replica2.state() == Replica::State::Live);
    CHECK(replica_db.count("items") == 3);
    CHECK(replica_db.scalar("SELECT name FROM items WHERE id = 1") == "A");
    CHECK(replica_db.scalar("SELECT name FROM items WHERE id = 2") == "b");
}

TEST_CASE("postgres already-in-sync reconnect (T34.3)") {
    if (!server_ready()) {
        MESSAGE("no Postgres server — skipped");
        return;
    }
    Pg master_db("sqlpipe_m");
    Pg replica_db("sqlpipe_r");
    master_db.exec(kItems);
    replica_db.exec(kItems);
    Master master(master_db.conn);
    Replica replica(replica_db.conn);
    handshake(master, replica);
    master.exec("INSERT INTO items (id, name, qty) VALUES (1, 'x', 1)");
    deliver(master.flush(), replica);
    auto seq = master.current_seq();
    CHECK(replica.current_seq() == seq);

    replica.reset();
    handshake(master, replica);
    CHECK(replica.state() == Replica::State::Live);
    CHECK(replica.current_seq() == seq);
    CHECK(replica_db.count("items") == 1);
}

TEST_CASE("postgres schema mismatch (T34.3)") {
    if (!server_ready()) {
        MESSAGE("no Postgres server — skipped");
        return;
    }
    Pg master_db("sqlpipe_m");
    Pg replica_db("sqlpipe_r");
    master_db.exec(kItems);
    replica_db.exec("CREATE TABLE items (id BIGINT PRIMARY KEY, name TEXT)");
    Master master(master_db.conn);
    Replica replica(replica_db.conn);
    auto hello = replica.hello();
    auto resp = master.handle_message(hello.msg);
    REQUIRE(resp.size() == 1);
    REQUIRE(std::holds_alternative<ErrorMsg>(resp[0].msg));
    CHECK(std::get<ErrorMsg>(resp[0].msg).code == ErrorCode::SchemaMismatch);
}

TEST_CASE("postgres rejects non-bigint PK (T34.3)") {
    if (!server_ready()) {
        MESSAGE("no Postgres server — skipped");
        return;
    }
    Pg db("sqlpipe_m");
    db.exec("CREATE TABLE bad (id TEXT PRIMARY KEY, v TEXT)");
    try {
        Master m(db.conn);
        FAIL("expected UnsupportedTable");
    } catch (const Error& e) {
        CHECK(e.code() == ErrorCode::UnsupportedTable);
    }
}

TEST_CASE("postgres Database::postgres + subscribe (T34.4)") {
    if (!server_ready()) {
        MESSAGE("no Postgres server — skipped");
        return;
    }
    ensure_database("sqlpipe_m");
    {
        Pg wipe("sqlpipe_m");
        (void)wipe;
    }
    auto db = Database::postgres(conninfo_for("sqlpipe_m"), kItems);
    CHECK(db.engine() == Engine::Postgres);
    CHECK(db.postgres_handle() != nullptr);
    CHECK(db.sqlite_handle() == nullptr);
    db.exec("INSERT INTO items (id, name, qty) VALUES (1, 'z', 4)");
    auto q = db.query("SELECT name FROM items WHERE id = 1");
    REQUIRE(q.rows.size() == 1);
    CHECK(std::get<std::string>(q.rows[0][0]) == "z");

    int fires = 0;
    QueryResult last;
    auto sub = db.subscribe("SELECT name FROM items ORDER BY id",
                            [&](const QueryResult& r) {
                                ++fires;
                                last = r;
                            });
    CHECK(fires >= 1);
    db.exec("INSERT INTO items (id, name, qty) VALUES (2, 'y', 1)");
    CHECK(fires >= 2);
    (void)sub;
}

TEST_CASE("postgres prediction rejects caller txn (T34.4)") {
    if (!server_ready()) {
        MESSAGE("no Postgres server — skipped");
        return;
    }
    Pg db("sqlpipe_r");
    db.exec(kItems);
    Replica replica(db.conn);
    replica.begin_prediction();
    replica.rollback_prediction();

    db.exec("BEGIN");
    CHECK_THROWS_AS(replica.begin_prediction(), Error);
    db.exec("ROLLBACK");
}

TEST_CASE("postgres peer ownership handshake (T34.4)") {
    if (!server_ready()) {
        MESSAGE("no Postgres server — skipped");
        return;
    }
    Pg a("sqlpipe_m");
    Pg b("sqlpipe_r");
    a.exec("CREATE TABLE left_t (id BIGINT PRIMARY KEY, v TEXT)");
    a.exec("CREATE TABLE right_t (id BIGINT PRIMARY KEY, v TEXT)");
    b.exec("CREATE TABLE left_t (id BIGINT PRIMARY KEY, v TEXT)");
    b.exec("CREATE TABLE right_t (id BIGINT PRIMARY KEY, v TEXT)");

    PeerConfig client_cfg;
    client_cfg.role = PeerRole::Client;
    client_cfg.owned_tables = {"left_t"};
    PeerConfig server_cfg;
    server_cfg.role = PeerRole::Server;

    Peer client(a.conn, client_cfg);
    Peer server(b.conn, server_cfg);
    sync_handshake(client, server);
    CHECK(client.state() == Peer::State::Live);
    CHECK(server.state() == Peer::State::Live);

    a.exec("INSERT INTO left_t (id, v) VALUES (1, 'from-a')");
    auto flushed = client.flush();
    for (const auto& om : flushed) {
        auto r = server.handle_message(om.msg);
        for (const auto& back : r.messages)
            client.handle_message(back.msg);
    }
    CHECK(b.scalar("SELECT v FROM left_t WHERE id = 1") == "from-a");
}

#endif
