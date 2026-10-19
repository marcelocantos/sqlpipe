// Copyright 2026 The sqlpipe Authors
// SPDX-License-Identifier: Apache-2.0
//
// Writes committed while a peer link is mid-handshake. Each side may write
// its own tables at any point: before, between and after the handshake's
// messages. Every such row must reach the other side exactly once — in the
// handshake diff or in a live changeset, never in both, and never in
// neither — and both peers must reach Live and stay there.
#include <doctest.h>
#include <sqlpipe.h>

#include <sqlite3.h>

#include <algorithm>
#include <deque>
#include <string>
#include <vector>

using namespace sqlpipe;

namespace {

struct HsDB {
    sqlite3* db = nullptr;
    HsDB() { sqlite3_open(":memory:", &db); }
    ~HsDB() { if (db) sqlite3_close(db); }
    void exec(const std::string& sql) {
        char* err = nullptr;
        int rc = sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &err);
        if (rc != SQLITE_OK) {
            std::string msg = err ? err : "error";
            sqlite3_free(err);
            throw std::runtime_error(msg);
        }
    }
    int count_where(const std::string& table, const std::string& val) {
        std::string sql = "SELECT COUNT(*) FROM " + table + " WHERE val = ?";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
        sqlite3_bind_text(stmt, 1, val.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
        int n = sqlite3_column_int(stmt, 0);
        sqlite3_finalize(stmt);
        return n;
    }
};

// One message in flight on the ordered link, and whether it goes to the
// server (true) or to the client (false).
struct InFlight {
    bool to_server;
    PeerMessage msg;
};

// Bytes of row data a message carries: a handshake diff or a changeset.
const Changeset* rows_of(const PeerMessage& m) {
    if (auto* d = std::get_if<DiffReadyMsg>(&m.payload)) return &d->patchset;
    if (auto* c = std::get_if<ChangesetMsg>(&m.payload)) return &c->data;
    return nullptr;
}

bool carries(const PeerMessage& m, const std::string& needle) {
    const Changeset* cs = rows_of(m);
    if (!cs || cs->empty()) return false;
    return std::search(cs->begin(), cs->end(), needle.begin(), needle.end()) !=
           cs->end();
}

struct Link {
    HsDB client_db, server_db;
    Peer client;
    Peer server;
    std::deque<InFlight> wire;
    std::vector<InFlight> log;  // every message delivered, in order

    static PeerConfig client_cfg() {
        PeerConfig c;
        c.owned_tables = {"c_rows"};
        return c;
    }
    static PeerConfig server_cfg() {
        PeerConfig c;
        c.role = PeerRole::Server;
        c.approve_ownership = [](const std::set<std::string>& t) {
            return t == std::set<std::string>{"c_rows"};
        };
        return c;
    }
    static const char* schema() {
        return "CREATE TABLE c_rows (id INTEGER PRIMARY KEY, val TEXT);"
               "CREATE TABLE s_rows (id INTEGER PRIMARY KEY, val TEXT)";
    }

    Link()
        : client_db(), server_db(),
          client(client_db.db, client_cfg()),
          server(server_db.db, server_cfg()) {
        client_db.exec(schema());
        server_db.exec(schema());
        // Rows each side already holds and the other lacks, so the
        // handshake runs a real two-round diff on both directions.
        client_db.exec("INSERT INTO c_rows VALUES (1, 'c-before')");
        server_db.exec("INSERT INTO s_rows VALUES (1, 's-before')");
    }

    void send(bool to_server, const std::vector<PeerOutMessage>& out) {
        for (const auto& m : out) wire.push_back({to_server, m.msg});
    }

    // Deliver one message; its responses go back on the wire.
    void step() {
        InFlight f = std::move(wire.front());
        wire.pop_front();
        log.push_back(f);
        if (f.to_server) {
            send(false, server.handle_message(f.msg).messages);
        } else {
            send(true, client.handle_message(f.msg).messages);
        }
    }

    // A caller that flushes after every write, as the docs ask. A flush
    // during the handshake must not put a changeset ahead of the diff.
    void flush_both() {
        send(true, client.flush());
        send(false, server.flush());
    }

    int crossings(const std::string& needle, bool to_server) const {
        int n = 0;
        for (const auto& f : log) {
            if (f.to_server == to_server && carries(f.msg, needle)) ++n;
        }
        return n;
    }
};

// Runs the link from start to quiet, writing on both sides just before
// message k is delivered. near rows share a bucket with the rows the diff
// already repairs; far rows sit in a bucket neither side had at the start.
void run_with_write_before(int k, bool flush_eagerly, int& steps_out) {
    Link link;
    link.send(true, link.client.start());
    const std::string cn = "c-near-" + std::to_string(k);
    const std::string cf = "c-far-" + std::to_string(k);
    const std::string sn = "s-near-" + std::to_string(k);
    const std::string sf = "s-far-" + std::to_string(k);
    int step = 0;
    bool wrote = false;
    while (!link.wire.empty()) {
        if (step == k) {
            link.client_db.exec("INSERT INTO c_rows VALUES (2, '" + cn + "')");
            link.client_db.exec("INSERT INTO c_rows VALUES (5000, '" + cf + "')");
            link.server_db.exec("INSERT INTO s_rows VALUES (2, '" + sn + "')");
            link.server_db.exec("INSERT INTO s_rows VALUES (5000, '" + sf + "')");
            wrote = true;
            if (flush_eagerly) link.flush_both();
        }
        link.step();
        ++step;
    }
    steps_out = step;
    REQUIRE(link.client.state() == Peer::State::Live);
    REQUIRE(link.server.state() == Peer::State::Live);
    if (!wrote) return;  // k is past the end of this handshake

    // The link is live: whatever the session still holds goes now.
    link.flush_both();
    while (!link.wire.empty()) link.step();
    CHECK(link.client.state() == Peer::State::Live);
    CHECK(link.server.state() == Peer::State::Live);

    for (const auto& v : {cn, cf}) {
        INFO("client row " << v << ", write before message " << k);
        CHECK(link.server_db.count_where("c_rows", v) == 1);
        CHECK(link.crossings(v, true) == 1);
    }
    for (const auto& v : {sn, sf}) {
        INFO("server row " << v << ", write before message " << k);
        CHECK(link.client_db.count_where("s_rows", v) == 1);
        CHECK(link.crossings(v, false) == 1);
    }

    // Later writes keep flowing as single changesets.
    link.client_db.exec("INSERT INTO c_rows VALUES (3, 'c-after')");
    link.server_db.exec("INSERT INTO s_rows VALUES (3, 's-after')");
    link.flush_both();
    while (!link.wire.empty()) link.step();
    CHECK(link.server_db.count_where("c_rows", "c-after") == 1);
    CHECK(link.client_db.count_where("s_rows", "s-after") == 1);
    CHECK(link.crossings("c-after", true) == 1);
    CHECK(link.crossings("s-after", false) == 1);
}

}  // namespace

TEST_CASE("peer: a write at any handshake step crosses exactly once") {
    int steps = 0;
    run_with_write_before(1 << 20, false, steps);  // measure the handshake
    REQUIRE(steps >= 6);
    for (int k = 0; k < steps; ++k) {
        CAPTURE(k);
        int ignored = 0;
        run_with_write_before(k, false, ignored);
    }
}

TEST_CASE("peer: flushing after every write during the handshake is safe") {
    int steps = 0;
    run_with_write_before(1 << 20, true, steps);
    for (int k = 0; k < steps; ++k) {
        CAPTURE(k);
        int ignored = 0;
        run_with_write_before(k, true, ignored);
    }
}
