// Copyright 2026 The sqlpipe Authors
// SPDX-License-Identifier: Apache-2.0
//
// Public-API fault suite (T41). Oracles are a committed write log replayed
// onto an independent database, and direct queries of the replica. The
// subscription cache is never the expected payload.

#include <doctest.h>
#include <sqlpipe.h>

#include <sqlite3.h>

#include <cstdint>
#include <filesystem>
#include <optional>
#include <sstream>
#include <string>
#include <unistd.h>
#include <vector>

using namespace sqlpipe;

namespace {

std::string value_text(const Value& v) {
    return std::visit([](const auto& x) -> std::string {
        using T = std::decay_t<decltype(x)>;
        if constexpr (std::is_same_v<T, std::monostate>) return "NULL";
        else if constexpr (std::is_same_v<T, std::int64_t>) return std::to_string(x);
        else if constexpr (std::is_same_v<T, double>) return std::to_string(x);
        else if constexpr (std::is_same_v<T, std::string>) return x;
        else {
            std::string s;
            for (auto b : x) s.push_back(static_cast<char>(b));
            return s;
        }
    }, v);
}

std::string make_path(const char* tag) {
    static int n = 0;
    auto path = std::filesystem::temp_directory_path() /
        ("sqlpipe-t41-" + std::to_string(static_cast<long long>(getpid())) +
         "-" + tag + "-" + std::to_string(++n));
    return path.string();
}

struct FileDB {
    std::string path;
    sqlite3* db = nullptr;

    explicit FileDB(const char* tag) : path(make_path(tag)) {
        REQUIRE(sqlite3_open(path.c_str(), &db) == SQLITE_OK);
    }
    ~FileDB() {
        if (db) sqlite3_close(db);
        std::remove(path.c_str());
    }
    FileDB(const FileDB&) = delete;
    FileDB& operator=(const FileDB&) = delete;

    void reopen() {
        REQUIRE(db != nullptr);
        sqlite3_close(db);
        db = nullptr;
        REQUIRE(sqlite3_open(path.c_str(), &db) == SQLITE_OK);
    }

    void exec(const std::string& sql) {
        char* err = nullptr;
        int rc = sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &err);
        if (rc != SQLITE_OK) {
            std::string msg = err ? err : "error";
            sqlite3_free(err);
            throw std::runtime_error(msg);
        }
    }
};

std::string dump(sqlite3* db, const char* sql) {
    auto result = query(db, sql);
    std::ostringstream out;
    for (const auto& row : result.rows) {
        for (std::size_t i = 0; i < row.size(); ++i) {
            if (i) out << '|';
            out << value_text(row[i]);
        }
        out << '\n';
    }
    return out.str();
}

// Authoritative writes. `shadow` receives the same committed SQL as the
// writer and is never a replica. `replay()` applies the log to a fresh
// database so the expected rows are the log, not the subscription cache.
struct WriteLog {
    std::vector<std::string> sqls;

    void commit(FileDB& writer, FileDB& shadow, const std::string& sql) {
        writer.exec(sql);
        shadow.exec(sql);
        sqls.push_back(sql);
    }

    std::string replay(const char* schema) const {
        FileDB fresh("replay");
        fresh.exec(schema);
        for (const auto& sql : sqls) fresh.exec(sql);
        return dump(fresh.db, "SELECT id, v FROM t ORDER BY id");
    }
};

Seq persisted_seq(sqlite3* db, const char* key = "seq") {
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db,
            "SELECT value FROM _sqlpipe_meta WHERE key=?",
            -1, &stmt, nullptr) != SQLITE_OK) {
        return 0;
    }
    sqlite3_bind_text(stmt, 1, key, -1, SQLITE_TRANSIENT);
    Seq seq = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) seq = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);
    return seq;
}

HandleResult pump(Master& master, Replica& replica,
                  std::vector<OutMessage> to_master) {
    HandleResult all;
    for (int guard = 0; guard < 16 && !to_master.empty(); ++guard) {
        std::vector<OutMessage> to_replica;
        for (const auto& msg : to_master) {
            auto resp = master.handle_message(msg.msg);
            to_replica.insert(to_replica.end(), resp.begin(), resp.end());
        }
        to_master.clear();
        for (const auto& msg : to_replica) {
            auto hr = replica.handle_message(msg.msg);
            all.messages.insert(all.messages.end(),
                                hr.messages.begin(), hr.messages.end());
            all.changes.insert(all.changes.end(),
                               hr.changes.begin(), hr.changes.end());
            all.subscriptions.insert(all.subscriptions.end(),
                                     hr.subscriptions.begin(),
                                     hr.subscriptions.end());
            to_master.insert(to_master.end(),
                             hr.messages.begin(), hr.messages.end());
        }
    }
    return all;
}

const QueryResult& last_for(const HandleResult& hr, SubscriptionId id) {
    const QueryResult* found = nullptr;
    for (const auto& sub : hr.subscriptions) {
        if (sub.id == id) found = &sub;
    }
    REQUIRE(found != nullptr);
    return *found;
}

void expect_query(const QueryResult& sub, sqlite3* db, const char* sql) {
    auto direct = query(db, sql);
    CHECK(sub.columns == direct.columns);
    CHECK(sub.rows == direct.rows);
}

const char* kSchema = "CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)";
const char* kWatchSql = "SELECT id, v FROM t ORDER BY id";

void boom_fn(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    if (argc != 1) {
        sqlite3_result_error(ctx, "boom argc", -1);
        return;
    }
    if (sqlite3_value_int(argv[0]) == 0) {
        sqlite3_result_error(ctx, "bad", -1);
        return;
    }
    sqlite3_result_int(ctx, sqlite3_value_int(argv[0]));
}

} // namespace

TEST_CASE("fault-suite: recovery matches the write log and a direct query") {
    FileDB master_db("m"), replica_db("r"), shadow("s");
    master_db.exec(kSchema);
    replica_db.exec(kSchema);
    shadow.exec(kSchema);

    Master master(master_db.db);
    Replica replica(replica_db.db);
    CHECK(replica.sync_status() == SyncStatus::Unsynchronized);
    CHECK_FALSE(replica.observed_remote_seq().has_value());

    const char* sql = kWatchSql;
    auto sub_id = replica.subscribe(sql);
    CHECK(replica.subscription_count() == 1);
    // Not live yet: the caller still has to drive the handshake.
    CHECK(replica.state() == Replica::State::Init);
    pump(master, replica, {replica.hello()});
    REQUIRE(replica.state() == Replica::State::Live);
    CHECK(replica.sync_status() == SyncStatus::Live);

    WriteLog log;
    log.commit(master_db, shadow, "INSERT INTO t VALUES (1, 'a')");
    log.commit(master_db, shadow, "INSERT INTO t VALUES (2, 'b')");
    log.commit(master_db, shadow, "INSERT INTO t VALUES (3, 'c')");
    HandleResult hr;
    for (const auto& msg : master.flush()) {
        auto part = replica.handle_message(msg.msg);
        hr.subscriptions.insert(hr.subscriptions.end(),
                                part.subscriptions.begin(),
                                part.subscriptions.end());
    }
    REQUIRE(replica.observed_remote_seq().has_value());
    CHECK(*replica.observed_remote_seq() == master.current_seq());

    CHECK(dump(replica_db.db, sql) == log.replay(kSchema));
    CHECK(dump(replica_db.db, sql) == dump(shadow.db, sql));
    expect_query(last_for(hr, sub_id), replica_db.db, sql);

    log.commit(master_db, shadow, "UPDATE t SET v = 'B' WHERE id = 2");
    log.commit(master_db, shadow, "DELETE FROM t WHERE id = 3");
    log.commit(master_db, shadow, "INSERT INTO t VALUES (4, 'd')");
    auto offline = master.flush();
    // One-way blackhole: the adapter holds the messages. Live is not
    // catch-up, and the sequence is the progress marker.
    CHECK(replica.sync_status() == SyncStatus::Live);
    CHECK(replica.current_seq() < master.current_seq());
    CHECK(dump(replica_db.db, sql) != dump(shadow.db, sql));

    // Caller-owned transport loss. reset() is the detection signal.
    replica.reset();
    CHECK(replica.sync_status() == SyncStatus::Unsynchronized);
    CHECK_FALSE(replica.observed_remote_seq().has_value());
    CHECK(replica.subscription_count() == 1);

    hr = pump(master, replica, {replica.hello()});
    REQUIRE(replica.state() == Replica::State::Live);
    CHECK(replica.current_seq() == master.current_seq());
    CHECK(dump(replica_db.db, sql) == dump(shadow.db, sql));
    CHECK(dump(replica_db.db, sql) == log.replay(kSchema));
    expect_query(last_for(hr, sub_id), replica_db.db, sql);

    // One further live write, no application refresh.
    log.commit(master_db, shadow, "INSERT INTO t VALUES (5, 'e')");
    auto more = master.flush();
    HandleResult followed;
    for (const auto& msg : more) {
        auto part = replica.handle_message(msg.msg);
        followed.subscriptions.insert(followed.subscriptions.end(),
                                      part.subscriptions.begin(),
                                      part.subscriptions.end());
    }
    CHECK(dump(replica_db.db, sql) == dump(shadow.db, sql));
    expect_query(last_for(followed, sub_id), replica_db.db, sql);
    CHECK(replica.subscription_count() == 1);
    CHECK(replica.prediction_queue_size() == 0);
}

TEST_CASE("fault-suite: unchanged sequence reconnect and endpoint restart") {
    FileDB master_db("m"), replica_db("r"), shadow("s");
    master_db.exec(kSchema);
    replica_db.exec(kSchema);
    shadow.exec(kSchema);
    WriteLog log;
    {
        Master master(master_db.db);
        Replica replica(replica_db.db);
        log.commit(master_db, shadow, "INSERT INTO t VALUES (1, 'keep')");
        // Flush before the handshake so diff sync carries the row and the
        // session does not still hold that insert.
        master.flush();
        pump(master, replica, {replica.hello()});
        REQUIRE(master.current_seq() > 0);
        CHECK(replica.current_seq() == master.current_seq());
        auto seq = replica.current_seq();

        replica.reset();
        pump(master, replica, {replica.hello()});
        CHECK(replica.state() == Replica::State::Live);
        CHECK(replica.current_seq() == seq);
        CHECK(replica.current_seq() == master.current_seq());
        CHECK(dump(replica_db.db, kWatchSql) == dump(shadow.db, kWatchSql));
    }

    master_db.reopen();
    replica_db.reopen();
    Master master2(master_db.db);
    Replica replica2(replica_db.db);
    auto sub = replica2.subscribe(kWatchSql);
    auto hr = pump(master2, replica2, {replica2.hello()});
    REQUIRE(replica2.state() == Replica::State::Live);
    CHECK(dump(replica_db.db, kWatchSql) == log.replay(kSchema));
    expect_query(last_for(hr, sub), replica_db.db, kWatchSql);

    log.commit(master_db, shadow, "INSERT INTO t VALUES (2, 'after-restart')");
    HandleResult followed;
    for (const auto& msg : master2.flush()) {
        auto part = replica2.handle_message(msg.msg);
        followed.subscriptions.insert(followed.subscriptions.end(),
                                      part.subscriptions.begin(),
                                      part.subscriptions.end());
    }
    CHECK(dump(replica_db.db, kWatchSql) == dump(shadow.db, kWatchSql));
    expect_query(last_for(followed, sub), replica_db.db, kWatchSql);
}

TEST_CASE("fault-suite: interrupted apply does not commit partial state or seq") {
    FileDB master_db("m"), replica_db("r");
    master_db.exec(kSchema);
    replica_db.exec(kSchema);
    replica_db.exec(
        "CREATE TRIGGER guard BEFORE INSERT ON t "
        "WHEN new.v = 'bad' "
        "BEGIN SELECT RAISE(ABORT, 'bad'); END");

    Master master(master_db.db);
    Replica replica(replica_db.db);
    pump(master, replica, {replica.hello()});
    REQUIRE(replica.state() == Replica::State::Live);
    CHECK(replica.current_seq() == 0);

    master_db.exec("BEGIN");
    master_db.exec("INSERT INTO t VALUES (1, 'ok')");
    master_db.exec("INSERT INTO t VALUES (2, 'bad')");
    master_db.exec("COMMIT");
    auto msgs = master.flush();
    REQUIRE(msgs.size() == 1);
    CHECK_THROWS_AS(replica.handle_message(msgs[0].msg), Error);
    CHECK(replica.current_seq() == 0);
    CHECK(persisted_seq(replica_db.db) == 0);
    CHECK(dump(replica_db.db, kWatchSql) == "");
    CHECK(sqlite3_get_autocommit(replica_db.db) == 1);
    CHECK(replica.state() == Replica::State::Live);

    replica_db.exec("DROP TRIGGER guard");
    for (const auto& msg : msgs) replica.handle_message(msg.msg);
    CHECK(replica.current_seq() == master.current_seq());
    CHECK(persisted_seq(replica_db.db) == master.current_seq());
    CHECK(dump(replica_db.db, kWatchSql) == "1|ok\n2|bad\n");
}

TEST_CASE("fault-suite: interrupted diff rolls back rows and sequence") {
    FileDB master_db("m"), replica_db("r"), shadow("s");
    master_db.exec(kSchema);
    replica_db.exec(kSchema);
    shadow.exec(kSchema);

    Master master(master_db.db);
    WriteLog log;
    log.commit(master_db, shadow, "INSERT INTO t VALUES (1, 'a')");
    master.flush();

    replica_db.exec("INSERT INTO t VALUES (1, 'a')");
    replica_db.exec("INSERT INTO t VALUES (2, 'extra')");
    replica_db.exec(
        "CREATE TRIGGER guard BEFORE DELETE ON t "
        "BEGIN SELECT RAISE(ABORT, 'no deletes'); END");

    {
        Replica replica(replica_db.db);
        CHECK(replica.current_seq() == 0);
        CHECK_THROWS_AS(pump(master, replica, {replica.hello()}), Error);
        CHECK(replica.current_seq() == 0);
        CHECK(persisted_seq(replica_db.db) == 0);
        CHECK(dump(replica_db.db, kWatchSql) == "1|a\n2|extra\n");
        CHECK(sqlite3_get_autocommit(replica_db.db) == 1);
        CHECK(replica.sync_status() != SyncStatus::Live);
    }

    replica_db.exec("DROP TRIGGER guard");
    Replica replica(replica_db.db);
    pump(master, replica, {replica.hello()});
    REQUIRE(replica.state() == Replica::State::Live);
    CHECK(replica.current_seq() == master.current_seq());
    CHECK(persisted_seq(replica_db.db) == master.current_seq());
    CHECK(dump(replica_db.db, kWatchSql) == dump(shadow.db, kWatchSql));
}

TEST_CASE("fault-suite: best-effort loss is recovered, reliable reorder is not applied") {
    FileDB master_db("m"), replica_db("r"), shadow("s");
    master_db.exec(kSchema);
    replica_db.exec(kSchema);
    shadow.exec(kSchema);
    Master master(master_db.db);
    Replica replica(replica_db.db);

    WriteLog log;
    log.commit(master_db, shadow, "INSERT INTO t VALUES (1, 'a')");
    // Commit the row before the handshake so diff sync is the path under
    // test, and the session does not still hold that insert.
    master.flush();
    // Drop the replica's bucket hashes (best-effort) and regenerate them.
    auto hello_resp = master.handle_message(replica.hello().msg);
    HandleResult buckets;
    for (const auto& msg : hello_resp) {
        auto hr = replica.handle_message(msg.msg);
        buckets.messages.insert(buckets.messages.end(),
                                hr.messages.begin(), hr.messages.end());
    }
    REQUIRE(replica.state() == Replica::State::DiffBuckets);
    CHECK(replica.sync_status() == SyncStatus::Synchronizing);
    // Blackhole those bucket hashes, then regenerate them.
    auto again = replica.converge();
    pump(master, replica, again);
    REQUIRE(replica.state() == Replica::State::Live);
    CHECK(dump(replica_db.db, kWatchSql) == dump(shadow.db, kWatchSql));

    log.commit(master_db, shadow, "INSERT INTO t VALUES (2, 'b')");
    auto first = master.flush();
    log.commit(master_db, shadow, "INSERT INTO t VALUES (3, 'c')");
    auto second = master.flush();
    auto seq_before = replica.current_seq();
    auto rows_before = dump(replica_db.db, kWatchSql);
    CHECK_THROWS_AS(replica.handle_message(second[0].msg), Error);
    CHECK(replica.current_seq() == seq_before);
    CHECK(persisted_seq(replica_db.db) == seq_before);
    CHECK(dump(replica_db.db, kWatchSql) == rows_before);
    CHECK(replica.state() == Replica::State::Live);

    for (const auto& msg : first) replica.handle_message(msg.msg);
    for (const auto& msg : second) replica.handle_message(msg.msg);
    CHECK(dump(replica_db.db, kWatchSql) == dump(shadow.db, kWatchSql));
    CHECK(dump(replica_db.db, kWatchSql) == log.replay(kSchema));
}

TEST_CASE("fault-suite: nested subquery writes invalidate and match a direct query") {
    FileDB db("q");
    db.exec("CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT)");
    db.exec("CREATE TABLE tags (id INTEGER PRIMARY KEY, item_id INTEGER, hot INTEGER)");
    db.exec("INSERT INTO items VALUES (1, 'a')");
    db.exec("INSERT INTO tags VALUES (1, 1, 0)");

    QueryWatch watch(db.db);
    const char* sql =
        "SELECT name FROM items WHERE id IN "
        "(SELECT item_id FROM tags WHERE hot = 1) ORDER BY name";
    auto id = watch.subscribe(sql);
    auto initial = watch.notify({"items", "tags"});
    REQUIRE(initial.size() == 1);
    CHECK(initial[0].rows.empty());

    db.exec("UPDATE tags SET hot = 1 WHERE id = 1");
    auto changed = watch.notify({"tags"});
    REQUIRE(changed.size() == 1);
    expect_query(changed[0], db.db, sql);
    CHECK(std::get<std::string>(changed[0].rows[0][0]) == "a");

    const char* scalar =
        "SELECT id, (SELECT count(*) FROM tags) AS n FROM items ORDER BY id";
    auto scalar_id = watch.subscribe(scalar);
    auto base = watch.notify({"items", "tags"});
    bool saw = false;
    for (const auto& result : base) {
        if (result.id == scalar_id) {
            saw = true;
            expect_query(result, db.db, scalar);
        }
    }
    CHECK(saw);
    db.exec("INSERT INTO tags VALUES (2, 1, 0)");
    auto bumped = watch.notify({"tags"});
    const QueryResult* scalar_result = nullptr;
    for (const auto& result : bumped) {
        if (result.id == scalar_id) scalar_result = &result;
    }
    REQUIRE(scalar_result != nullptr);
    expect_query(*scalar_result, db.db, scalar);
    CHECK(std::get<std::int64_t>(scalar_result->rows[0][1]) == 2);
    (void)id;
}

TEST_CASE("fault-suite: query failure is not an unchanged result, and repair delivers") {
    FileDB db("q");
    db.exec("CREATE TABLE t (id INTEGER PRIMARY KEY, v INTEGER)");
    REQUIRE(sqlite3_create_function(db.db, "boom", 1, SQLITE_UTF8, nullptr,
                                    boom_fn, nullptr, nullptr) == SQLITE_OK);
    QueryWatch watch(db.db);
    CHECK_THROWS_AS(watch.subscribe("SELECT missing FROM t"), Error);
    try {
        watch.subscribe("SELECT missing FROM t");
        FAIL("initial prepare must fail");
    } catch (const Error& e) {
        CHECK(e.code() == ErrorCode::QueryFailed);
    }
    CHECK(watch.subscription_count() == 0);

    db.exec("INSERT INTO t VALUES (1, 1)");
    db.exec("INSERT INTO t VALUES (2, 1)");
    const char* sql = "SELECT id, boom(v) FROM t ORDER BY id";
    auto id = watch.subscribe(sql);
    auto ok = watch.notify({"t"});
    REQUIRE(ok.size() == 1);
    expect_query(ok[0], db.db, sql);
    CHECK(watch.subscription_count() == 1);

    db.exec("UPDATE t SET v = 0 WHERE id = 2");
    auto deliveries = 0;
    for (int i = 0; i < 2; ++i) {
        try {
            auto ignored = watch.notify({"t"});
            deliveries += static_cast<int>(ignored.size());
            FAIL("evaluation must not succeed");
        } catch (const Error& e) {
            CHECK(e.code() == ErrorCode::QueryFailed);
        }
    }
    CHECK(deliveries == 0);
    CHECK(watch.subscription_count() == 1);

    db.exec("UPDATE t SET v = 2 WHERE id = 2");
    auto repaired = watch.notify({"t"});
    REQUIRE(repaired.size() == 1);
    CHECK(repaired[0].id == id);
    expect_query(repaired[0], db.db, sql);
    CHECK(std::get<std::int64_t>(repaired[0].rows[1][1]) == 2);
}

TEST_CASE("fault-suite: slow consumer gets the latest result and registrations stay bounded") {
    FileDB master_db("m"), replica_db("r"), shadow("s");
    master_db.exec(kSchema);
    replica_db.exec(kSchema);
    shadow.exec(kSchema);
    Master master(master_db.db);
    Replica replica(replica_db.db);
    auto id = replica.subscribe(kWatchSql);
    pump(master, replica, {replica.hello()});
    REQUIRE(replica.state() == Replica::State::Live);

    WriteLog log;
    std::vector<OutMessage> held;
    log.commit(master_db, shadow, "INSERT INTO t VALUES (1, 'a')");
    auto one = master.flush();
    log.commit(master_db, shadow, "INSERT INTO t VALUES (2, 'b')");
    auto two = master.flush();
    log.commit(master_db, shadow, "INSERT INTO t VALUES (3, 'c')");
    auto three = master.flush();
    held.insert(held.end(), one.begin(), one.end());
    held.insert(held.end(), two.begin(), two.end());
    held.insert(held.end(), three.begin(), three.end());
    // Paused consumer: the library has not buffered subscription payloads.
    CHECK(held.size() == 3);
    CHECK(replica.subscription_count() == 1);
    CHECK(replica.prediction_queue_size() == 0);

    std::vector<Message> batch;
    batch.reserve(held.size());
    for (auto& msg : held) batch.push_back(std::move(msg.msg));
    auto hr = replica.handle_messages(batch);
    REQUIRE(hr.subscriptions.size() == 1);
    expect_query(hr.subscriptions[0], replica_db.db, kWatchSql);
    CHECK(hr.subscriptions[0].id == id);
    CHECK(hr.subscriptions[0].rows.size() == 3);
    CHECK(dump(replica_db.db, kWatchSql) == log.replay(kSchema));
    CHECK(replica.subscription_count() == 1);

    for (int i = 0; i < 20; ++i) {
        auto extra = replica.subscribe("SELECT count(*) FROM t");
        replica.unsubscribe(extra);
    }
    CHECK(replica.subscription_count() == 1);
    replica.unsubscribe(id);
    CHECK(replica.subscription_count() == 0);
    log.commit(master_db, shadow, "INSERT INTO t VALUES (4, 'd')");
    for (const auto& msg : master.flush()) {
        auto part = replica.handle_message(msg.msg);
        CHECK(part.subscriptions.empty());
    }
    CHECK(replica.subscription_count() == 0);
}

TEST_CASE("fault-suite: database close and peer replacement do not keep a stale subscription") {
    auto path = make_path("db");
    int calls = 0;
    std::optional<Subscription> sub;
    {
        Database db(path, "CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)");
        sub = db.subscribe("SELECT {id, v} FROM t ORDER BY id",
                           [&](const QueryResult&) { ++calls; });
        CHECK(calls == 1);
        CHECK(db.subscription_count() == 1);
        db.exec("INSERT INTO t VALUES (1, 'fixture')");
        CHECK(calls == 2);
    }
    auto calls_after_close = calls;
    sub.reset();
    CHECK(calls == calls_after_close);
    std::remove(path.c_str());

    FileDB client_db("c"), server_db("s");
    const char* peer_schema =
        "CREATE TABLE local_t (id INTEGER PRIMARY KEY, v TEXT);"
        "CREATE TABLE remote_t (id INTEGER PRIMARY KEY, v TEXT)";
    client_db.exec(peer_schema);
    server_db.exec(peer_schema);
    PeerConfig client_cfg;
    client_cfg.role = PeerRole::Client;
    client_cfg.owned_tables = {"local_t"};
    PeerConfig server_cfg;
    server_cfg.role = PeerRole::Server;
    Peer client(client_db.db, client_cfg);
    Peer server(server_db.db, server_cfg);
    sync_handshake(client, server);
    REQUIRE(client.state() == Peer::State::Live);
    CHECK(client.sync_status() == SyncStatus::Live);

    server_db.exec("INSERT INTO remote_t VALUES (1, 'old')");
    for (const auto& msg : server.flush()) client.handle_message(msg.msg);

    auto stale = client.subscribe("SELECT id, v FROM remote_t ORDER BY id");
    CHECK(client.subscription_count() == 1);
    client.reset();
    server.reset();
    CHECK(client.sync_status() == SyncStatus::Unsynchronized);
    CHECK(client.subscription_count() == 0);
    CHECK_THROWS_AS(client.subscribe("SELECT id, v FROM remote_t ORDER BY id"),
                    Error);

    server_db.exec("INSERT INTO remote_t VALUES (2, 'new')");
    sync_handshake(client, server);
    REQUIRE(client.state() == Peer::State::Live);
    auto id = client.subscribe("SELECT id, v FROM remote_t ORDER BY id");
    CHECK(client.subscription_count() == 1);
    server_db.exec("INSERT INTO remote_t VALUES (3, 'live')");
    PeerHandleResult hr;
    for (const auto& msg : server.flush()) {
        auto part = client.handle_message(msg.msg);
        hr.subscriptions.insert(hr.subscriptions.end(),
                                part.subscriptions.begin(),
                                part.subscriptions.end());
    }
    REQUIRE_FALSE(hr.subscriptions.empty());
    expect_query(last_for(
        HandleResult{{}, {}, hr.subscriptions}, id),
        client_db.db, "SELECT id, v FROM remote_t ORDER BY id");
    CHECK(dump(client_db.db, "SELECT id, v FROM remote_t ORDER BY id") ==
          "1|old\n2|new\n3|live\n");
    (void)stale;
}

TEST_CASE("fault-suite: sqldeep subscription matches a direct query after handshake") {
    auto master_path = make_path("sd-m");
    auto replica_path = make_path("sd-r");
    Database master_db(master_path,
                       "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT)");
    Database replica_db(replica_path,
                        "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT)");
    Master master(master_db.handle());
    Replica replica(replica_db.handle());

    const char* projection = "SELECT {id, name} FROM items ORDER BY id";
    std::vector<QueryResult> seen;
    auto sub = replica_db.subscribe(projection, [&](const QueryResult& result) {
        seen.push_back(result);
    });
    REQUIRE_FALSE(seen.empty());

    pump(master, replica, {replica.hello()});
    REQUIRE(replica.state() == Replica::State::Live);
    master_db.exec("INSERT INTO items VALUES (1, 'fixture')");
    auto flushed = master.flush();
    for (const auto& msg : flushed) replica.handle_message(msg.msg);
    auto before = seen.size();
    replica_db.notify();
    REQUIRE(seen.size() > before);
    auto direct = replica_db.query(projection);
    CHECK(seen.back().columns == direct.columns);
    CHECK(seen.back().rows == direct.rows);
    REQUIRE_FALSE(direct.rows.empty());
    CHECK(value_text(direct.rows[0][0]).find("fixture") != std::string::npos);

    master_db.exec("INSERT INTO items VALUES (2, 'live')");
    for (const auto& msg : master.flush()) replica.handle_message(msg.msg);
    replica_db.notify();
    direct = replica_db.query(projection);
    CHECK(seen.back().rows == direct.rows);
    CHECK(direct.rows.size() == 2);
    CHECK(replica_db.subscription_count() == 1);

    std::remove(master_path.c_str());
    std::remove(replica_path.c_str());
}

TEST_CASE("fault-suite: protocol failure is distinct from unsynchronized and live") {
    FileDB master_db("m"), replica_db("r");
    master_db.exec(kSchema);
    replica_db.exec(kSchema);
    Master master(master_db.db);
    Replica replica(replica_db.db);
    CHECK(replica.sync_status() == SyncStatus::Unsynchronized);

    auto hello = replica.hello();
    CHECK(replica.sync_status() == SyncStatus::Synchronizing);
    pump(master, replica, {std::move(hello)});
    REQUIRE(replica.sync_status() == SyncStatus::Live);

    replica.handle_message(Message{ErrorMsg{ErrorCode::ProtocolError, "boom"}});
    CHECK(replica.state() == Replica::State::Error);
    CHECK(replica.sync_status() == SyncStatus::Failed);
    CHECK(replica.sync_status() != SyncStatus::Live);
}
