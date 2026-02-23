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
};

} // namespace

TEST_CASE("replica: initial state") {
    DB d;
    Replica r(d.db);
    CHECK(r.current_seq() == 0);
    CHECK(r.state() == Replica::State::Init);
}

TEST_CASE("replica: hello produces HelloMsg") {
    DB d;
    Replica r(d.db);
    auto msg = r.hello();
    auto& h = std::get<HelloMsg>(msg);
    CHECK(h.protocol_version == kProtocolVersion);
    CHECK(r.state() == Replica::State::Handshake);
}

TEST_CASE("replica: transitions through diff states to live") {
    DB d;
    d.exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)");
    Replica r(d.db);
    r.hello();

    // Master says hello back.
    auto result = r.handle_message(HelloMsg{kProtocolVersion, r.schema_version(), {}});
    CHECK(r.state() == Replica::State::DiffBuckets);
    // Replica sends BucketHashesMsg.
    REQUIRE(!result.messages.empty());
    CHECK(std::holds_alternative<BucketHashesMsg>(result.messages[0]));

    // Master says no buckets needed (empty NeedBucketsMsg).
    result = r.handle_message(NeedBucketsMsg{});
    CHECK(r.state() == Replica::State::DiffRows);

    // Master sends empty DiffReadyMsg.
    result = r.handle_message(DiffReadyMsg{0, {}, {}});
    CHECK(r.state() == Replica::State::Live);
    // Should produce an AckMsg.
    REQUIRE(!result.messages.empty());
    CHECK(std::holds_alternative<AckMsg>(result.messages[0]));
}
