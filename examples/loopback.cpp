// Copyright 2026 The sqlpipe Authors
// SPDX-License-Identifier: Apache-2.0
#include <sqlpipe.h>

#include <spdlog/spdlog.h>

#include <sqlite3.h>

#include <cstdio>
#include <string>
#include <vector>

using namespace sqlpipe;

static HandleResult deliver(const std::vector<Message>& msgs, Replica& handler) {
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

static void print_events(const std::vector<ChangeEvent>& changes) {
    for (const auto& e : changes) {
        const char* op_str = "?";
        switch (e.op) {
        case OpType::Insert: op_str = "INSERT"; break;
        case OpType::Update: op_str = "UPDATE"; break;
        case OpType::Delete: op_str = "DELETE"; break;
        }
        std::printf("  [event] %s on %s\n", op_str, e.table.c_str());
    }
}

int main() {
    spdlog::set_level(spdlog::level::info);

    // Open two in-memory databases.
    sqlite3* master_db = nullptr;
    sqlite3* replica_db = nullptr;
    sqlite3_open(":memory:", &master_db);
    sqlite3_open(":memory:", &replica_db);

    // Create matching schemas.
    const char* schema =
        "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)";
    sqlite3_exec(master_db, schema, nullptr, nullptr, nullptr);
    sqlite3_exec(replica_db, schema, nullptr, nullptr, nullptr);

    Master master(master_db);
    Replica replica(replica_db);

    // 1. Handshake.
    std::printf("=== Handshake ===\n");
    auto hello = replica.hello();
    auto master_resp = master.handle_message(hello);
    deliver(master_resp, replica);
    std::printf("Replica state: Live=%d, seq=%lld\n\n",
                replica.state() == Replica::State::Live,
                static_cast<long long>(replica.current_seq()));

    // 2. Insert some rows on master.
    std::printf("=== Insert rows ===\n");
    sqlite3_exec(master_db,
        "INSERT INTO users VALUES (1, 'Alice', 'alice@example.com');"
        "INSERT INTO users VALUES (2, 'Bob', 'bob@example.com');",
        nullptr, nullptr, nullptr);
    auto result = deliver(master.flush(), replica);
    print_events(result.changes);
    std::printf("Master seq=%lld, Replica seq=%lld\n\n",
                static_cast<long long>(master.current_seq()),
                static_cast<long long>(replica.current_seq()));

    // 3. Update a row.
    std::printf("=== Update row ===\n");
    sqlite3_exec(master_db,
        "UPDATE users SET email='alice@newmail.com' WHERE id=1",
        nullptr, nullptr, nullptr);
    result = deliver(master.flush(), replica);
    print_events(result.changes);

    // 4. Delete a row.
    std::printf("=== Delete row ===\n");
    sqlite3_exec(master_db,
        "DELETE FROM users WHERE id=2",
        nullptr, nullptr, nullptr);
    result = deliver(master.flush(), replica);
    print_events(result.changes);

    std::printf("\nFinal master seq=%lld, replica seq=%lld\n",
                static_cast<long long>(master.current_seq()),
                static_cast<long long>(replica.current_seq()));

    sqlite3_close(master_db);
    sqlite3_close(replica_db);
    return 0;
}
