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

// Perform the multi-step handshake (hello → bucket hashes → row hashes → diff).
static void handshake(Master& master, Replica& replica) {
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
                               result2.messages.begin(), result2.messages.end());
        }
        for (const auto& m3 : r2.messages) {
            auto result3 = master.handle_message(m3);
            for (const auto& m4 : result3) {
                replica.handle_message(m4);
            }
        }
    }
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

    // 1. Handshake (includes diff sync).
    std::printf("=== Handshake ===\n");
    handshake(master, replica);
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
