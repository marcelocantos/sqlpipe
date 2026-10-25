// Copyright 2026 The sqlpipe Authors
// SPDX-License-Identifier: Apache-2.0
//
// Fresh public-API consumer (not the doctest translation unit). Replicates
// one owned table, subscribes to a sqldeep projection, drives the handshake,
// and prints the subscription payload. Exits non-zero when that payload
// differs from a direct query or does not contain the fixture row.

#include <sqlpipe.h>

#include <cstdio>
#include <filesystem>
#include <iostream>
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

std::string format_result(const QueryResult& result) {
    std::string out;
    for (std::size_t c = 0; c < result.columns.size(); ++c) {
        if (c) out += "\t";
        out += result.columns[c];
    }
    out += "\n";
    for (const auto& row : result.rows) {
        for (std::size_t c = 0; c < row.size(); ++c) {
            if (c) out += "\t";
            out += value_text(row[c]);
        }
        out += "\n";
    }
    return out;
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
            all.subscriptions.insert(all.subscriptions.end(),
                                     hr.subscriptions.begin(),
                                     hr.subscriptions.end());
            to_master.insert(to_master.end(),
                             hr.messages.begin(), hr.messages.end());
        }
    }
    return all;
}

} // namespace

int main() {
    namespace fs = std::filesystem;
    auto dir = fs::temp_directory_path();
    auto master_path =
        dir / ("sqlpipe-consumer-m-" + std::to_string(static_cast<long long>(getpid())));
    auto replica_path =
        dir / ("sqlpipe-consumer-r-" + std::to_string(static_cast<long long>(getpid())));
    const char* schema =
        "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT)";
    const char* projection = "SELECT {id, name} FROM items ORDER BY id";

    int rc = 0;
    try {
        Database master_db(master_path.string(), schema);
        Database replica_db(replica_path.string(), schema);
        Master master(master_db.handle());
        Replica replica(replica_db.handle());

        std::vector<QueryResult> seen;
        auto sub = replica_db.subscribe(projection, [&](const QueryResult& result) {
            seen.push_back(result);
        });

        pump(master, replica, {replica.hello()});
        if (replica.state() != Replica::State::Live) {
            std::cerr << "handshake did not reach Live\n";
            return 1;
        }

        master_db.exec("INSERT INTO items VALUES (1, 'fixture')");
        for (const auto& msg : master.flush()) replica.handle_message(msg.msg);
        replica_db.notify();

        if (seen.empty()) {
            std::cerr << "subscription produced no payload\n";
            return 1;
        }
        auto direct = replica_db.query(projection);
        const auto& payload = seen.back();
        auto text = format_result(payload);
        std::cout << text;
        if (payload.columns != direct.columns || payload.rows != direct.rows) {
            std::cerr << "subscription diverged from direct query\n";
            rc = 1;
        } else if (direct.rows.empty() ||
                   value_text(direct.rows[0][0]).find("fixture") == std::string::npos) {
            std::cerr << "fixture row missing\n";
            rc = 1;
        } else {
            std::cout << "match=1\n";
        }
        (void)sub;
    } catch (const std::exception& e) {
        std::cerr << e.what() << "\n";
        rc = 1;
    }
    std::error_code ec;
    fs::remove(master_path, ec);
    fs::remove(replica_path, ec);
    return rc;
}
