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

TEST_CASE("QueryWatch standalone — subscribe returns current result") {
    DB d;
    d.exec("CREATE TABLE items(id INTEGER PRIMARY KEY, name TEXT)");
    d.exec("INSERT INTO items VALUES(1, 'alpha')");
    d.exec("INSERT INTO items VALUES(2, 'beta')");

    QueryWatch w(d.db);
    auto result = w.subscribe("SELECT name FROM items ORDER BY id");

    CHECK(result.columns == std::vector<std::string>{"name"});
    REQUIRE(result.rows.size() == 2);
    CHECK(std::get<std::string>(result.rows[0][0]) == "alpha");
    CHECK(std::get<std::string>(result.rows[1][0]) == "beta");
}

TEST_CASE("QueryWatch standalone — notify detects changes") {
    DB d;
    d.exec("CREATE TABLE items(id INTEGER PRIMARY KEY, name TEXT)");
    d.exec("INSERT INTO items VALUES(1, 'alpha')");

    QueryWatch w(d.db);
    w.subscribe("SELECT name FROM items ORDER BY id");

    // No change yet — notify should return nothing.
    auto unchanged = w.notify({"items"});
    CHECK(unchanged.empty());

    // Insert a row — notify should detect the change.
    d.exec("INSERT INTO items VALUES(2, 'beta')");
    auto changed = w.notify({"items"});
    REQUIRE(changed.size() == 1);
    REQUIRE(changed[0].rows.size() == 2);
    CHECK(std::get<std::string>(changed[0].rows[1][0]) == "beta");
}

TEST_CASE("QueryWatch standalone — unrelated table does not fire") {
    DB d;
    d.exec("CREATE TABLE items(id INTEGER PRIMARY KEY, name TEXT)");
    d.exec("CREATE TABLE other(id INTEGER PRIMARY KEY, val INT)");
    d.exec("INSERT INTO items VALUES(1, 'alpha')");

    QueryWatch w(d.db);
    w.subscribe("SELECT name FROM items ORDER BY id");

    d.exec("INSERT INTO other VALUES(1, 42)");
    auto result = w.notify({"other"});
    CHECK(result.empty());
}

TEST_CASE("QueryWatch standalone — unsubscribe stops notifications") {
    DB d;
    d.exec("CREATE TABLE items(id INTEGER PRIMARY KEY, name TEXT)");
    d.exec("INSERT INTO items VALUES(1, 'alpha')");

    QueryWatch w(d.db);
    auto result = w.subscribe("SELECT name FROM items ORDER BY id");
    w.unsubscribe(result.id);

    d.exec("INSERT INTO items VALUES(2, 'beta')");
    auto changed = w.notify({"items"});
    CHECK(changed.empty());
    CHECK(w.empty());
}

TEST_CASE("QueryWatch standalone — multiple subscriptions on same table") {
    DB d;
    d.exec("CREATE TABLE items(id INTEGER PRIMARY KEY, name TEXT, active INT)");
    d.exec("INSERT INTO items VALUES(1, 'alpha', 1)");
    d.exec("INSERT INTO items VALUES(2, 'beta', 0)");

    QueryWatch w(d.db);
    w.subscribe("SELECT name FROM items ORDER BY id");
    w.subscribe("SELECT name FROM items WHERE active = 1");

    // Change that affects both queries.
    d.exec("UPDATE items SET active = 1 WHERE id = 2");
    auto changed = w.notify({"items"});
    // The first query's result (all rows) hasn't changed, only the second.
    REQUIRE(changed.size() == 1);
    REQUIRE(changed[0].rows.size() == 2);  // now both active
}

TEST_CASE("QueryWatch standalone — JOIN across tables") {
    DB d;
    d.exec("CREATE TABLE orders(id INTEGER PRIMARY KEY, item_id INT)");
    d.exec("CREATE TABLE items(id INTEGER PRIMARY KEY, name TEXT)");
    d.exec("INSERT INTO items VALUES(1, 'widget')");
    d.exec("INSERT INTO orders VALUES(1, 1)");

    QueryWatch w(d.db);
    w.subscribe(
        "SELECT o.id, i.name FROM orders o "
        "JOIN items i ON o.item_id = i.id ORDER BY o.id");

    // Change to items should fire the subscription.
    d.exec("UPDATE items SET name = 'gadget' WHERE id = 1");
    auto changed = w.notify({"items"});
    REQUIRE(changed.size() == 1);
    CHECK(std::get<std::string>(changed[0].rows[0][1]) == "gadget");

    // Change to orders should also fire.
    d.exec("INSERT INTO orders VALUES(2, 1)");
    changed = w.notify({"orders"});
    REQUIRE(changed.size() == 1);
    CHECK(changed[0].rows.size() == 2);
}

TEST_CASE("QueryWatch standalone — empty() reflects state") {
    DB d;
    d.exec("CREATE TABLE items(id INTEGER PRIMARY KEY, name TEXT)");

    QueryWatch w(d.db);
    CHECK(w.empty());

    auto result = w.subscribe("SELECT * FROM items");
    CHECK_FALSE(w.empty());

    w.unsubscribe(result.id);
    CHECK(w.empty());
}
