# sqlpipe

Streaming replication protocol for SQLite.

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

sqlpipe is a C++ library that keeps two SQLite databases in sync over any
transport layer. A **Master** component tracks changes and produces compact
binary changesets; a **Replica** component applies them, emitting per-row change
events to client code as they arrive.

The library is transport-agnostic: it defines a message-in / message-out API.
You decide how messages travel between master and replica (TCP, WebSocket,
serial, shared memory, etc.).

## Features

- **Incremental replication** via SQLite's session extension (compact binary
  changesets)
- **Catchup on reconnect** from a configurable log of recent changesets
- **Full resync** when the log doesn't cover the gap or schemas diverge
- **Per-row change events** (insert/update/delete) on the replica side
- **Conflict callbacks** for custom resolution logic
- **Schema fingerprinting** to detect and handle schema mismatches
- **Single header + source** (`sqlpipe.h` / `sqlpipe.cpp`) for easy integration

## Requirements

- C++20 compiler
- SQLite 3 compiled with `-DSQLITE_ENABLE_SESSION
  -DSQLITE_ENABLE_PREUPDATE_HOOK`
- [spdlog](https://github.com/gabime/spdlog) (header-only)

All tables must have explicit `PRIMARY KEY`s (required by SQLite's session
extension).

## Quick start

```cpp
#include <sqlpipe.h>
using namespace sqlpipe;

// Open two databases with matching schemas.
sqlite3 *master_db, *replica_db;
sqlite3_open(":memory:", &master_db);
sqlite3_open(":memory:", &replica_db);
sqlite3_exec(master_db,
    "CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)", 0, 0, 0);
sqlite3_exec(replica_db,
    "CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)", 0, 0, 0);

// Create master and replica.
Master master(master_db);
Replica replica(replica_db);

// Handshake.
auto hello = replica.hello();
auto resp = master.handle_message(hello);
for (auto& m : resp) replica.handle_message(m);

// Make changes on the master, then flush.
sqlite3_exec(master_db, "INSERT INTO t VALUES (1, 'hello')", 0, 0, 0);
auto msgs = master.flush();
for (auto& m : msgs) replica.handle_message(m);
// replica_db now has the row.
```

See [`examples/loopback.cpp`](examples/loopback.cpp) for a complete working
example including change event callbacks.

## Building

```sh
git clone --recurse-submodules https://github.com/marcelocantos/sqlpipe.git
cd sqlpipe
make test     # build and run tests (28 test cases)
make example  # build and run the loopback demo
```

## Protocol overview

```
Replica                              Master
   |                                    |
   |-- HelloMsg(seq, sv) ------------->|
   |                                    |
   |<-- HelloMsg(seq, sv) -------------|  (schema match, replica behind)
   |<-- CatchupBeginMsg --------------|
   |<-- ChangesetMsg ... -------------|
   |<-- CatchupEndMsg ----------------|
   |-- AckMsg ----------------------->|
   |                                    |
   |         [LIVE STREAMING]           |
   |<-- ChangesetMsg -----------------|  (master.flush())
   |-- AckMsg ----------------------->|
```

On schema mismatch or when the changeset log doesn't cover the gap, the master
triggers a full resync instead.

## API

### Master

```cpp
class Master {
public:
    explicit Master(sqlite3* db, MasterConfig config = {});
    std::vector<Message> flush();
    std::vector<Message> handle_message(const Message& msg);
    Seq current_seq() const;
};
```

### Replica

```cpp
class Replica {
public:
    explicit Replica(sqlite3* db, ReplicaConfig config = {});
    Message hello() const;
    std::vector<Message> handle_message(const Message& msg);
    Seq current_seq() const;
    State state() const;  // Init, Handshake, Catchup, Resync, Live, Error
};
```

### ReplicaConfig

```cpp
struct ReplicaConfig {
    ChangeCallback   on_change       = nullptr;  // per-row, post-apply
    ConflictCallback on_conflict     = nullptr;  // per-conflict during apply
    std::function<void()> on_resync_begin = nullptr;
    std::function<void()> on_resync_end   = nullptr;
};
```

## License

Apache 2.0. See [LICENSE](LICENSE) for details.

Third-party dependencies:
- **SQLite** - public domain
- **spdlog** - MIT
- **doctest** - MIT
