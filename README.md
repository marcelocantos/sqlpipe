# sqlpipe

Streaming replication protocol for SQLite.

sqlpipe is a C++ library that keeps SQLite databases in sync over any transport
layer. A **Master** tracks changes and produces compact binary changesets; a
**Replica** applies them, emitting per-row change events and query subscription
updates. A **Peer** wraps both behind a symmetric API for bidirectional
replication with table-level ownership. A **Relay** enables chain replication
(source -> relay -> sink).

The library is transport-agnostic: it defines a message-in / message-out API.
You decide how messages travel between peers (TCP, WebSocket, QUIC, serial,
shared memory, datagrams, etc.). The convergence loop makes every message
regenerable, so the protocol works over pure datagrams -- any message can be
lost and recovered by the next convergence round.

## Features

- **Convergence loop** -- `Replica::converge()` provides stateless,
  loss-tolerant sync. The replica computes bucket hashes and sends them
  directly; the master responds with the delta. Works entirely over
  datagrams. No handshake required. Call it periodically or on reconnect.
- **Bidirectional replication** via the Peer API -- each side owns a disjoint
  set of tables, with server-authoritative ownership negotiation
- **Chain replication** via the Relay class -- source -> relay -> sink
  topologies for fan-out or geographic distribution
- **Incremental replication** via SQLite's session extension (compact binary
  changesets)
- **Efficient diff sync** on reconnect -- bucketed row hashes identify what
  differs, then only the delta is transferred
- **Changeset queue** -- master retains recent changesets
  (`changeset_queue_size`, default 64) for fast reconnect replay without
  full diff sync
- **Predicate-aware query subscriptions** -- register SQL queries on the
  replica; receive updated result sets only when incoming changes match
  extracted predicates. Queries are parsed via liteparser into relational
  algebra; predicates are propagated through equijoins and evaluated by a
  bytecode VM. Supports equality, inequality, range, IS NULL, IN, NOT IN,
  BETWEEN, and OR-of-equalities.
- **Prediction API** -- `begin_prediction`/`commit_prediction`/`rollback_prediction`
  for optimistic local updates with automatic rollback on server response
- **Auto-flush** -- `MasterConfig::on_flush` callback fires on commit, so
  callers never need to call `flush()` explicitly
- **Per-row change events** (insert/update/delete) on the receiving side
- **Conflict callbacks** for custom resolution logic
- **LZ4 changeset compression** -- automatic, with uncompressed fallback
- **Schema fingerprinting** via structural hashing (sqlift) to detect mismatches
- **Single header + source** (`sqlpipe.h` / `sqlpipe.cpp`) for easy integration
- **Formally verified** -- the convergence protocol is modelled in
  [TLA+](formal/Convergence.tla) and checked with TLC

## Language bindings

| Language | Location | Install |
|---|---|---|
| C++ | `dist/sqlpipe.h` + `dist/sqlpipe.cpp` | Copy two files |
| Go | `go/sqlpipe/` | `go get github.com/marcelocantos/sqlpipe/go/sqlpipe` |
| Swift | `swift/` | SPM package with `CSqlpipe` and `Sqlpipe` targets |
| TypeScript/Wasm | `web/` | `npm install` (builds SQLite + sqlpipe to Wasm) |

## Requirements

- C++23 compiler
- SQLite 3 compiled with `-DSQLITE_ENABLE_SESSION
  -DSQLITE_ENABLE_PREUPDATE_HOOK`

All tables must have explicit `PRIMARY KEY`s (required by SQLite's session
extension). `WITHOUT ROWID` tables are not supported.

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

// Handshake (exchange messages until replica reaches Live state).
sync_handshake(master, replica);  // convenience for in-process use

// Make changes on the master, then flush.
sqlite3_exec(master_db, "INSERT INTO t VALUES (1, 'hello')", 0, 0, 0);
auto msgs = master.flush();  // returns vector<Message>
for (auto& msg : msgs) {
    auto result = replica.handle_message(msg);
    // result.messages    — vector<Message> to send back
    // result.changes     — per-row ChangeEvents
    // result.subscriptions — updated query results
}
// replica_db now has the row.
```

See [`examples/loopback.cpp`](examples/loopback.cpp) for a complete working
example including handshake and change event handling.

## Building

```sh
git clone --recurse-submodules https://github.com/marcelocantos/sqlpipe.git
cd sqlpipe
mk test     # build and run tests (134 test cases)
mk example  # build and run the loopback demo
mk wasm     # build Wasm module (requires emscripten)
```

If you use an agentic coding tool (Claude Code, Cursor, Copilot, etc.), include
[`dist/sqlpipe-agents-guide.md`](dist/sqlpipe-agents-guide.md) in your project
context for a condensed API reference.

## Protocol overview

Two sync paths are available. The convergence loop is preferred for most use
cases; the legacy handshake is available for environments that require
ordered reliable delivery.

**Convergence loop** (preferred -- stateless, works over datagrams):

```
Replica                              Master
   |                                    |
   |-- BucketHashesMsg -------------->|  converge() — no prior hello needed
   |                                    |  compare bucket hashes
   |<-- NeedBucketsMsg ---------------|  (skipped if all match)
   |                                    |
   |-- RowHashesMsg ----------------->|  row-level hashes for mismatched buckets
   |                                    |
   |<-- DiffReadyMsg -----------------|  patchset + per-table deletes
   |-- AckMsg ----------------------->|
   |                                    |
   |         [LIVE STREAMING]           |
   |<-- ChangesetMsg -----------------|  (master.flush())
   |-- AckMsg ----------------------->|
```

Every message in the convergence loop is regenerable. If any message is
lost, call `converge()` again -- the loop is idempotent. The master
processes `BucketHashesMsg` directly without requiring a prior `HelloMsg`.

**Legacy handshake** (ordered reliable channel):

```
Replica                              Master
   |                                    |
   |-- HelloMsg --------------------->|
   |<-- HelloMsg ---------------------|  schema mismatch -> ErrorMsg
   |                                    |
   |-- BucketHashesMsg -------------->|
   |<-- NeedBucketsMsg ---------------|
   |-- RowHashesMsg ----------------->|
   |<-- DiffReadyMsg -----------------|
   |-- AckMsg ----------------------->|
   |                                    |
   |         [LIVE STREAMING]           |
```

## API

### Master

```cpp
struct MasterConfig {
    std::optional<std::set<std::string>> table_filter;  // nullopt = all tables
    std::int64_t bucket_size = 1024;
    ProgressCallback on_progress = nullptr;
    SchemaMismatchCallback on_schema_mismatch = nullptr;
    FlushCallback on_flush = nullptr;        // auto-flush on commit (takes std::vector<Message>)
    std::size_t changeset_queue_size = 64;   // 0 = disable queue replay
    LogCallback on_log = nullptr;
};

class Master {
public:
    explicit Master(sqlite3* db, MasterConfig config = {});
    void exec(const std::string& sql);                     // auto-flushes if on_flush set
    std::vector<Message> flush();                          // manual flush
    std::vector<Message> handle_message(const Message& msg);
    Seq current_seq() const;
    SchemaVersion schema_version() const;
};
```

### Replica

```cpp
struct ReplicaConfig {
    ConflictCallback on_conflict = nullptr;
    std::optional<std::set<std::string>> table_filter;
    std::int64_t bucket_size = 1024;
    ProgressCallback on_progress = nullptr;
    SchemaMismatchCallback on_schema_mismatch = nullptr;
    LogCallback on_log = nullptr;
};

struct HandleResult {
    std::vector<Message>      messages;       // protocol responses
    std::vector<ChangeEvent>  changes;        // row-level changes applied
    std::vector<QueryResult>  subscriptions;  // invalidated query results
};

class Replica {
public:
    explicit Replica(sqlite3* db, ReplicaConfig config = {});
    Message hello() const;
    std::vector<Message> converge();                       // stateless sync
    HandleResult handle_message(const Message& msg);
    HandleResult handle_messages(std::span<const Message> msgs);  // batched
    SubscriptionId subscribe(const std::string& sql);
    void unsubscribe(SubscriptionId id);
    void begin_prediction();       // optimistic local update
    void commit_prediction();      // finalise prediction
    void rollback_prediction();    // cancel prediction
    void reset();                  // back to Init; preserves subscriptions
    Seq current_seq() const;
    SchemaVersion schema_version() const;
    State state() const;  // Init, Handshake, DiffBuckets, DiffRows, Live, Error
};
```

### Peer (bidirectional)

```cpp
enum class PeerRole : std::uint8_t { Client, Server };

struct PeerConfig {
    PeerRole role = PeerRole::Client;
    std::set<std::string> owned_tables;
    std::optional<std::set<std::string>> table_filter;
    ApproveOwnershipCallback approve_ownership = nullptr;  // server only
    ConflictCallback on_conflict = nullptr;
    ProgressCallback on_progress = nullptr;
    SchemaMismatchCallback on_schema_mismatch = nullptr;
    LogCallback on_log = nullptr;
};

struct PeerHandleResult {
    std::vector<PeerMessage>  messages;
    std::vector<ChangeEvent>  changes;
    std::vector<QueryResult>  subscriptions;
};

class Peer {
public:
    explicit Peer(sqlite3* db, PeerConfig config = {});
    std::vector<PeerMessage> start();      // client initiates
    std::vector<PeerMessage> flush();
    PeerHandleResult handle_message(const PeerMessage& msg);
    SubscriptionId subscribe(const std::string& sql);
    void unsubscribe(SubscriptionId id);
    void reset();
    State state() const;  // Init, Negotiating, Diffing, Live, Error
    const std::set<std::string>& owned_tables() const;
    const std::set<std::string>& remote_tables() const;
};
```

### Relay (chain replication)

```cpp
class Relay {
public:
    explicit Relay(sqlite3* db, RelayConfig config = {});
    std::size_t add_sink(SinkCallback cb);             // register downstream (takes const Message&)
    void remove_sink(std::size_t id);
    Message hello();                                   // send to upstream
    std::vector<Message> handle_upstream(const Message& msg);
    std::vector<Message> handle_downstream(const Message& msg);
    SubscriptionId subscribe(const std::string& sql);
    void unsubscribe(SubscriptionId id);
    void reset();
};
```

### Query subscriptions

Register SQL queries on the replica to receive updated results when incoming
changes match the query's predicates:

```cpp
auto id = replica.subscribe("SELECT id, val FROM t1 WHERE val > 10 ORDER BY id");

// After applying a changeset:
auto result = replica.handle_message(changeset_msg);
for (const auto& sub : result.subscriptions) {
    // sub.id      — which subscription fired
    // sub.columns — column names
    // sub.rows    — the full updated result set
}

replica.unsubscribe(id);
```

Predicates are extracted from WHERE clauses and propagated through equijoins.
A bytecode VM evaluates predicates against changeset rows, so subscriptions
whose predicates don't match are skipped entirely -- no SQL re-evaluation
needed.

### Prediction API

Optimistic local updates with automatic rollback:

```cpp
replica.begin_prediction();
// Write optimistically to the local database.
sqlite3_exec(replica_db, "INSERT INTO items VALUES (99, 'pending')", 0, 0, 0);
// Subscriptions now reflect the predicted state.
replica.commit_prediction();
// Send the corresponding action to the server.
// When the server's changeset arrives via handle_message(), the prediction
// savepoint is automatically rolled back and the server's state applied.
```

### Reconnection

**Convergence loop** (preferred): Call `converge()` at any time to sync
without a handshake. Works from any state -- Init, Live, or after `reset()`.

```cpp
replica.reset();
auto msgs = replica.converge();  // returns BucketHashesMsg
// Send msgs to master, process responses normally.
// If a message is lost, just call converge() again.
```

**Legacy handshake**: For ordered reliable channels.

```cpp
replica.reset();
auto hello = replica.hello();
// ... exchange messages until Live ...
```

**Peer reconnection**:

```cpp
peer.reset();              // preserves table ownership
auto msgs = peer.start();  // re-initiate handshake
```

## Error handling

All operations may throw `sqlpipe::Error`, which carries an `ErrorCode` and a
human-readable message:

```cpp
try {
    auto msgs = master.flush();  // std::vector<Message>
} catch (const sqlpipe::Error& e) {
    // e.code()  — ErrorCode enum
    // e.what()  — descriptive string
}
```

| ErrorCode | Meaning | Recommended action |
|---|---|---|
| `SqliteError` | An underlying SQLite call failed | Check the message; may indicate corruption or constraint violation |
| `ProtocolError` | Malformed or unexpected message | Disconnect and reconnect |
| `SchemaMismatch` | Master and replica schemas differ | Install `on_schema_mismatch`, or migrate offline and reconnect |
| `InvalidState` | Operation not valid in current state | Bug in calling code |
| `OwnershipRejected` | Peer ownership request rejected | Server's `approve_ownership` returned false |
| `WithoutRowidTable` | Table uses `WITHOUT ROWID` | Use regular rowid tables |

## Schema migration

Install a callback to run migrations on schema mismatch instead of erroring:

```cpp
ReplicaConfig rc;
rc.on_schema_mismatch = [&](SchemaVersion remote, SchemaVersion local,
                            const std::string& remote_schema_sql) {
    // remote_schema_sql has the master's CREATE TABLE statements.
    sqlite3_exec(replica_db, "ALTER TABLE t ADD COLUMN new_col TEXT", 0, 0, 0);
    return true;  // reset to Init; re-handshake
};
```

The same callback is available on `MasterConfig` and `PeerConfig`.

## Transport wiring

sqlpipe is transport-agnostic. The wire format is length-prefixed:

```cpp
// Sending:
auto buf = sqlpipe::serialize(msg);   // or serialize(peer_msg)
send(socket, buf.data(), buf.size());

// Receiving:
uint8_t hdr[4];
recv(socket, hdr, 4);
uint32_t len = hdr[0] | (hdr[1]<<8) | (hdr[2]<<16) | (hdr[3]<<24);
std::vector<uint8_t> buf(4 + len);
memcpy(buf.data(), hdr, 4);
recv(socket, buf.data() + 4, len);
auto msg = sqlpipe::deserialize(buf);    // or deserialize_peer(buf)
```

The Go wrapper provides a `Transport` interface in
`go/sqlpipe/transport` for pluggable transport implementations.

## Thread safety

`Master`, `Replica`, `Peer`, and `Relay` are **not thread-safe**. Each
instance must be accessed from a single thread at a time. The `sqlite3*`
handle must not be used concurrently during sqlpipe operations.

## Message size limits

- **`kMaxMessageSize`** (64 MB) -- maximum serialized message size
- **`kMaxArrayCount`** (10 M) -- maximum elements in any array field

Messages exceeding these limits cause `deserialize()` to throw `ProtocolError`.

## Related projects

- **[sqldeep](https://github.com/marcelocantos/sqldeep)** -- JSON5-like SQL syntax transpiler for SQLite JSON functions
- **[sqlift](https://github.com/marcelocantos/sqlift)** -- Declarative SQLite schema migrations via structural diffing

## License

Apache 2.0. See [LICENSE](LICENSE) for details.

Third-party dependencies:
- **SQLite** -- public domain
- **LZ4** -- BSD 2-Clause
- **spdlog** -- MIT
- **nlohmann/json** -- MIT
- **liteparser** -- MIT
- **sqlift** -- Apache 2.0
- **doctest** -- MIT (test only)
