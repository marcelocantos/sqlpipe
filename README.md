# sqlpipe

Streaming replication protocol for SQLite.

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

sqlpipe is a C++ library that keeps two SQLite databases in sync over any
transport layer. A **Master** component tracks changes and produces compact
binary changesets; a **Replica** component applies them, emitting per-row change
events to client code as they arrive. A **Peer** component wraps both behind a
symmetric API for bidirectional replication with table-level ownership.

The library is transport-agnostic: it defines a message-in / message-out API.
You decide how messages travel between peers (TCP, WebSocket, serial, shared
memory, etc.).

## Features

- **Bidirectional replication** via the Peer API — each side owns a disjoint
  set of tables, with server-authoritative ownership negotiation
- **Incremental replication** via SQLite's session extension (compact binary
  changesets)
- **Efficient diff sync** on reconnect — bucketed row hashes identify what
  differs, then only the delta is transferred
- **Query subscriptions** — register SQL queries on the replica; receive updated
  result sets automatically when incoming changes affect relevant tables
- **Per-row change events** (insert/update/delete) on the receiving side
- **Conflict callbacks** for custom resolution logic
- **LZ4 changeset compression** — changeset blobs are automatically compressed
  with LZ4 for reduced bandwidth (transparent, with uncompressed fallback)
- **Schema fingerprinting** to detect schema mismatches
- **Single header + source** (`sqlpipe.h` / `sqlpipe.cpp`) for easy integration

## Requirements

- C++20 compiler
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
// See examples/loopback.cpp for the full multi-step handshake.

// Make changes on the master, then flush.
sqlite3_exec(master_db, "INSERT INTO t VALUES (1, 'hello')", 0, 0, 0);
auto msgs = master.flush();
for (auto& m : msgs) {
    auto result = replica.handle_message(m);
    // result.messages — AckMsg to send back to master
    // result.changes  — per-row ChangeEvents (table, op, old/new values)
}
// replica_db now has the row.
```

See [`examples/loopback.cpp`](examples/loopback.cpp) for a complete working
example including the handshake and change event handling.

## Building

```sh
git clone --recurse-submodules https://github.com/marcelocantos/sqlpipe.git
cd sqlpipe
mk test     # build and run tests (74 test cases)
mk example  # build and run the loopback demo
```

If you use an agentic coding tool (Claude Code, Cursor, Copilot, etc.), include
[`agents-guide.md`](agents-guide.md) in your project context for a condensed
API reference.

## Protocol overview

**Diff sync** (reconnect — discovers and transfers only what differs):

```
Replica                              Master
   |                                    |
   |-- HelloMsg(sv) ------------------>|
   |<-- HelloMsg(sv) -----------------|  schema mismatch → ErrorMsg
   |                                    |
   |-- BucketHashesMsg -------------->|  per-table bucketed row hashes
   |                                    |  compare bucket hashes
   |<-- NeedBucketsMsg (ranges) ------|  (empty if all match)
   |                                    |
   |-- RowHashesMsg ----------------->|  row-level hashes for mismatched buckets
   |                                    |  compute diff: insert/update/delete
   |<-- DiffReadyMsg(seq, patchset,  |
   |      deletes per table) ---------|
   |-- AckMsg ----------------------->|
   |                                    |
   |         [LIVE STREAMING]           |
   |<-- ChangesetMsg -----------------|  (master.flush())
   |-- AckMsg ----------------------->|
```

## API

### Master

```cpp
struct MasterConfig {
    std::optional<std::set<std::string>> table_filter;
    std::int64_t bucket_size = 1024;  // rows per diff bucket
    ProgressCallback on_progress = nullptr;
    SchemaMismatchCallback on_schema_mismatch = nullptr;
};

class Master {
public:
    explicit Master(sqlite3* db, MasterConfig config = {});
    std::vector<Message> flush();
    std::vector<Message> handle_message(const Message& msg);
    Seq current_seq() const;
    SchemaVersion schema_version() const;
};
```

### Replica

```cpp
struct ReplicaConfig {
    ConflictCallback on_conflict = nullptr;  // default: Abort
    std::optional<std::set<std::string>> table_filter;
    std::int64_t bucket_size = 1024;
    ProgressCallback on_progress = nullptr;
    SchemaMismatchCallback on_schema_mismatch = nullptr;
};

struct HandleResult {
    std::vector<Message>      messages;       // protocol responses to send back
    std::vector<ChangeEvent>  changes;        // row-level changes applied this call
    std::vector<QueryResult>  subscriptions;  // invalidated subscription results
};

class Replica {
public:
    explicit Replica(sqlite3* db, ReplicaConfig config = {});
    Message hello() const;
    HandleResult handle_message(const Message& msg);
    HandleResult handle_messages(std::span<const Message> msgs);  // batched
    QueryResult subscribe(const std::string& sql);  // register a query
    void unsubscribe(SubscriptionId id);             // remove a subscription
    void reset();                                    // return to Init; preserves subscriptions
    Seq current_seq() const;
    SchemaVersion schema_version() const;
    State state() const;  // Init, Handshake, DiffBuckets, DiffRows, Live, Error
};
```

### Peer (bidirectional)

```cpp
struct PeerConfig {
    std::set<std::string> owned_tables;       // tables this side masters
    ApproveOwnershipCallback approve_ownership; // non-null = server side
    ConflictCallback on_conflict = nullptr;
    ProgressCallback on_progress = nullptr;
    SchemaMismatchCallback on_schema_mismatch = nullptr;
};

struct PeerHandleResult {
    std::vector<PeerMessage>  messages;  // responses to send back
    std::vector<ChangeEvent>  changes;   // row-level changes applied
};

class Peer {
public:
    explicit Peer(sqlite3* db, PeerConfig config = {});
    std::vector<PeerMessage> start();   // client initiates handshake
    std::vector<PeerMessage> flush();   // after writing owned tables
    PeerHandleResult handle_message(const PeerMessage& msg);
    State state() const;  // Init, Negotiating, Diffing, Live, Error
    const std::set<std::string>& owned_tables() const;
    const std::set<std::string>& remote_tables() const;
    void reset();  // return to Init for reconnection; preserves table ownership
};
```

Each peer internally wraps a Master (for its owned tables) and a Replica (for
the remote peer's tables). The client calls `start()` to request ownership; the
server validates via `approve_ownership` (or auto-approves if null). The server
owns the complement of whatever the client claims.

```cpp
// Client (e.g. mobile app) owns "drafts", server owns the rest.
PeerConfig client_cfg;
client_cfg.owned_tables = {"drafts"};
Peer client(client_db, client_cfg);

PeerConfig server_cfg;
server_cfg.approve_ownership = [](const std::set<std::string>& t) {
    return t == std::set<std::string>{"drafts"};
};
Peer server(server_db, server_cfg);

auto msgs = client.start();
// Exchange msgs between client and server until both reach Live.
// Then: client.flush() after writes to "drafts",
//       server.flush() after writes to other tables.
```

### Query subscriptions

Register SQL queries on the replica to receive updated results whenever incoming
changes affect a table the query reads from:

```cpp
// Subscribe to a query — returns the current result immediately.
auto qr = replica.subscribe("SELECT id, val FROM t1 ORDER BY id");
// qr.id       — subscription handle
// qr.columns  — {"id", "val"}
// qr.rows     — current result set (vector of vector<Value>)

// After applying a changeset that touches t1:
auto result = replica.handle_message(changeset_msg);
for (const auto& sub : result.subscriptions) {
    // sub.id   — which subscription was invalidated
    // sub.rows — the full updated result set
}

// Stop receiving updates.
replica.unsubscribe(qr.id);
```

Table dependencies are discovered automatically via SQLite's authorizer API.
Queries involving JOINs across multiple tables will fire when any of those
tables change. Invalidation is table-level: any row change to a relevant table
triggers re-evaluation of the full query.

## Error handling

All operations may throw `sqlpipe::Error`, which carries an `ErrorCode` and a
human-readable message:

```cpp
try {
    auto msgs = master.flush();
} catch (const sqlpipe::Error& e) {
    // e.code()  — ErrorCode enum
    // e.what()  — descriptive string
}
```

Error codes: `SqliteError`, `ProtocolError`, `SchemaMismatch`, `InvalidState`,
`OwnershipRejected`, `WithoutRowidTable`. See `sqlpipe.h` for details.

The replica also returns `ErrorMsg` messages when it receives unexpected
protocol messages — these should be forwarded to the master over the transport.

## Schema migration

By default, a schema mismatch between master and replica is a hard error. You
can install a callback to run migrations instead:

```cpp
MasterConfig mc;
mc.on_schema_mismatch = [&](SchemaVersion remote, SchemaVersion local) {
    // ALTER the master's DB to match the replica, then return true to retry.
    sqlite3_exec(master_db, "ALTER TABLE t ADD COLUMN new_col TEXT", 0, 0, 0);
    return true;  // recompute fingerprint and retry
};
Master master(master_db, mc);

ReplicaConfig rc;
rc.on_schema_mismatch = [&](SchemaVersion remote, SchemaVersion local) {
    // ALTER the replica's DB to match the master, then return true.
    // The replica will reset to Init — call hello() again to re-handshake.
    sqlite3_exec(replica_db, "ALTER TABLE t ADD COLUMN new_col TEXT", 0, 0, 0);
    return true;
};
Replica replica(replica_db, rc);
```

The same callback is available on `PeerConfig` and is forwarded to both the
internal Master and Replica.

## Batched message handling

When processing a burst of messages, use `handle_messages()` to defer
subscription re-evaluation until all messages are applied:

```cpp
std::vector<Message> burst = /* received from network */;
auto result = replica.handle_messages(burst);
// Subscriptions are evaluated once, not per-message.
```

## Thread safety

`Master`, `Replica`, and `Peer` are **not thread-safe**. Each instance must be
accessed from a single thread at a time. If you need multi-threaded access,
provide your own synchronisation (e.g. a mutex around all calls to the
instance). The `sqlite3*` handle must not be used concurrently by other threads
during sqlpipe operations.

## WAL mode

SQLite WAL mode is recommended but not required. WAL allows concurrent readers
while the replica applies changes, which is useful if your application reads the
database on a separate thread. Enable it before creating any sqlpipe objects:

```cpp
sqlite3_exec(db, "PRAGMA journal_mode=WAL", 0, 0, 0);
```

## Transport wiring

sqlpipe is transport-agnostic. The wire format is already length-prefixed, so
integrating with any byte-stream transport (TCP, WebSocket, serial, etc.) is
straightforward:

**Sending:**
```cpp
auto buf = sqlpipe::serialize(msg);      // or serialize(peer_msg)
send(socket, buf.data(), buf.size());    // your transport
```

**Receiving:**
```cpp
// 1. Read the 4-byte little-endian length prefix.
uint8_t hdr[4];
recv(socket, hdr, 4);
uint32_t len = hdr[0] | (hdr[1]<<8) | (hdr[2]<<16) | (hdr[3]<<24);

// 2. Read the full message (length prefix + payload).
std::vector<uint8_t> buf(4 + len);
memcpy(buf.data(), hdr, 4);
recv(socket, buf.data() + 4, len);

// 3. Deserialize.
auto msg = sqlpipe::deserialize(buf);    // or deserialize_peer(buf)
```

## Reconnection

Both `Replica` and `Peer` support reconnection without recreating the object:

```cpp
// Replica reconnection:
replica.reset();           // back to Init; subscriptions are preserved
auto hello = replica.hello();
// ... re-run the handshake exchange ...
// Diff sync will discover and transfer only what changed.

// Peer reconnection:
peer.reset();              // back to Init; table ownership is preserved
auto msgs = peer.start();  // re-initiate handshake
// ... exchange messages until Live ...
```

## Error recovery

| ErrorCode | Meaning | Recommended action |
|---|---|---|
| `SqliteError` | An underlying SQLite call failed | Check the message for details; may indicate corruption or a constraint violation |
| `ProtocolError` | Malformed or unexpected message | Disconnect and reconnect; the peer may be buggy or malicious |
| `SchemaMismatch` | Master and replica schemas differ | Install an `on_schema_mismatch` callback, or migrate offline and reconnect |
| `InvalidState` | Operation not valid in the current state | Bug in the calling code; check the state machine |
| `OwnershipRejected` | Peer ownership request was rejected | The server's `approve_ownership` callback returned false |
| `WithoutRowidTable` | Table uses `WITHOUT ROWID` | Not supported; use regular rowid tables |

## Message size limits

Incoming messages are validated against built-in limits to resist malicious
peers:

- **`kMaxMessageSize`** (64 MB) — maximum serialized message size
- **`kMaxArrayCount`** (10 M) — maximum number of elements in any array field

Messages exceeding these limits cause `deserialize()` to throw
`ProtocolError`. The limits are defined as `inline constexpr` in `sqlpipe.h`.

## License

Apache 2.0. See [LICENSE](LICENSE) for details.

Third-party dependencies:
- **SQLite** - public domain
- **LZ4** - BSD 2-Clause
- **spdlog** - MIT
- **doctest** - MIT
