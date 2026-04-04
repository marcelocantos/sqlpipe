# sqlpipe — Agent Reference

Streaming SQLite replication with bundled query transpilation (sqldeep) and
schema migration (sqlift). Two files: `sqlpipe.h` (header) + `sqlpipe.cpp`
(implementation). C++23. Apache 2.0.

## Integration

Add `sqlpipe.h` and `sqlpipe.cpp` to your project. The `dist/` bundle includes
sqldeep and sqlift — no separate installs needed. Compile with:

```
-std=c++23 -DSQLITE_ENABLE_SESSION -DSQLITE_ENABLE_PREUPDATE_HOOK
```

Requires SQLite 3 on the include path. All tables must have explicit `PRIMARY
KEY`s. `WITHOUT ROWID` tables are not supported.

## API

Everything is in `namespace sqlpipe`. All operations may throw
`sqlpipe::Error` (has `.code()` returning `ErrorCode` and `.what()`).

### Database (unified API)

`Database` is the primary entry point for most users. It owns the `sqlite3*`
handle, auto-migrates schema via sqlift, and auto-transpiles sqldeep syntax
in all SQL methods.

```cpp
// Open with schema — creates or migrates existing schema via sqlift.
Database db(":memory:", "CREATE TABLE t (id INTEGER PRIMARY KEY, val TEXT)");

// exec/query auto-transpile sqldeep syntax.
db.exec("INSERT INTO t VALUES (1, 'hello')");
auto r = db.query("SELECT {id, val} FROM t");  // sqldeep → json_object(...)
// r.id=0, r.columns, r.rows

// Subscribe — fires callback on data change. RAII: auto-unsubscribes on destruction.
auto sub = db.subscribe("SELECT count(*) FROM t", [](const QueryResult& r) {
    // r.rows[0][0] is the count
});
db.exec("INSERT INTO t VALUES (2, 'world')");  // callback fires

// For replication: expose the sqlite3* handle (Database retains ownership).
Master master(db.handle());
// After replication applies changes, fire Database subscriptions manually:
db.notify();           // scan all tracked tables
db.notify({"t"});      // specific tables only

// Schema migration plan (static utility).
auto plan = Database::migration("", "CREATE TABLE t (id INTEGER PRIMARY KEY)");
```

### Master (sending side)

```cpp
Master master(db);                           // does NOT own db
auto msgs = master.flush();                  // after each write txn
auto resp = master.handle_message(incoming); // process replica msgs
master.current_seq();                        // current sequence number
master.schema_version();                     // schema fingerprint
```

`MasterConfig`:
- `table_filter` — `optional<set<string>>`. `nullopt` = all tables, empty = none.
- `bucket_size` — rows per bucket for diff protocol (default 1024).

### Replica (receiving side)

```cpp
Replica replica(db, config);                   // does NOT own db
auto hello = replica.hello();                  // send to master first
HandleResult r = replica.handle_message(incoming);
// r.messages      — protocol responses to send back
// r.changes       — per-row ChangeEvents applied this call
// r.subscriptions — invalidated query subscription results
replica.current_seq();
replica.schema_version();
replica.state();  // Init → Handshake → DiffBuckets → DiffRows → Live (or Error)

// Query subscriptions (reactive queries)
auto qr = replica.subscribe("SELECT * FROM t1 ORDER BY id");
// qr.id, qr.columns, qr.rows — current result
// After handle_message, check r.subscriptions for updated results
replica.unsubscribe(qr.id);
replica.reset();              // return to Init; subscriptions preserved
```

`ReplicaConfig`:
- `on_conflict` — `ConflictAction(ConflictType, const ChangeEvent&)`. Default:
  Abort.
- `table_filter` — `optional<set<string>>`. `nullopt` = all tables, empty = none.
- `bucket_size` — rows per bucket for diff protocol (default 1024).

### Peer (bidirectional)

```cpp
PeerConfig cfg;
cfg.owned_tables = {"*"};            // glob: own all user tables
cfg.owned_tables = {"draft*"};       // glob: own tables starting with "draft"
cfg.owned_tables = {"drafts"};       // exact match (still works)
Peer client(db, cfg);                // does NOT own db

auto msgs = client.start();              // initiate handshake (client only)
PeerHandleResult r = client.handle_message(incoming);
// r.messages — PeerMessages to send back
// r.changes  — per-row ChangeEvents applied
auto fmsgs = client.flush();             // after writing owned tables
client.state();    // Init → Negotiating → Diffing → Live (or Error)
client.owned_tables();                   // tables we master
client.remote_tables();                  // tables we replicate
client.reset();                          // return to Init for reconnect
```

`PeerConfig`:
- `owned_tables` — tables this side wants to own; supports glob patterns
- `approve_ownership` — server-side callback; non-null marks this peer as
  server. `nullptr` = auto-approve.
- `on_conflict` — forwarded to internal Replica

`PeerMessage` wraps `Message` with `SenderRole` (`AsMaster`/`AsReplica`) for
routing. Wire format: `[4B LE length][1B sender_role][1B tag][payload]`.
`serialize(PeerMessage)` / `deserialize_peer(buf)`.

Server creates Peer without `owned_tables` — it owns whatever the client
doesn't claim. Client calls `start()`; server receives messages via
`handle_message()`.

### sqldeep (bundled query transpiler)

All `Database` methods auto-transpile sqldeep syntax — do not call
`sqldeep_transpile()` manually on SQL that goes through `Database`.

Key features:
- `SELECT {id, name}` → `SELECT json_object('id', id, 'name', name)`
- Works in `exec()`, `query()`, `subscribe()`
- Direct access: `sqldeep_transpile(sql, &err_msg, &err_line, &err_col)`

### sqlift (bundled schema migration)

- `Database` constructor auto-migrates schema on open
- `Database::migration(from_ddl, to_ddl)` — returns JSON migration plan
- `generate_migration(old_ddl, new_ddl)` — same as the static method
- Direct access: `sqlift_parse()`, `sqlift_diff()`, `sqlift_apply()`

### Typical loop (unidirectional)

```cpp
// 1. Handshake (multi-step: hello → bucket hashes → row hashes → diff)
auto hello = replica.hello();
auto resp = master.handle_message(hello);
// Exchange messages until replica.state() == Live:
// master → HelloMsg → replica → BucketHashesMsg → master
// master → NeedBucketsMsg → replica → RowHashesMsg → master
// master → DiffReadyMsg → replica → AckMsg → master

// 2. Live streaming
sqlite3_exec(db, "INSERT ...", ...);
auto msgs = master.flush();            // → send to replica
for (auto& m : msgs) {
    auto result = replica.handle_message(m);
    // result.messages → send back to master
    // result.changes  → business-level row changes
}
```

### Typical loop (bidirectional)

```cpp
// Setup
PeerConfig client_cfg;
client_cfg.owned_tables = {"drafts"};
Peer client(client_db, client_cfg);

PeerConfig server_cfg;
server_cfg.approve_ownership = [](auto& t) { return true; };
Peer server(server_db, server_cfg);

// Handshake — exchange messages until both Live
auto msgs = client.start();
// ... deliver msgs to server, deliver responses to client, repeat ...

// Live — each side flushes its owned tables
sqlite3_exec(client_db, "INSERT INTO drafts ...", ...);
auto peer_msgs = client.flush();          // → send to server
for (auto& m : peer_msgs) {
    auto r = server.handle_message(m);
    // r.messages → send back    r.changes → row events
}
```

### Key types

- `HandleResult` — `.messages` (protocol responses), `.changes` (row events),
  `.subscriptions` (invalidated query results)
- `QueryResult` — `.id` (SubscriptionId), `.columns`, `.rows`
- `Message` — variant of: `HelloMsg`, `ChangesetMsg`, `AckMsg`, `ErrorMsg`,
  `BucketHashesMsg`, `NeedBucketsMsg`, `RowHashesMsg`, `DiffReadyMsg`
- `ChangeEvent` — `.table`, `.op` (Insert/Update/Delete), `.pk_flags`,
  `.old_values`, `.new_values`
- `Value` — variant: `monostate` (NULL), `int64_t`, `double`, `string`,
  `vector<uint8_t>` (BLOB)
- `PeerMessage` — `.sender_role` (`AsMaster`/`AsReplica`), `.payload` (Message)
- `PeerHandleResult` — `.messages` (PeerMessages), `.changes` (row events)
- `serialize(msg)` / `deserialize(buf)` — wire format:
  `[4B LE length][1B tag][payload]`. Changeset blobs within payloads use
  compression framing: `[u32 len][u8 type][data]` where type `0x00` =
  uncompressed, `0x01` = LZ4. Blobs < 64 bytes are stored uncompressed.
- `serialize(PeerMessage)` / `deserialize_peer(buf)` — wire format:
  `[4B LE length][1B role][1B tag][payload]`

### Error codes

`SqliteError`, `ProtocolError`, `SchemaMismatch`, `InvalidState`,
`OwnershipRejected`, `WithoutRowidTable`.

## Gotchas

- `Database` owns the `sqlite3*` handle. `Master`, `Replica`, and `Peer` do
  **not** — they borrow it and must not outlive the owning `Database` (or your
  own `sqlite3*`).
- After replication operations (`handle_message`, `flush`), call `db.notify()`
  (or `db.notify(tables)`) to fire any `Database` subscriptions — replication
  bypasses the normal change-detection path.
- sqldeep transpilation is automatic in all `Database` methods. Do not call
  `sqldeep_transpile()` on SQL that will also pass through `exec()`, `query()`,
  or `subscribe()` — it will be double-transpiled.
- Library is transport-agnostic: `handle_message` in, `HandleResult` out.
  You provide the transport.
- Replica returns `AckMsg` in `result.messages` after each `ChangesetMsg` —
  forward to the master.
- Replica may return `ErrorMsg` in `result.messages` — forward to the master.
- Row-level changes are in `result.changes`, not a callback.
- Subscriptions use table-level invalidation: any change to a table a query
  reads from triggers re-evaluation. JOIN queries fire on either table.
- Diff sync happens automatically during handshake: bucket hash exchange
  discovers differences, then only the delta is transferred.
- Schema mismatch is an error (not auto-resolved). Migrate schemas before
  connecting, or use `Database` which handles migration automatically.
