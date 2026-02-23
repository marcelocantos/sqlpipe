# sqlpipe — Agent Reference

Streaming SQLite replication. Two files: `sqlpipe.h` (header) + `sqlpipe.cpp`
(implementation). C++20. Apache 2.0.

## Integration

Add `sqlpipe.h` and `sqlpipe.cpp` to your project. Compile with:

```
-std=c++20 -DSQLITE_ENABLE_SESSION -DSQLITE_ENABLE_PREUPDATE_HOOK
```

Requires SQLite 3 on the include path. All tables must have explicit `PRIMARY
KEY`s. `WITHOUT ROWID` tables are not supported.

## API

Everything is in `namespace sqlpipe`. All operations may throw
`sqlpipe::Error` (has `.code()` returning `ErrorCode` and `.what()`).

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
// r.messages — protocol responses to send back
// r.changes  — per-row ChangeEvents applied this call
replica.current_seq();
replica.schema_version();
replica.state();  // Init → Handshake → DiffBuckets → DiffRows → Live (or Error)
```

`ReplicaConfig`:
- `on_conflict` — `ConflictAction(ConflictType, const ChangeEvent&)`. Default:
  Abort.
- `table_filter` — `optional<set<string>>`. `nullopt` = all tables, empty = none.
- `bucket_size` — rows per bucket for diff protocol (default 1024).

### Peer (bidirectional)

```cpp
PeerConfig cfg;
cfg.owned_tables = {"drafts"};           // tables this side masters
Peer client(db, cfg);                    // does NOT own db

auto msgs = client.start();              // initiate handshake (client only)
PeerHandleResult r = client.handle_message(incoming);
// r.messages — PeerMessages to send back
// r.changes  — per-row ChangeEvents applied
auto fmsgs = client.flush();             // after writing owned tables
client.state();    // Init → Negotiating → Diffing → Live (or Error)
client.owned_tables();                   // tables we master
client.remote_tables();                  // tables we replicate
```

`PeerConfig`:
- `owned_tables` — tables this side wants to own (client sends in hello)
- `approve_ownership` — server-side callback; non-null marks this peer as
  server. `nullptr` = auto-approve.
- `on_conflict` — forwarded to internal Replica

`PeerMessage` wraps `Message` with `SenderRole` (`AsMaster`/`AsReplica`) for
routing. Wire format: `[4B LE length][1B sender_role][1B tag][payload]`.
`serialize(PeerMessage)` / `deserialize_peer(buf)`.

Server creates Peer without `owned_tables` — it owns whatever the client
doesn't claim. Client calls `start()`; server receives messages via
`handle_message()`.

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

- `HandleResult` — `.messages` (protocol responses), `.changes` (row events)
- `Message` — variant of: `HelloMsg`, `ChangesetMsg`, `AckMsg`, `ErrorMsg`,
  `BucketHashesMsg`, `NeedBucketsMsg`, `RowHashesMsg`, `DiffReadyMsg`
- `ChangeEvent` — `.table`, `.op` (Insert/Update/Delete), `.pk_flags`,
  `.old_values`, `.new_values`
- `Value` — variant: `monostate` (NULL), `int64_t`, `double`, `string`,
  `vector<uint8_t>` (BLOB)
- `PeerMessage` — `.sender_role` (`AsMaster`/`AsReplica`), `.payload` (Message)
- `PeerHandleResult` — `.messages` (PeerMessages), `.changes` (row events)
- `serialize(msg)` / `deserialize(buf)` — wire format:
  `[4B LE length][1B tag][payload]`
- `serialize(PeerMessage)` / `deserialize_peer(buf)` — wire format:
  `[4B LE length][1B role][1B tag][payload]`

### Error codes

`SqliteError`, `ProtocolError`, `SchemaMismatch`, `InvalidState`,
`OwnershipRejected`, `WithoutRowidTable`.

## Gotchas

- Library is transport-agnostic: `handle_message` in, `HandleResult` out.
  You provide the transport.
- Both `Master` and `Replica` do **not** own the `sqlite3*` handle. Keep it
  open for their lifetime.
- Replica returns `AckMsg` in `result.messages` after each `ChangesetMsg` —
  forward to the master.
- Replica may return `ErrorMsg` in `result.messages` — forward to the master.
- Row-level changes are in `result.changes`, not a callback.
- Diff sync happens automatically during handshake: bucket hash exchange
  discovers differences, then only the delta is transferred.
- Schema mismatch is an error (not auto-resolved). Migrate schemas before
  connecting.
