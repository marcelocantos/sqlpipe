# sqlpipe — Agent Reference

Streaming SQLite replication. Two files: `sqlpipe.h` (header) + `sqlpipe.cpp`
(implementation). C++20. Apache 2.0.

## Integration

Add `sqlpipe.h` and `sqlpipe.cpp` to your project. Compile with:

```
-std=c++20 -DSQLITE_ENABLE_SESSION -DSQLITE_ENABLE_PREUPDATE_HOOK
```

Requires SQLite 3 on the include path. All tables must have explicit `PRIMARY
KEY`s.

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
master.generate_resync();                    // force full resync
```

`MasterConfig{.max_log_entries = 10000}` — changesets kept for catchup (0 =
unlimited).

### Replica (receiving side)

```cpp
Replica replica(db, config);                   // does NOT own db
auto hello = replica.hello();                  // send to master first
HandleResult r = replica.handle_message(incoming);
// r.messages — protocol responses (AckMsg, ErrorMsg) to send back
// r.changes  — per-row ChangeEvents applied this call
replica.current_seq();
replica.schema_version();
replica.state();  // Init → Handshake → Catchup/Resync → Live (or Error)
```

`ReplicaConfig`:
- `on_conflict` — `ConflictAction(ConflictType, const ChangeEvent&)`. Default:
  Abort.

### Typical loop

```cpp
// 1. Handshake
auto hello = replica.hello();          // → send to master
auto resp = master.handle_message(hello);
for (auto& m : resp) {
    auto result = replica.handle_message(m);
    // result.messages → send back to master
}

// 2. Live streaming
sqlite3_exec(db, "INSERT ...", ...);
auto msgs = master.flush();            // → send to replica
for (auto& m : msgs) {
    auto result = replica.handle_message(m);
    // result.messages → send back to master
    // result.changes  → business-level row changes
}
```

### Key types

- `HandleResult` — `.messages` (protocol responses), `.changes` (row events)
- `Message` — variant of: `HelloMsg`, `CatchupBeginMsg`, `ChangesetMsg`,
  `CatchupEndMsg`, `ResyncBeginMsg`, `ResyncTableMsg`, `ResyncEndMsg`,
  `AckMsg`, `ErrorMsg`
- `ChangeEvent` — `.table`, `.op` (Insert/Update/Delete), `.pk_flags`,
  `.old_values`, `.new_values`
- `Value` — variant: `monostate` (NULL), `int64_t`, `double`, `string`,
  `vector<uint8_t>` (BLOB)
- `serialize(msg)` / `deserialize(buf)` — wire format:
  `[4B LE length][1B tag][payload]`

### Error codes

`SqliteError`, `ProtocolError`, `SequenceGap`, `SchemaMismatch`,
`InvalidState`, `ResyncRequired`.

## Gotchas

- Library is transport-agnostic: `handle_message` in, `HandleResult` out.
  You provide the transport.
- Both `Master` and `Replica` do **not** own the `sqlite3*` handle. Keep it
  open for their lifetime.
- Replica returns `AckMsg` in `result.messages` after each `ChangesetMsg` —
  forward to the master.
- Replica may return `ErrorMsg` in `result.messages` — forward to the master.
- Row-level changes are in `result.changes`, not a callback.
- Catchup/resync happen automatically during handshake based on sequence gap
  and schema fingerprint.
