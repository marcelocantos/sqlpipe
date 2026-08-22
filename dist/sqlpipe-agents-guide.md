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

Requires SQLite 3 on the include path. All tables must have a single
`INTEGER PRIMARY KEY` (a rowid alias). Composite primary keys, non-`INTEGER`
primary keys (e.g. `TEXT`), and `WITHOUT ROWID` tables are not supported and are
rejected at `Master`/`Replica` construction with `WithoutRowidTable`.

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
auto msgs = master.flush();                  // vector<OutMessage> after each write txn
auto resp = master.handle_message(incoming); // vector<OutMessage>; incoming is Message
master.current_seq();                        // current sequence number
master.schema_version();                     // schema fingerprint
```

`OutMessage` is `{Message msg; Delivery delivery;}`. `serialize` and
`handle_message` take `msg`. Do not pass `vector<OutMessage>` where
`vector<Message>` is required.

`MasterConfig`:
- `table_filter` — `optional<set<string>>`. `nullopt` = all tables, empty = none.
- `bucket_size` — rows per bucket for diff protocol (default 1024).

### Replica (receiving side)

```cpp
Replica replica(db, config);                   // does NOT own db
auto hello = replica.hello();                  // OutMessage; send hello.msg to master
HandleResult r = replica.handle_message(incoming);
// r.messages      — vector<OutMessage> protocol responses
// r.changes       — per-row ChangeEvents applied this call
// r.subscriptions — invalidated query subscription results
replica.current_seq();
replica.schema_version();
replica.state();  // Init → Handshake → DiffBuckets → DiffRows → Live (or Error)

// Preferred reconnect: converge() — no HelloMsg required
auto buckets = replica.converge();             // vector<OutMessage> (BucketHashesMsg)

// Query subscriptions: subscribe returns an id, not a result set.
auto id = replica.subscribe("SELECT * FROM t1 ORDER BY id");
// Results arrive later on HandleResult::subscriptions (not at subscribe()).
replica.unsubscribe(id);
replica.reset();              // return to Init; subscriptions preserved
// (also rolls back any prediction and drops any queued inbound messages)
```

`ReplicaConfig`:
- `on_conflict` — `ConflictAction(ConflictType, const ChangeEvent&)`. Default:
  Abort.
- `table_filter` — `optional<set<string>>`. `nullopt` = all tables, empty = none.
- `bucket_size` — rows per bucket for diff protocol (default 1024).
- `queue_while_predicting` — `bool`, default `false`. See **Optimistic
  prediction** below.

### Optimistic prediction (low-latency UI over server-owned truth)

sqlpipe is dual uni-directional ownership: a client cannot master tables the
server owns. Painting the UI from a subscription over server-owned tables
therefore waits a full round trip unless you use **prediction** — a local
SAVEPOINT sandbox on the **Replica** so subscriptions can show anticipated
truth immediately. Server apply always wins when it lands.

**When to use.** Interactive latency where the user must see local effect
before the network returns (freehand drawing, dragging, typing into a
server-owned row). Not for durable multi-writer, offline queues, or
long-lived “pending” workflows — provisionality is a **session lifecycle**,
not a data lifetime. Prefer prediction over app-level “tentative” columns:
open-ended tentatives leave GC/identity holes; prediction closes the loop.

**Lifecycle**

```
begin_prediction()     → Drafting  (SAVEPOINT open; write optimistically)
  local writes...
commit_prediction()    → Committed (done editing; still sandboxed)
end_prediction()       → None      (rollback savepoint; apply any queue)
// or rollback_prediction()  — same drain; discards HandleResult
// or reset()                — drop queue without applying (reconnect)
```

- Only **one** prediction active at a time (`InvalidState` on double begin).
- One prediction may contain many row writes (one gesture, many points).
- Slot stays taken through **Committed** until end / auto-clear / reset —
  sequentialize short gestures; do not expect concurrent independent
  predictions.

**Two modes of inbound truth**

| `queue_while_predicting` | Behaviour |
|---|---|
| `false` (default) | Next `handle_message` **auto-rollbacks** a Committed prediction, then applies. Simple; unrelated truth can end the sandbox early (flicker). |
| `true` | Inbound messages during Drafting **or** Committed are **queued**. Sandbox stays until `end_prediction()` / `rollback_prediction()`, which roll back then apply the queue in order. You **must** end the prediction or truth freezes and the queue grows. |

```cpp
ReplicaConfig cfg;
cfg.queue_while_predicting = true;   // preserve paint for short gestures
Replica truth(truth_db, cfg);

truth.begin_prediction();
// write anticipated rows into server-owned tables on truth_db
truth.commit_prediction();
// keep calling handle_message — messages queue; local paint stays
auto hr = truth.end_prediction();    // e.g. on pen-up
// forward hr.messages (acks) to the master
```

**Intent vs paint (critical).** Prediction only affects the **local replica
of server-owned tables**. It does not ship intent upstream. Always:

1. Write **intent** on client-owned tables (Master / Peer flush path).
2. Optionally **predict** truth-shaped rows on the replica for instant UI.
3. Server applies intent → authoritative truth replicates → prediction ends
   and truth supersedes the guess.

If guess ≠ server truth, the UI may briefly correct on end/apply — that is
correct, not a bug.

**Recommended topology: two databases / two pipes**

Prefer separate SQLite handles for the two directions when using prediction
seriously:

| DB | Role | Prediction? |
|---|---|---|
| Intent | Client → server (`Master` only) | No |
| Truth | Server → client (`Replica` only) | Yes (`queue_while_predicting` as needed) |

Benefits: savepoint cannot roll back client-owned rows; intent-pipe traffic
cannot tear down a truth prediction; lower SQLite writer contention between
directions. Cost: no cross-DB SQL joins (join in the app).

Avoid one shared `sqlite3*` for Master+Replica while a prediction is open
unless you are sure **no** owned-table writes land inside the savepoint
window (including after `commit_prediction` — the savepoint stays open until
end/auto-clear). Writes inside the window are undone with the prediction.

**Keep predictions short-lived.** After queue + dual DB, the remaining cost
of a long hold is **truth lag** (collaborative updates and your own confirm
wait until `end_prediction`) plus queue growth and a drain burst. Fine for
sub-second gestures; treat multi-second holds as an explicit “draft frozen”
mode, not the default. Short life also reduces how often the single-flight
sandbox collides with the next gesture.

**Do / don’t**

| Do | Don’t |
|---|---|
| Predict only on truth-shaped, server-owned tables | Treat prediction as multi-writer ownership |
| End on gesture complete (pen-up); drain acks | Leave queue mode open indefinitely |
| Sequentialize gestures (or batch into one envelope) | Expect two concurrent predictions |
| Send intent on the Master path separately | Put intent rows inside the prediction savepoint on a shared DB |
| Use subscriptions for paint (`subscribe` on truth) | Rely on durable “tentative” columns for closed-loop UX |
| Call `end_prediction()` when `queue_while_predicting` | Assume `handle_message` will clear the sandbox in queue mode |

**API surface (Replica)**

```cpp
void begin_prediction();
void commit_prediction();
HandleResult end_prediction();       // rollback + apply queue; prefer this
void rollback_prediction();          // same drain; result discarded
std::size_t prediction_queue_size() const;
bool queues_while_predicting() const;
```

Tests: `tests/test_prediction_queue.cpp` (ordering, Drafting vs Committed,
batch `handle_messages`, subscriptions on drain, reset drops queue, seq
continuity).

### Peer (bidirectional)

```cpp
PeerConfig cfg;
cfg.owned_tables = {"*"};            // glob: own all user tables
cfg.owned_tables = {"draft*"};       // glob: own tables starting with "draft"
cfg.owned_tables = {"drafts"};       // exact match (still works)
Peer client(db, cfg);                // does NOT own db

auto msgs = client.start();              // vector<PeerOutMessage> (client only)
PeerHandleResult r = client.handle_message(incoming);
// r.messages — vector<PeerOutMessage> to send back
// r.changes  — per-row ChangeEvents applied
auto fmsgs = client.flush();             // vector<PeerOutMessage> after writing owned tables
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
// Preferred: converge() — no prior HelloMsg. Every message is regenerable.
auto buckets = replica.converge();
auto resp = master.handle_message(buckets[0].msg);
// Exchange .msg until replica.state() == Live:
// replica → BucketHashesMsg → master → NeedBucketsMsg
// replica → RowHashesMsg → master → DiffReadyMsg → replica → AckMsg

// Legacy ordered-channel handshake: replica.hello() then the same
// exchange starting with HelloMsg. sync_handshake(master, replica)
// drives either path in-process (tests).

// Live streaming
sqlite3_exec(db, "INSERT ...", ...);
auto msgs = master.flush();            // vector<OutMessage>
for (auto& om : msgs) {
    auto result = replica.handle_message(om.msg);
    // result.messages → send .msg back to master
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
auto msgs = client.start();               // vector<PeerOutMessage>
// ... deliver msgs[i].msg to server, deliver responses, repeat ...

// Live — each side flushes its owned tables
sqlite3_exec(client_db, "INSERT INTO drafts ...", ...);
auto peer_msgs = client.flush();          // vector<PeerOutMessage>
for (auto& om : peer_msgs) {
    auto r = server.handle_message(om.msg);
    // r.messages → send .msg back    r.changes → row events
}
```

### Key types

- `OutMessage` — `.msg` (`Message`) + `.delivery` (`Reliable` / `BestEffort`)
- `HandleResult` — `.messages` (`vector<OutMessage>`), `.changes` (row events),
  `.subscriptions` (invalidated query results)
- `QueryResult` — `.id` (SubscriptionId), `.columns`, `.rows`
- `Message` — variant of: `HelloMsg`, `ChangesetMsg`, `AckMsg`, `ErrorMsg`,
  `BucketHashesMsg`, `NeedBucketsMsg`, `RowHashesMsg`, `DiffReadyMsg`
- `ChangeEvent` — `.table`, `.op` (Insert/Update/Delete), `.pk_flags`,
  `.old_values`, `.new_values`
- `Value` — variant: `monostate` (NULL), `int64_t`, `double`, `string`,
  `vector<uint8_t>` (BLOB)
- `PeerMessage` — `.sender_role` (`AsMaster`/`AsReplica`), `.payload` (Message)
- `PeerOutMessage` — `.msg` (`PeerMessage`) + `.delivery`
- `PeerHandleResult` — `.messages` (`vector<PeerOutMessage>`), `.changes` (row events)
- `Relay` — C++-only chain node (`hello` / `handle_upstream` /
  `handle_downstream` return `OutMessage`). No C ABI.
- `serialize(msg)` / `deserialize(buf)` — wire format:
  `[4B LE length][1B tag][payload]`. Changeset blobs within payloads use
  compression framing: `[u32 len][u8 type][data]` where type `0x00` =
  uncompressed, `0x01` = LZ4. Blobs < 64 bytes are stored uncompressed.
- `serialize(PeerMessage)` / `deserialize_peer(buf)` — wire format:
  `[4B LE length][1B role][1B tag][payload]`

### Error codes

`SqliteError`, `ProtocolError`, `SchemaMismatch`, `InvalidState`,
`OwnershipRejected`, `WithoutRowidTable`.

### Go wrapper (`go/sqlpipe`)

```
go get github.com/marcelocantos/sqlpipe/go/sqlpipe@v0.31.0
```

Self-contained CGo module (vendored SQLite with session/preupdate + FTS5).
`Database` mirrors the C++ surface:

```go
db, err := sqlpipe.OpenDatabase(":memory:",
    "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT)")
// optional second arg: sqlift schema migration on open
_ = db.Migrate("CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT, qty INTEGER)")
_ = db.Exec("INSERT INTO items VALUES (1, 'Widget', 10)")
// sqldeep syntax is transpiled on Exec/Query/Rows when extended markers
// are present (e.g. SELECT {id, name}). Plain DDL is left alone so FTS5
// CREATE VIRTUAL TABLE … works.
qr, _ := db.Query("SELECT {id, name} FROM items")
_ = db.Exec("CREATE VIRTUAL TABLE docs USING fts5(content)")
```

Also: `Master` / `Replica` / `Peer` with the same wire protocol as C++.
Use `go/sqlpipe/vX.Y.0` path-prefixed tags (created alongside root tags).
Go encodes HandleResult with a delivery byte; Wasm/TS does **not**, and
Wasm has no prediction API (reduced surface). Swift `TruthReplica` wraps
the C-API prediction symbols; CI is `swift build` only.

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
  forward to the master. After `end_prediction()` drain, forward **all**
  acks in the returned `HandleResult` as well.
- Replica may return `ErrorMsg` in `result.messages` — forward to the master.
- Row-level changes are in `result.changes`, not a callback.
- Subscriptions use table-level invalidation: any change to a table a query
  reads from triggers re-evaluation. JOIN queries fire on either table.
- Diff sync happens automatically during handshake: bucket hash exchange
  discovers differences, then only the delta is transferred.
- Schema mismatch is an error (not auto-resolved). Migrate schemas before
  connecting, or use `Database` which handles migration automatically.
- Prediction is Replica-only (not on Master). With `queue_while_predicting`,
  you own the hold: end the prediction or truth stays frozen.
- One prediction at a time; `reset()` drops any queued inbound messages
  without applying them (reconnect/diff will resync).
