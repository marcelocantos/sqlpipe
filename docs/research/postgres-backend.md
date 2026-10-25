# Postgres backend support

**Status:** design (not a commitment to implement)  
**Captured:** 2026-09-07  
**Related:** 🎯T34 (umbrella — set this as the goal), 🎯T26 (structural schema),
🎯T27 / `edge-projection-multiplayer.md` (parameterized SQLite slice — **out of
scope here**), 🎯T28 (parked hub/slice; now depends on T34), sqldeep 🎯T18,
sqlift 🎯T3. sqldeep `SQLDEEP_POSTGRES` is transpile-only until T18.

---

## 1. Decisions already taken

These are product constraints, not open questions.

1. **Intra-engine only.** A Postgres master talks to a Postgres replica. A
   SQLite master talks to a SQLite replica. There is no requirement that either
   side can apply the other's vendor payload.
2. **Shared conversation, split vendor.** Envelope, message *kinds*, seq,
   handshake/diff/live state machine, and the C++ API shape are shared.
   Changeset bytes, row identity, value hashing, capture, and apply are
   per-engine.
3. **Parameterized SQLite slice of a Postgres universe** (`U_P = slice(U, params)`)
   is a later product. It is not a dialect flag and must not drive this design.
   See §16.
4. **sqlift and sqldeep are in scope.** “Postgres support” means a working
   stack: transpile + execute, extract/diff/apply, then replicate.

---

## 2. Goals and non-goals

### Goals

- `Database` / `Master` / `Replica` / `Peer` / `QueryWatch` work against
  Postgres with the same caller-facing loop they have against SQLite.
- sqldeep `SQLDEEP_POSTGRES` is a **runtime** for the JSON / join-path /
  `RECURSE` surface, with a live execution oracle.
- sqlift can parse (against a live server), extract, diff, and apply a
  declarative want-state on Postgres.
- Schema identity stays structural (sqlift IR hash in `SchemaVersion`).
- A SQLite peer and a Postgres peer that accidentally meet fail at Hello
  with `ErrorCode::ProtocolError`, not inside an opaque apply.

### Non-goals (this design)

- SQLite ↔ Postgres row sync, type mapping, or dual-emit fingerprints.
- Porting `Master` to “pretend `PGconn*` is `sqlite3*`.”
- Logical-decoding-as-the-only-capture (v1 uses a transactional outbox; §9).
- UUID / composite / text primary keys (v1 is a single `BIGINT` PK).
- Postgres schemas other than a configured search-path schema (v1: `public`).
- XML / JSONML / JSX runtime on Postgres (sqldeep keeps those SQLite-only).
- Wasm / Emscripten Postgres (no libpq in the browser module).
- Electric / PowerSync parity, edge projection, multiplayer scopes (🎯T27).
- Raw DDL-down-the-pipe (🎯T26 still holds inside each engine).

---

## 3. Architecture

```text
                    ┌─ protocol (shared) ─────────────────────────┐
                    │ envelope, tags, Hello/Ack/Error, seq,       │
                    │ Replica::State, Peer roles, Delivery        │
                    └───────────────────┬─────────────────────────┘
                                        │
              ┌─────────────────────────┴─────────────────────────┐
              │                                                   │
     sqlite/ (today)                                    postgres/ (new)
     session + changeset_apply                          outbox + DML apply
     rowid buckets                                      bigint-PK buckets
     SQLite value tags                                  PG value tags
     authorizer subscribe                               AST table-deps
              │                                                   │
              └─────────────┬─────────────────┬───────────────────┘
                            │                 │
                     sqlift IR + diff   sqldeep Transformer
                     extract/apply ×2   emit ×2 + PG runtime
```

Callers keep constructing `Master` / `Replica` on a borrowed connection and
driving `hello` / `handle_message` / `flush`. The pimpl dispatches to an
`Engine` vtable. Public headers stay dependency-light: `typedef struct pg_conn
PGconn` next to the existing `typedef struct sqlite3 sqlite3` — do not
`#include <libpq-fe.h>` from `sqlpipe.h`.

```cpp
enum class Engine : std::uint8_t { Sqlite = 0, Postgres = 1 };

explicit Master(sqlite3* db, MasterConfig = {});   // unchanged
explicit Master(PGconn*  conn, MasterConfig = {}); // new
// same pair for Replica, Peer, QueryWatch, Database
```

Wasm builds omit the `PGconn*` overloads (`#ifndef EMSCRIPTEN`).

---

## 4. Shared framing

Unchanged envelope:

```text
unidirectional: [4B LE length][1B tag][payload…]
peer:           [4B LE length][1B sender_role][1B tag][payload…]
```

`MessageTag` values stay (`Hello=0x01`, `Changeset=0x03`, … `DiffReady=0x0D`).
`SenderRole`, `Delivery`, `Replica::State`, and the Hello → optional diff dance
→ live Changeset/Ack loop stay.

SQLite keeps `kProtocolVersion = 7` and its current payload layouts (stable).

Postgres uses a **new protocol version**, not a compatible extension of v7:

```cpp
inline constexpr std::uint32_t kProtocolVersion         = 7; // SQLite
inline constexpr std::uint32_t kPostgresProtocolVersion = 8;
```

Existing SQLite `handle_hello` already rejects `protocol_version != 7` with
`ErrorCode::ProtocolError`. A Postgres Hello is therefore refused by any
current SQLite peer without parsing vendor bytes.

Postgres Hello payload (v8):

```text
u32  protocol_version = 8
u8   engine           = Engine::Postgres   // 1
fingerprint          schema_version         // [algo_id][digest…]
u32  n_owned + strings
i64  last_seq
```

`BucketHashesMsg` on the Postgres lane carries `protocol_version = 8` the same
way v7 already carries version for `converge()`-without-Hello. Engine mismatch
or version ≠ 8 → `ProtocolError`.

`AckMsg` / `ErrorMsg` / `NeedBucketsMsg` field layouts can be identical to v7.
`ChangesetMsg.data` and `DiffReadyMsg.patchset` use the same **outer**
compression frame already on the wire:

```text
[u32 nbytes][u8 type][data…]
  type 0x00 = uncompressed
  type 0x01 = LZ4 (then u32 original_len + body)
```

The bytes *inside* that frame are a Postgres DML patch (§8), not a SQLite
session blob. `kMaxMessageSize` (64 MiB) and the LZ4 length check stay.

C++ `Message` / `HelloMsg` / `BucketHashEntry` types can be reused. On the
Postgres path, `RowHashRun::start_rowid` and `TableDeletes::rowids` mean
**bigint primary-key values**, not physical tuple IDs. Do not rename the
SQLite-stable fields; document the alias in the Postgres protocol section.
A later cleanup can introduce `using RowKey = std::int64_t`.

### `SchemaVersion`

Still `[algo_id byte][digest…]`, compared as raw bytes.

| Engine | `SchemaFingerprintAlgo` | Input |
|---|---|---|
| SQLite | `SqliftSha256 = 0x01` (today) | sqlift SQLite IR |
| Postgres | `SqliftPgSha256 = 0x02` | sqlift Postgres IR |

Different algo ids make a confused cross-engine compare fail even if someone
strips the Hello version check. No dual-emit: the two IRs are not required to
hash equal for “the same” logical schema.

---

## 5. Identity, types, and hashing (Postgres)

### Primary key (v1)

Every tracked table must have a **single `BIGINT` primary key** (column type
`smallint` / `integer` / `bigint`, including `GENERATED … AS IDENTITY` and
`serial` / `bigserial`). The key is the stable identity used for:

- bucket ranges (`bucket_lo` / `bucket_hi`)
- `RowHashRun` starts
- `DiffReadyMsg` deletes
- outbox `pk` column

Reject at table discovery (new `ErrorCode::UnsupportedTable`, not
`WithoutRowidTable`):

- no PK, composite PK, `UUID` / `TEXT` / other PK types
- `UNLOGGED` is allowed; `TEMPORARY` is rejected (not visible across sessions)
- partitioned parents: reject in v1 (children would split identity)

`ctid` is never an identity. It is valid only as a intra-query tie-break
(sqldeep `RECURSE` already uses it that way).

Bucket math is the current one with PK substituted for rowid: default
`bucket_size = 1024`, XOR of `fnv1a(pk || row_hash)` per row, order-independent.

### Hashable column types (v1)

Row hashes are FNV-1a over type-tagged values. Tags are **Postgres-specific**
and must not match the SQLite tag numbers except by coincidence.

| PG type | Tag | Encoding |
|---|---|---|
| NULL | `0x00` | (none) |
| `int2` / `int4` / `int8` | `0x01` | 8-byte LE i64 (zero-extended / sign-extended) |
| `float4` / `float8` | `0x02` | 8-byte IEEE-754 LE f64 (`float4` promoted) |
| `text` / `varchar` / `bpchar` | `0x03` | u32 LE utf8 length + bytes (`bpchar` stripped of trailing pad) |
| `bytea` | `0x04` | u32 LE length + bytes |
| `bool` | `0x05` | 1 byte `0x00` / `0x01` |
| `date` | `0x06` | i32 LE days since 2000-01-01 (Postgres epoch) |
| `timestamp` / `timestamptz` | `0x07` | i64 LE microseconds since 2000-01-01 |
| `uuid` | `0x08` | 16 bytes RFC-4122 order |
| `json` / `jsonb` | `0x09` | u32 LE + **canonical jsonb** binary (cast `json` → `jsonb` first) |

Anything else (`numeric`, arrays, composites, ranges, `tsvector`, geometric,
`money`, enums, domains over the above until unwrapped) → table rejected at
discovery. `numeric` is omitted on purpose: no unique binary that both sides
will hash the same across `numeric(p,s)` and unconstrained `numeric`.

`Value` in `ChangeEvent` / `QueryResult` stays the existing SQLite-shaped
variant for the first cut (`monostate / i64 / f64 / string / bytes`). Map
`bool` → i64 0/1, temporal → i64, `uuid` / `jsonb` → bytes. A later API can
widen `Value`; that is a C++/wrapper change, not a wire change.

---

## 6. sqldeep — Postgres as a runtime

### Today

`SQLDEEP_POSTGRES` emits `jsonb_build_object` / `jsonb_build_array` /
`jsonb_agg` / `jsonb_extract_path`, and `RECURSE` already branches on
`lpad` / `ctid` / `string_agg` / `pg_typeof`. Coverage is
`expected_postgres` string goldens. Hygiene `correctness.postgres-live` is
planned. 🎯T11 documented this as transpile-only so 1.0 would not lie.

### v1 runtime

- CI job: Postgres service (15+), run a new `testdata/postgres.yaml` (or a
  `backend:` field on shared cases) by transpiling with `SQLDEEP_POSTGRES` and
  executing via libpq.
- JSON objects / arrays / nested subqueries / `SELECT/1` / join paths /
  FK-guided joins / JSON path / `RECURSE` must match SQLite JSON **modulo
  jsonb key order and whitespace**.
- No `sqldeep_register_postgres` for JSON — stock `jsonb_*` is the runtime.
- XML / JSONML / JSX: **not** a PG runtime in v1. `sqldeep_transpile_backend`
  may still emit `xml_element` names (current behaviour); executing those
  statements is unsupported. Document next to the existing “transpile-only”
  sentence. A later `sqldeep_register_postgres` can map onto `xmlelement` /
  `xmlagg` or a `jsonb` HTML encoding.
- Parser remains deepparser (SQLite Lemon grammar). Passthrough of
  `RETURNING`, `DISTINCT ON`, `::`, arrays, `$$` is not a contract. App SQL
  that uses sqldeep extensions is the supported input; exotic PG SQL is not.
- Bind parameters: named / numbered preferred; bare `?` keeps today’s
  left-to-right rule (Postgres `?` is not standard — drivers often rewrite to
  `$n`. Document that PG callers should use `$1` / `:name`).

### 1.0 settle clock

sqldeep `🎯T1` is blocked on freeze + tag (`T1.4`). Shipping a live PG oracle
**before** freeze resets N=3. Default schedule: **after `v1.0.0`**, as a minor.
If the stack needs the oracle sooner, treat it as a declared freeze exception
in `STABILITY.md`, not a silent catalogue add.

---

## 7. sqlift — second extract/apply compiler

`diff()` stays a pure function on two `Schema` JSON documents. That is the
whole point of the library. Postgres is a new **parse / extract / apply**
triple that produces and consumes the same IR *shape* with a dialect tag.

### IR

Keep `Table` / `Column` / `Index` / `View` / `Trigger`. Add:

```text
Schema.dialect        = "sqlite" | "postgres"
Table.schema          = "public"          // v1: always public (or config)
Column.type           = canonical PG type name (see below)
// sqlite-only fields ignored on postgres: without_rowid, strict, virtual_tables
```

Canonical PG type names (lowercase): `bigint`, `integer`, `smallint`,
`double precision`, `real`, `text`, `varchar`, `bytea`, `boolean`, `date`,
`timestamp without time zone`, `timestamp with time zone`, `uuid`, `jsonb`,
`json`. `serial` / `bigserial` normalize to `integer`/`bigint` plus
`identity` / default-nextval metadata so `serial` vs `GENERATED ALWAYS AS
IDENTITY` can be distinguished when it matters and ignored when it does not.

`raw_sql` remains display-only and **out of equality**, same as SQLite
(`sqlite_master.sql` vs `ALTER TABLE ADD COLUMN`).

Equality must not treat `VARCHAR(255)` and `TEXT` as the same type (they are
not, on Postgres). `json` vs `jsonb` differ.

### parse

SQLite `parse()` today: exec DDL on `:memory:`, then `extract()`. That is the
correct *shape* (the engine validates). Reuse it for Postgres:

```text
parse_postgres(conn, ddl):
  CREATE SCHEMA sqlift_parse_tmp AUTHORIZATION current_user
  SET LOCAL search_path TO sqlift_parse_tmp
  exec(ddl)
  schema = extract(conn, schema="sqlift_parse_tmp")
  DROP SCHEMA sqlift_parse_tmp CASCADE
  return schema
```

Offline PG parse (no server) is **not** v1. `sqlift_parse()` C API stays
SQLite-on-memory. New:

```c
char* sqlift_parse_on(sqlift_db* db, const char* ddl,
                      int* err_type, char** err_msg);
```

`Database(conninfo, schema_ddl)` always has a connection, so open-with-DDL
does not need an offline parser.

### extract

Replace `sqlite_master` + PRAGMAs with `pg_catalog`:

- tables / columns: `pg_class` + `pg_attribute` + `pg_constraint` +
  `pg_attrdef`
- PK / UNIQUE / CHECK / FK: `pg_constraint`
- indexes: `pg_index` (skip constraint-backed indexes, as SQLite skips
  autoindexes)
- views: `pg_get_viewdef`
- triggers: `pg_get_triggerdef`
- exclude `sqlift_parse_tmp`, `sqlpipe` catalog schema (§9), and
  `information_schema`

### apply

Postgres has in-place `ALTER TABLE`. The SQLite 12-step rebuild is the wrong
default. `OpType` gains PG-meaningful variants (JSON names stable; unknown
ops are an error on the other dialect):

| Op | Typical SQL |
|---|---|
| `CreateTable` / `DropTable` | `CREATE` / `DROP TABLE` |
| `AddColumn` | `ALTER TABLE … ADD COLUMN` |
| `DropColumn` | `ALTER TABLE … DROP COLUMN` |
| `AlterColumnType` | `ALTER TABLE … ALTER COLUMN … TYPE` |
| `SetNotNull` / `DropNotNull` | `SET` / `DROP NOT NULL` |
| `SetDefault` / `DropDefault` | `SET` / `DROP DEFAULT` |
| `AddConstraint` / `DropConstraint` | `ADD` / `DROP CONSTRAINT` |
| `CreateIndex` / `DropIndex` | `CREATE` / `DROP INDEX` |
| `CreateView` / `DropView` | `CREATE OR REPLACE` / `DROP VIEW` |
| `CreateTrigger` / `DropTrigger` | `CREATE` / `DROP TRIGGER` |

`RebuildTable` is unused on Postgres v1. `CreateVirtualTable` is SQLite-only.

Policy bits map without new flags:

| Flag | Postgres meaning |
|---|---|
| `ALLOW_REBUILD` | `ALTER COLUMN TYPE` (may rewrite the table) |
| `ALLOW_DESTRUCTIVE` | `DROP TABLE` / `DROP COLUMN` / drop index/view/trigger |
| `ALLOW_LOOSEN` | `DROP NOT NULL`, `DROP CONSTRAINT` |
| `ALLOW_DATA_DEPENDENT` | `SET NOT NULL`, `ADD` FK/CHECK, `ADD COLUMN … NOT NULL` without default |

Apply is one transaction (`BEGIN` … `COMMIT`). Postgres DDL is transactional
on the engines we care about (vanilla PG). Drift detection still writes
`_sqlift_state` (place it in schema `sqlpipe`, §9).

### C API / no `PGconn*` in `sqlift.h`

Do not add `libpq` to the public C header. Wrap with an executor:

```c
typedef struct sqlift_exec {
    void* ctx;
    int (*exec)(void* ctx, const char* sql, char** err_msg);
    /* query: callback per row; columns are text for extract */
    int (*query)(void* ctx, const char* sql,
                 void (*row)(void* row_ctx, int ncols, const char* const* cols),
                 void* row_ctx, char** err_msg);
} sqlift_exec;

sqlift_db* sqlift_db_wrap_sqlite(sqlite3* db);           // today's wrap
sqlift_db* sqlift_db_wrap_exec(int engine, sqlift_exec); // postgres
```

sqlpipe’s bundled copy implements `sqlift_db_wrap_exec` with libpq internally.

`SQLIFT_ALLOW_REBUILD` documentation must say “table rewrite on SQLite;
`ALTER TYPE` on Postgres” so the bit does not imply a 12-step script on PG.

---

## 8. Postgres changeset (vendor payload)

Inner format (after the shared LZ4 frame). Version-tagged so we can evolve
without a new `MessageTag`.

```text
u8  changeset_version = 1
u32 n_ops
for each op:
  u8  op            // 1=insert 2=update 3=delete  (same as sqlpipe::OpType)
  str table         // unqualified, public schema
  i64 pk
  u16 n_old         // 0 for insert
  repeated (str col, u8 type_tag, value)
  u16 n_new         // 0 for delete
  repeated (str col, u8 type_tag, value)
```

Column order is the table’s physical `attnum` order (same as `extract`).
PK is repeated in the row values when the PK column is present; the leading
`i64 pk` is authoritative for apply.

`DiffReadyMsg.patchset` is the same format, insert-or-update only (`op` is
insert; apply uses `INSERT … ON CONFLICT (pk) DO UPDATE`). Deletes stay in
`DiffReadyMsg.deletes` (int64 PKs), same as today.

Do not reuse SQLite session-extension framing. Do not invent a second
compression scheme.

---

## 9. Capture and apply (sqlpipe Postgres)

### v1 capture: transactional outbox

Logical decoding needs `wal_level=logical`, a replication slot, and privileges
many managed hosts restrict. It is the right *scale* tool, not the right
library-v1 tool.

v1 records DML with `AFTER` triggers into an outbox, in the same transaction
as the write. `flush()` assigns `seq`, packs pending rows into a changeset,
and deletes them.

Catalog schema `sqlpipe` (not `public`) so app tables never collide.
After creating it, sqlpipe `SET search_path TO public` on the connection:
Postgres defaults to `"$user", public`, so a role also named `sqlpipe`
would otherwise put unqualified `CREATE TABLE` into the catalog. sqlift
fingerprints `public` only. The hermetic gate uses role `postgres` for
the same reason.

```sql
CREATE SCHEMA IF NOT EXISTS sqlpipe;

CREATE TABLE IF NOT EXISTS sqlpipe.meta (
    key   text PRIMARY KEY,
    value text NOT NULL
);

CREATE TABLE IF NOT EXISTS sqlpipe.outbox (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    table_name text   NOT NULL,
    op         smallint NOT NULL,   -- 1/2/3
    pk         bigint NOT NULL,
    old_row    jsonb,
    new_row    jsonb
);
```

`seq` lives in `sqlpipe.meta` under `MasterConfig::seq_key` /
`ReplicaConfig::seq_key` (`master_seq` / `replica_seq` in Peer mode, same
as today).

Triggers are installed on tracked tables at `Master` construction (and
reinstalled if `on_schema_mismatch` mutates the schema). Each trigger writes
one outbox row with `to_jsonb(OLD)` / `to_jsonb(NEW)` and the PK.

Exclude from tracking / fingerprint / `table_filter` resolution:

- everything in schema `sqlpipe`
- `sqlift`’s state table (`sqlpipe.state` or `sqlpipe.sqlift_state`)

`table_filter` still means “these `public` tables.” Empty set = none;
`nullopt` = all user tables in `public` that pass the PK/type gate.

### flush and auto-flush

Postgres has no `sqlite3_commit_hook`.

- `Master::exec` / `Database::exec`: if `on_flush` is set, `flush()` after a
  successful statement that is not inside an explicit transaction.
- Multi-statement `BEGIN … COMMIT` issued *outside* `exec` (caller using
  the raw `PGconn*`): caller must `flush()` after commit. Document this.
- `changeset_queue_size` replay on reconnect works the same: retain packed
  changesets keyed by seq.

Do not use `LISTEN/NOTIFY` as the capture log (payload limits, no
durability). NOTIFY as an optional *hint* that flush is needed is a later
optimisation.

### apply (replica)

For each op, `INSERT` / `UPDATE … WHERE pk=$1` / `DELETE … WHERE pk=$1`.
Conflict callback maps onto existence / uniqueness failures:

| Situation | `ConflictType` |
|---|---|
| INSERT and PK exists | `Conflict` |
| UPDATE/DELETE and PK missing | `NotFound` |
| UNIQUE / CHECK / NOT NULL | `Constraint` |
| FK violation | `ForeignKey` |
| UPDATE row exists but values differ from `old_row` (optional v1.1) | `Data` |

v1 may skip old-row comparison (`Data`) and treat apply as last-writer-wins
when `on_conflict` is null → `Abort` (today’s default).

Apply one changeset in one transaction. Restore nothing analogous to
`PRAGMA foreign_keys`; use `SET LOCAL` only if we defer constraints
(`SET CONSTRAINTS ALL DEFERRED`) around a DiffReady insert+delete batch
that would otherwise trip FKs mid-batch. DiffReady should order inserts
before deletes that would orphan, or defer FKs for the transaction.

`handle_diff_ready` must roll back on any failure (same guarantee as T21).

### live vs diff

Same state machine as SQLite. Diff compares bucket hashes of bigint PKs,
requests mismatched ranges, builds a patchset of current rows + delete PK
lists. No session extension, no `DETACH _sqlpipe_stage`: build the patchset
by `SELECT`ing current rows for insert/update PKs.

---

## 10. Subscriptions, prediction, `Database`

### Subscriptions

`sqlite3_set_authorizer` does not exist on Postgres. Collect table deps by
walking the deepparser AST of the (sqldeep-transpiled) SQL. Unparseable
subscribe strings → error at `subscribe()` (fail closed).

Invalidation stays **table-level**: any applied op whose table intersects the
dep set re-evaluates the query. Predicate-aware invalidation (already SQLite-
only IVM research) is not a PG v1 goal.

`QueryResult` filling: `PQgetvalue` → `Value` via the type map in §5.

### Prediction

`SAVEPOINT sqlpipe_pred` / `ROLLBACK TO` / `RELEASE` — same API
(`begin_prediction`, `commit_prediction`, `end_prediction`,
`queue_while_predicting`). Postgres savepoints require an open transaction;
`begin_prediction` starts `BEGIN` if not already in one. Document that
interaction with caller-owned transactions (reject nested prediction if the
caller already has a txn, or adopt it).

### `Database`

```cpp
class Database {
    static Database sqlite(const std::string& path,
                           const std::string& schema_ddl = {});
    static Database postgres(const std::string& conninfo,
                             const std::string& schema_ddl = {});
    // existing path ctor remains SQLite (no silent URI sniffing in v1)
};
```

Open-with-DDL: `sqlift_parse_on` + `extract` + `diff` + `apply` with the
same policy `Database` uses today. Transpile via `SQLDEEP_POSTGRES` on the
Postgres instance. Do not call `sqldeep_register_sqlite`.

`handle()` today returns `sqlite3*`. Add:

```cpp
sqlite3* sqlite_handle() const;   // throws if Engine::Postgres
PGconn*  postgres_handle() const; // throws if Engine::Sqlite
Engine   engine() const;
```

Keep `handle()` as the SQLite alias so existing code compiles.

---

## 11. Public API / error codes

Additive, not a rename sweep:

```cpp
enum class ErrorCode : int {
    Ok = 0,
    SqliteError,         // unchanged
    PostgresError,       // new — libpq / SQLSTATE failures
    ProtocolError,
    SchemaMismatch,
    InvalidState,
    OwnershipRejected,
    WithoutRowidTable,   // SQLite only
    UnsupportedTable,    // new — PK/type/schema gate (both engines may use)
};

enum class Engine : std::uint8_t { Sqlite = 0, Postgres = 1 };

enum class SchemaFingerprintAlgo : std::uint8_t {
    SqliftSha256   = 0x01,
    SqliftPgSha256 = 0x02,
};
```

`MasterConfig` / `ReplicaConfig` / `PeerConfig` need no new required fields
for v1. Optional later: `std::string pg_schema = "public"`.

Go / Swift: second constructor or `OpenPostgres(conninfo)`. Optional build
tag / package feature so default builds stay SQLite-only (no libpq). Wasm:
SQLite only; TypeScript `SqldeepBackend.Postgres` remains a transpile enum.

---

## 12. Wrappers and distribution

| Surface | v1 |
|---|---|
| C++ `dist/sqlpipe.{h,cpp}` | SQLite always; Postgres compiled when `SQLPIPE_POSTGRES=1` or `pkg-config libpq` is present |
| `cv test` | existing suite unchanged; `cv test postgres` (or a doctest filter) needs a server |
| Go `go/sqlpipe` | default CGo = SQLite; `postgres` build tag links libpq and exposes `OpenPostgres` |
| Swift | SQLite default; Postgres only if `libpq` is linked (macOS Homebrew), not iOS |
| Wasm | no change |
| `scripts/bundle-deps.sh` | bundle sqlift/sqldeep as today; do not vendor libpq |

CI: add a `postgres` service to the C++ job (and sqldeep / sqlift repos
similarly). Skip the PG suite when `PGHOST` is unset so laptops without
Docker still run SQLite tests.

---

## 13. Testing

Parity, not cross-engine sync.

**sqldeep** — `testdata/postgres.yaml` execution oracle for JSON / joins /
`RECURSE`. Fail the job if jsonb result ≠ expected (canonicalised).

**sqlift** — extract from a live DB; parse-on-temp-schema; apply additive
`ADD COLUMN`; reject `SET NOT NULL` without `ALLOW_DATA_DEPENDENT`; drift
hash after apply.

**sqlpipe** — loopback on two `PGconn*` to the same server (two schemas or
two databases):

- handshake + live insert/update/delete
- disconnect, mutate, reconnect → diff
- seq-match fast reconnect
- schema mismatch → `ErrorMsg`
- `table_filter`
- Peer ownership
- subscribe fire / no-fire
- unsupported PK → construct-time error
- Hello v8 vs a v7 fixture → `ProtocolError`

No test that opens one SQLite and one Postgres and expects them to converge.

---

## 14. Phasing

| Phase | Repo | Deliverable | Unblocks |
|---|---|---|---|
| **P0** | sqldeep | Live PG oracle for JSON/`RECURSE`; docs drop “transpile-only” for that subset | honest stack tests |
| **P1** | sqlift | `dialect=postgres` IR, extract, parse-on, apply ALTER compiler, executor wrap | `Database` open-with-DDL |
| **P2** | sqlpipe | Outbox triggers, v8 Hello, DML changeset, bigint-PK diff, `PGconn*` ctors | loopback replication |
| **P3** | sqlpipe | Subscribe AST deps, prediction savepoints, Peer, wrappers (Go tag) | feature parity minus Wasm/XML |
| **P4** | all | CI service + hygiene `correctness.postgres-live` → present | merge gate |

P0 may wait for sqldeep `v1.0.0` (§6). P1 does not depend on P0 except for
`Database::exec` transpilation tests. P2 depends on P1 for fingerprints.

Logical decoding, UUID keys, non-`public` schemas, XML-on-PG, and the
parameterized slice (§16) are **after P4**.

---

## 15. File-level sketch (when implemented)

Prefer new TUs over `#ifdef` in `flush()`:

```text
dist/sqlpipe.h                 Engine, PGconn* overloads, new error codes
dist/sqlpipe.cpp               shared serialize + state machine dispatch
src/engine.hpp                 vtable: flush, apply, buckets, exec, subscribe_deps
src/engine_sqlite.cpp          moved session/rowid code (or stay in sqlpipe.cpp v1)
src/engine_postgres.cpp        outbox, libpq, v8 payloads
src/pg_changeset.{h,cpp}       §8 codec
```

sqlift / sqldeep stay in their repos; sqlpipe vendors via `bundle-deps.sh`
as today. Do not grow a third copy of the PG apply compiler inside sqlpipe.

---

## 16. Deferred: parameterized SQLite slice of Postgres

Not this project. Recorded so P0–P4 do not paint it out.

A later layer defines `U_P = slice(U, params)` and materializes that slice
in a **SQLite** edge. That is interest policy (which rows, for whom), not a
second `Master` backend. 🎯T27 is one parameterization (global ∪ private(P) ∪
scoped membership). The general form is wider (tenant, device, query shape).

Implications for *this* design — preserve, do not implement:

- **Message-in/out.** A future projector is a process: read Postgres (outbox
  or logical decoding), write sqlpipe **SQLite-lane** messages toward edges.
  Putting all Postgres logic only behind `PGconn*` `Master` still allows that;
  a hard-wired “the connection *is* the peer” does not.
- **`table_filter` / filtered fingerprints.** A slice is a subset catalog.
- **Structural schema (🎯T26).** Edge want-state is a projected IR, not a
  hub DDL tape.
- **sqldeep’s two emitters.** Same query text on hub (PG) and edge (SQLite)
  is the cheap part of the slice story; it is not the data plane.

What this design deliberately does **not** do, so the slice can choose later:

- shared changeset codec
- cross-engine type lattice / dual-emit fingerprints
- embedding projection predicates in Hello

When that work is unparked, it gets its own design. It does not reopen this
one as “make the wires compatible.”

---

## 17. Open choices (narrow)

Everything else in this note is a default. These four still need a call
before coding:

1. **sqldeep P0 vs 1.0 freeze** — after `v1.0.0` (default) or a documented
   exception.
2. **`numeric`** — reject tables (default) or add a canonical-decimal tag
   (`0x0A`, normalized text without exponent).
3. **Caller-owned PG transactions vs prediction** — reject `begin_prediction`
   if already in a txn (default) or adopt the existing txn.
4. **Go default linkage** — `postgres` build tag (default) vs always-on
   libpq.

Non-choices (already decided): no SQLite↔Postgres sync; outbox not slots in
v1; bigint PK only; XML-on-PG later; Wasm stays SQLite.
