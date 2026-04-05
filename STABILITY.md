# Stability

## Commitment

Version 1.0 will represent a backwards-compatibility contract. After 1.0,
breaking changes to the public C++ API, wire format, or internal storage schema
require a major version bump (which, per project policy, means forking to a new
product). The pre-1.0 period exists to get these right.

Even when all known gaps are resolved and the surface catalogue shows everything
as Stable, the project should remain pre-1.0 for a settling period — real-world
usage over time is the only reliable way to discover API design mistakes that
aren't obvious from tests and documentation alone. Once 1.0 ships, fixing those
mistakes becomes extremely costly. Think twice, cut once.

The settling threshold is purely time-based — new releases don't accelerate it,
because new code is inherently destabilising. The minimum period scales with
API surface complexity:

| Surface items | Minimum settling period |
|---|---|
| < 20 | 1 month |
| 20–50 | 2 months |
| 50–100 | 3 months |
| > 100 | 4 months |

The clock starts from the last breaking change to the interaction surface.

Current surface: ~105 items → 3 months. Last breaking change: v0.17.0
(Delivery/OutMessage/PeerOutMessage removed — all methods return Message/
PeerMessage directly; FlushCallback/SinkCallback simplified, 2026-03-30).
Eligible: 2026-06-30.

## Interaction surface catalogue

Snapshot as of v0.20.0. Items annotated with stability assessments.

### Version macros

| Macro | Value | Stability |
|---|---|---|
| `SQLPIPE_VERSION` | `"0.20.0"` | **Stable** |
| `SQLPIPE_VERSION_MAJOR` | `0` | **Stable** |
| `SQLPIPE_VERSION_MINOR` | `20` | **Stable** |
| `SQLPIPE_VERSION_PATCH` | `0` | **Stable** |
| `SQLDEEP_VERSION` | `"0.12.0"` | **Stable** (bundled) |
| `SQLIFT_VERSION` | `"0.12.0"` | **Stable** (bundled) |

### Type aliases

| Name | Definition | Stability |
|---|---|---|
| `Seq` | `std::int64_t` | **Stable** |
| `SchemaVersion` | `std::int32_t` | **Stable** |
| `Changeset` | `std::vector<std::uint8_t>` | **Stable** |
| `Value` | `std::variant<monostate, int64_t, double, string, vector<uint8_t>>` | **Stable** |
| `SubscriptionId` | `std::uint64_t` | **Stable** |
| `ConflictCallback` | `std::function<ConflictAction(ConflictType, const ChangeEvent&)>` | **Stable** |
| `ProgressCallback` | `std::function<void(const DiffProgress&)>` | **Stable** |
| `LogCallback` | `std::function<void(LogLevel, std::string_view)>` | **Stable** |
| `SchemaMismatchCallback` | `std::function<bool(SchemaVersion remote, SchemaVersion local, const std::string& remote_schema_sql)>` | **Stable** |
| `ApproveOwnershipCallback` | `std::function<bool(const std::set<std::string>&)>` | **Stable** |
| `FlushCallback` | `std::function<void(const std::vector<Message>&)>` | **Stable** |
| `SinkCallback` | `std::function<void(const Message&)>` | **Stable** |
| `SubscriptionCallback` | `std::function<void(const QueryResult&)>` | **Fluid** (new in v0.19.0) |

### Enums

| Enum | Variants | Stability |
|---|---|---|
| `OpType` | `Insert=1, Update=2, Delete=3` | **Stable** |
| `ConflictAction` | `Omit, Replace, Abort` | **Stable** |
| `ConflictType` | `Data, NotFound, Conflict, Constraint, ForeignKey` | **Stable** |
| `ErrorCode` | `Ok=0, SqliteError, ProtocolError, SchemaMismatch, InvalidState, OwnershipRejected, WithoutRowidTable` | **Stable** |
| `DiffPhase` | `ComputingBuckets, ComparingBuckets, ComputingRowHashes, BuildingPatchset, ApplyingPatchset` | **Stable** |
| `LogLevel` | `Debug=0, Info, Warn, Error` | **Stable** |
| `MessageTag` | `Hello=0x01, Changeset=0x03, Ack=0x08, Error=0x09, BucketHashes=0x0A, NeedBuckets=0x0B, RowHashes=0x0C, DiffReady=0x0D` | **Stable** |
| `SenderRole` | `AsMaster=0, AsReplica=1` | **Stable** |
| `PeerRole` | `Client, Server` | **Stable** |
| `Replica::State` | `Init, Handshake, DiffBuckets, DiffRows, Live, Error` | **Stable** |
| `Peer::State` | `Init, Negotiating, Diffing, Live, Error` | **Stable** |

### Structs (data types)

| Struct | Fields | Stability |
|---|---|---|
| `ChangeEvent` | `table, op, pk_flags, old_values, new_values` | **Stable** |
| `QueryResult` | `id, columns, rows` | **Stable** |
| `DiffProgress` | `phase, table, items_done, items_total` | **Stable** |
| `HandleResult` | `messages: vector<Message>, changes, subscriptions` | **Stable** |
| `PeerHandleResult` | `messages: vector<PeerMessage>, changes, subscriptions` | **Stable** |
| `PeerMessage` | `sender_role, payload` | **Stable** |

### Message structs

| Struct | Fields | Stability |
|---|---|---|
| `HelloMsg` | `protocol_version, schema_version, owned_tables, last_seq` | **Stable** |
| `ChangesetMsg` | `seq, data` | **Stable** |
| `AckMsg` | `seq` | **Stable** |
| `ErrorMsg` | `code, detail, remote_schema_version, remote_schema_sql` | **Stable** |
| `BucketHashEntry` | `table, bucket_lo, bucket_hi, hash, row_count` | **Stable** |
| `BucketHashesMsg` | `buckets, last_seq, protocol_version, schema_version` | **Stable** (last_seq/protocol_version/schema_version added v0.16.0) |
| `NeedBucketRange` | `table, lo, hi` | **Stable** |
| `NeedBucketsMsg` | `ranges` | **Stable** |
| `RowHashRun` | `start_rowid, count, hashes` | **Stable** |
| `RowHashesEntry` | `table, lo, hi, runs` | **Stable** |
| `RowHashesMsg` | `entries` | **Stable** |
| `TableDeletes` | `table, rowids` | **Stable** |
| `DiffReadyMsg` | `seq, patchset, deletes` | **Stable** |
| `Message` | `variant<HelloMsg, ChangesetMsg, AckMsg, ErrorMsg, BucketHashesMsg, NeedBucketsMsg, RowHashesMsg, DiffReadyMsg>` | **Stable** |

### Config structs

| Struct | Fields | Stability |
|---|---|---|
| `MasterConfig` | `table_filter, seq_key, bucket_size, on_progress, on_schema_mismatch, on_log, on_flush, changeset_queue_size` | **Stable** |
| `ReplicaConfig` | `on_conflict, table_filter, seq_key, bucket_size, on_progress, on_schema_mismatch, on_log` | **Stable** |
| `PeerConfig` | `role, owned_tables, table_filter, approve_ownership, on_conflict, on_progress, on_schema_mismatch, on_log` | **Stable** (owned_tables accepts glob patterns since v0.18.0) |
| `RelayConfig` | `table_filter, on_conflict, on_schema_mismatch, on_log` | **Stable** |

### Constants

| Name | Value | Stability |
|---|---|---|
| `kProtocolVersion` | `6` | **Stable** (will increment with breaking wire changes) |
| `kDefaultBucketSize` | `1024` | **Stable** |
| `kMaxMessageSize` | `64 * 1024 * 1024` (64 MB) | **Stable** |
| `kMaxArrayCount` | `10'000'000` (10 M) | **Stable** |

### Error class

```cpp
class Error : public std::runtime_error {
    Error(ErrorCode code, const std::string& msg);
    ErrorCode code() const noexcept;
};
```

**Stability**: **Stable**

### Master class

```cpp
class Master {
    explicit Master(sqlite3* db, MasterConfig config = {});
    ~Master();
    Master(Master&&) noexcept;
    Master& operator=(Master&&) noexcept;

    void exec(const std::string& sql);
    std::vector<Message> flush();
    std::vector<Message> handle_message(const Message& msg);
    Seq current_seq() const;
    SchemaVersion schema_version() const;
};
```

**Stability**: **Stable**

### Replica class

```cpp
class Replica {
    explicit Replica(sqlite3* db, ReplicaConfig config = {});
    ~Replica();
    Replica(Replica&&) noexcept;
    Replica& operator=(Replica&&) noexcept;

    Message hello() const;
    std::vector<Message> converge();
    HandleResult handle_message(const Message& msg);
    HandleResult handle_messages(std::span<const Message> msgs);
    SubscriptionId subscribe(const std::string& sql);
    void unsubscribe(SubscriptionId id);
    void begin_prediction();
    void commit_prediction();
    void rollback_prediction();
    void reset();
    Seq current_seq() const;
    SchemaVersion schema_version() const;
    State state() const;
};
```

**Stability**: **Stable** (converge() added v0.16.0)

### Peer class

```cpp
class Peer {
    explicit Peer(sqlite3* db, PeerConfig config = {});
    ~Peer();
    Peer(Peer&&) noexcept;
    Peer& operator=(Peer&&) noexcept;

    std::vector<PeerMessage> start();
    std::vector<PeerMessage> flush();
    PeerHandleResult handle_message(const PeerMessage& msg);
    SubscriptionId subscribe(const std::string& sql);
    void unsubscribe(SubscriptionId id);
    void reset();
    State state() const;
    const std::set<std::string>& owned_tables() const;
    const std::set<std::string>& remote_tables() const;
};
```

**Stability**: **Stable**

### Relay class

```cpp
class Relay {
    explicit Relay(sqlite3* db, RelayConfig config = {});
    ~Relay();
    Relay(Relay&&) noexcept;
    Relay& operator=(Relay&&) noexcept;

    std::size_t add_sink(SinkCallback cb);
    void remove_sink(std::size_t id);
    Message hello();
    std::vector<Message> handle_upstream(const Message& msg);
    std::vector<Message> handle_downstream(const Message& msg);
    SubscriptionId subscribe(const std::string& sql);
    void unsubscribe(SubscriptionId id);
    void reset();
};
```

**Stability**: **Stable**

### QueryWatch class

```cpp
class QueryWatch {
    explicit QueryWatch(sqlite3* db);
    ~QueryWatch();
    QueryWatch(QueryWatch&&) noexcept;
    QueryWatch& operator=(QueryWatch&&) noexcept;

    SubscriptionId subscribe(const std::string& sql);
    void unsubscribe(SubscriptionId id);
    std::vector<QueryResult> notify(const std::set<std::string>& affected_tables);
    std::vector<QueryResult> notify(const std::set<std::string>& affected_tables,
                                    const Changeset& changeset_data);
    bool empty() const;
};
```

**Stability**: **Stable**

### Database class

```cpp
class Database {
    explicit Database(const std::string& path, const std::string& schema_ddl = {});
    ~Database();
    Database(Database&&) noexcept;
    Database& operator=(Database&&) noexcept;

    void exec(const std::string& sql);
    QueryResult query(const std::string& sql) const;
    Subscription subscribe(const std::string& sql, SubscriptionCallback cb);
    void notify(const std::set<std::string>& affected_tables);
    void notify();
    sqlite3* handle() const;
    static std::string migration(const std::string& from_ddl, const std::string& to_ddl);
};
```

**Stability**: **Fluid** (new in v0.19.0 — API shape may evolve before 1.0)

### Subscription class

```cpp
class Subscription {
    ~Subscription();  // auto-unsubscribes
    Subscription(Subscription&&) noexcept;
    Subscription& operator=(Subscription&&) noexcept;
};
```

**Stability**: **Fluid** (new in v0.19.0)

### Free functions

| Signature | Stability |
|---|---|
| `std::vector<uint8_t> serialize(const Message&)` | **Stable** |
| `Message deserialize(std::span<const uint8_t>)` | **Stable** |
| `std::vector<uint8_t> serialize(const PeerMessage&)` | **Stable** |
| `PeerMessage deserialize_peer(std::span<const uint8_t>)` | **Stable** |
| `void sync_handshake(Master&, Replica&)` | **Stable** |
| `void sync_handshake(Peer& client, Peer& server)` | **Stable** |
| `void sync_handshake(Master&, Relay&)` | **Stable** |
| `QueryResult query(sqlite3* db, const std::string& sql)` | **Stable** |
| `std::string generate_migration(const std::string&, const std::string&)` | **Fluid** (new in v0.19.0) |

### Bundled C APIs (sqldeep, sqlift)

The following C APIs are bundled into `dist/sqlpipe.h` and available to consumers. They are pass-through wrappers of the standalone sqldeep and sqlift libraries.

| Function | Stability |
|---|---|
| `sqldeep_transpile()` | **Stable** (matches sqldeep 0.8.0) |
| `sqldeep_transpile_fk()` | **Stable** |
| `sqldeep_transpile_backend()` | **Stable** |
| `sqldeep_transpile_fk_backend()` | **Stable** |
| `sqldeep_version()` / `sqldeep_free()` | **Stable** |
| `sqldeep_register_sqlite_xml(db)` | **Fluid** (new in v0.20.0) |
| SQLite: `xml_element()`, `xml_attrs()`, `xml_agg()` | **Fluid** (new in v0.20.0, HTML string output) |
| SQLite: `xml_element_jsonml()`, `xml_attrs_jsonml()`, `jsonml_agg()` | **Fluid** (new in v0.20.0, JSONML output) |
| `sqlift_parse()` / `sqlift_diff()` / `sqlift_apply()` | **Stable** (matches sqlift 0.12.0) |
| `sqlift_extract()` / `sqlift_db_wrap()` / `sqlift_db_close()` | **Stable** |
| `sqlift_schema_hash()` / `sqlift_detect_redundant_indexes()` | **Stable** |
| `sqlift_free()` | **Stable** |

### Wire format

| Format | Description | Stability |
|---|---|---|
| Message frame | `[4B LE length][1B tag][payload]` | **Stable** |
| PeerMessage frame | `[4B LE length][1B sender_role][1B tag][payload]` | **Stable** |
| Changeset compression | `[u32 len][u8 type][data]` — `0x00` uncompressed, `0x01` LZ4 | **Stable** |

### Internal storage

| Table | Schema | Stability |
|---|---|---|
| `_sqlpipe_meta` | `CREATE TABLE _sqlpipe_meta(key TEXT PRIMARY KEY, value)` | **Stable** |

Keys: `seq` (Master/Replica solo), `master_seq` / `replica_seq` (Peer mode).

## Gaps

- Database and Subscription APIs are new and marked Fluid — need real-world
  usage to validate the design before stabilising.
- Database does not yet expose sqldeep FK-guided transpilation (only
  convention-based). May need a method to register foreign keys.

## Out of scope for 1.0

- Subscription prepared statement sharing (statement cache keyed by SQL text
  for duplicate queries).
- Multi-master replication (more than two peers).
- WITHOUT ROWID table support.
- Incremental View Maintenance for subscriptions.
