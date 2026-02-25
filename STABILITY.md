# Stability

## Commitment

Version 1.0 will represent a backwards-compatibility contract. After 1.0,
breaking changes to the public C++ API, wire format, or internal storage schema
require a major version bump (which, per project policy, means forking to a new
product). The pre-1.0 period exists to get these right.

## Interaction surface catalogue

Snapshot as of v0.5.0. Items annotated with stability assessments.

### Version macros

| Macro | Value | Stability |
|---|---|---|
| `SQLPIPE_VERSION` | `"0.5.0"` | **Stable** |
| `SQLPIPE_VERSION_MAJOR` | `0` | **Stable** |
| `SQLPIPE_VERSION_MINOR` | `5` | **Stable** |
| `SQLPIPE_VERSION_PATCH` | `0` | **Stable** |

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
| `SchemaMismatchCallback` | `std::function<bool(SchemaVersion remote, SchemaVersion local)>` | **Needs review** — see Gaps |
| `ApproveOwnershipCallback` | `std::function<bool(const std::set<std::string>&)>` | **Stable** |

### Enums

| Enum | Variants | Stability |
|---|---|---|
| `OpType` | `Insert=1, Update=2, Delete=3` | **Stable** |
| `ConflictAction` | `Omit, Replace, Abort` | **Stable** |
| `ConflictType` | `Data, NotFound, Conflict, Constraint, ForeignKey` | **Stable** |
| `ErrorCode` | `Ok=0, SqliteError, ProtocolError, SchemaMismatch, InvalidState, OwnershipRejected, WithoutRowidTable` | **Stable** |
| `DiffPhase` | `ComputingBuckets, ComparingBuckets, ComputingRowHashes, BuildingPatchset, ApplyingPatchset` | **Stable** |
| `MessageTag` | `Hello=0x01, Changeset=0x03, Ack=0x08, Error=0x09, BucketHashes=0x0A, NeedBuckets=0x0B, RowHashes=0x0C, DiffReady=0x0D` | **Stable** |
| `SenderRole` | `AsMaster=0, AsReplica=1` | **Stable** |
| `Replica::State` | `Init, Handshake, DiffBuckets, DiffRows, Live, Error` | **Stable** |
| `Peer::State` | `Init, Negotiating, Diffing, Live, Error` | **Stable** |

### Structs (data types)

| Struct | Fields | Stability |
|---|---|---|
| `ChangeEvent` | `table, op, pk_flags, old_values, new_values` | **Stable** |
| `QueryResult` | `id, columns, rows` | **Stable** |
| `DiffProgress` | `phase, table, items_done, items_total` | **Stable** |
| `HandleResult` | `messages, changes, subscriptions` | **Stable** |
| `PeerHandleResult` | `messages, changes` | **Stable** |
| `PeerMessage` | `sender_role, payload` | **Stable** |

### Message structs

| Struct | Fields | Stability |
|---|---|---|
| `HelloMsg` | `protocol_version, schema_version, owned_tables` | **Stable** |
| `ChangesetMsg` | `seq, data` | **Stable** |
| `AckMsg` | `seq` | **Stable** |
| `ErrorMsg` | `code, detail` | **Stable** |
| `BucketHashEntry` | `table, bucket_lo, bucket_hi, hash, row_count` | **Stable** |
| `BucketHashesMsg` | `buckets` | **Stable** |
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
| `MasterConfig` | `table_filter, seq_key, bucket_size, on_progress, on_schema_mismatch` | **Needs review** — `on_schema_mismatch` (see Gaps) |
| `ReplicaConfig` | `on_conflict, table_filter, seq_key, bucket_size, on_progress, on_schema_mismatch` | **Needs review** — `on_schema_mismatch` (see Gaps) |
| `PeerConfig` | `owned_tables, table_filter, approve_ownership, on_conflict, on_progress, on_schema_mismatch` | **Needs review** — `on_schema_mismatch` (see Gaps) |

### Constants

| Name | Value | Stability |
|---|---|---|
| `kProtocolVersion` | `3` | **Stable** (will increment with breaking wire changes) |
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
    HandleResult handle_message(const Message& msg);
    HandleResult handle_messages(std::span<const Message> msgs);
    QueryResult subscribe(const std::string& sql);
    void unsubscribe(SubscriptionId id);
    void reset();
    Seq current_seq() const;
    SchemaVersion schema_version() const;
    State state() const;
};
```

**Stability**: **Stable**

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
    void reset();
    State state() const;
    const std::set<std::string>& owned_tables() const;
    const std::set<std::string>& remote_tables() const;
};
```

**Stability**: **Stable**

### Free functions

| Signature | Stability |
|---|---|
| `std::vector<uint8_t> serialize(const Message&)` | **Stable** |
| `Message deserialize(std::span<const uint8_t>)` | **Stable** |
| `std::vector<uint8_t> serialize(const PeerMessage&)` | **Stable** |
| `PeerMessage deserialize_peer(std::span<const uint8_t>)` | **Stable** |

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

## Gaps and prerequisites

### Must fix before 1.0

1. **Schema mismatch callback redesign** — The replica's
   `on_schema_mismatch` callback currently receives `(my_sv, my_sv)` because
   the replica does not know the master's schema fingerprint (only that it
   mismatched). The callback signature promises `(remote_sv, local_sv)` but
   cannot deliver on the replica side. Fix: extend the `ErrorMsg` wire format
   (or add a new message) to carry the master's fingerprint or schema SQL,
   then pass the real remote value. This requires a protocol version bump to
   v4.

### Should address before 1.0

2. **Packaging** — No pkg-config `.pc` file or CMake `find_package` module.
   Users must manually set include/link paths. At minimum, provide a
   `sqlpipe.pc.in` template.

3. **Single-header amalgamation** — A `dist/sqlpipe.h` that bundles the
   header and implementation (behind `SQLPIPE_IMPLEMENTATION`) would make
   vendoring trivial. Add an `mk dist` target to generate it.

## Out of scope for 1.0

- Subscription prepared statement sharing (statement cache keyed by SQL text
  for duplicate queries).
- Multi-master replication (more than two peers).
- WITHOUT ROWID table support.
- Incremental View Maintenance for subscriptions.
