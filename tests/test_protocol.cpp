// Copyright 2026 The sqlpipe Authors
// SPDX-License-Identifier: Apache-2.0
#include <doctest.h>
#include <sqlpipe.h>

using namespace sqlpipe;

TEST_CASE("HelloMsg round-trip") {
    HelloMsg orig{kProtocolVersion, SchemaVersion{0x01, 0x03}, {}};
    auto buf = serialize(Message{orig});
    auto msg = deserialize(buf);
    auto& m = std::get<HelloMsg>(msg);
    CHECK(m.protocol_version == kProtocolVersion);
    CHECK(m.schema_version == SchemaVersion{0x01, 0x03});
    CHECK(m.owned_tables.empty());
}

TEST_CASE("ChangesetMsg round-trip") {
    Changeset data = {0x01, 0x02, 0x03, 0xFF};
    ChangesetMsg orig{7, data};
    auto buf = serialize(Message{orig});
    auto msg = deserialize(buf);
    auto& m = std::get<ChangesetMsg>(msg);
    CHECK(m.seq == 7);
    CHECK(m.data == data);
}

TEST_CASE("ChangesetMsg round-trip (large, LZ4 path)") {
    // Build a changeset > 64 bytes with repetitive data that compresses well.
    Changeset data(256);
    for (std::size_t i = 0; i < data.size(); ++i)
        data[i] = static_cast<std::uint8_t>(i % 7);
    ChangesetMsg orig{99, data};
    auto buf = serialize(Message{orig});
    auto msg = deserialize(buf);
    auto& m = std::get<ChangesetMsg>(msg);
    CHECK(m.seq == 99);
    CHECK(m.data == data);
    // The serialized form should be smaller than 4 (len prefix) + 1 (tag) +
    // 8 (seq) + 4 (blob len) + 1 (type) + 256 (raw) = 274 bytes.
    CHECK(buf.size() < 274);
}

TEST_CASE("AckMsg round-trip") {
    AckMsg orig{55};
    auto buf = serialize(Message{orig});
    auto msg = deserialize(buf);
    auto& m = std::get<AckMsg>(msg);
    CHECK(m.seq == 55);
}

TEST_CASE("ErrorMsg round-trip") {
    ErrorMsg orig(ErrorCode::SchemaMismatch, "schema differs",
                  SchemaVersion{0x01, 0x2a},
                  "CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT);");
    auto buf = serialize(Message{orig});
    auto msg = deserialize(buf);
    auto& m = std::get<ErrorMsg>(msg);
    CHECK(m.code == ErrorCode::SchemaMismatch);
    CHECK(m.detail == "schema differs");
    CHECK(m.remote_schema_version == SchemaVersion{0x01, 0x2a});
    CHECK(m.remote_schema_sql ==
          "CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT);");
}

TEST_CASE("ErrorMsg round-trip (non-schema-mismatch defaults)") {
    ErrorMsg orig(ErrorCode::ProtocolError, "bad version");
    auto buf = serialize(Message{orig});
    auto msg = deserialize(buf);
    auto& m = std::get<ErrorMsg>(msg);
    CHECK(m.code == ErrorCode::ProtocolError);
    CHECK(m.detail == "bad version");
    CHECK(m.remote_schema_version.empty());
    CHECK(m.remote_schema_sql.empty());
}

TEST_CASE("BucketHashesMsg round-trip") {
    BucketHashesMsg orig;
    orig.buckets.push_back({"t1", 0, 1023, 0xABCDEF0123456789ULL, 100});
    orig.buckets.push_back({"t1", 1024, 2047, 0x1122334455667788ULL, 50});

    auto buf = serialize(Message{orig});
    auto msg = deserialize(buf);
    auto& m = std::get<BucketHashesMsg>(msg);
    REQUIRE(m.buckets.size() == 2);
    CHECK(m.buckets[0].table == "t1");
    CHECK(m.buckets[0].bucket_lo == 0);
    CHECK(m.buckets[0].bucket_hi == 1023);
    CHECK(m.buckets[0].hash == 0xABCDEF0123456789ULL);
    CHECK(m.buckets[0].row_count == 100);
    CHECK(m.buckets[1].table == "t1");
    CHECK(m.buckets[1].bucket_lo == 1024);
}

TEST_CASE("NeedBucketsMsg round-trip") {
    NeedBucketsMsg orig;
    orig.ranges.push_back({"users", 0, 1023});
    orig.ranges.push_back({"orders", 1024, 2047});

    auto buf = serialize(Message{orig});
    auto msg = deserialize(buf);
    auto& m = std::get<NeedBucketsMsg>(msg);
    REQUIRE(m.ranges.size() == 2);
    CHECK(m.ranges[0].table == "users");
    CHECK(m.ranges[0].lo == 0);
    CHECK(m.ranges[0].hi == 1023);
    CHECK(m.ranges[1].table == "orders");
}

TEST_CASE("RowHashesMsg round-trip") {
    RowHashesMsg orig;
    RowHashesEntry entry;
    entry.table = "t1";
    entry.lo = 0;
    entry.hi = 1023;
    entry.runs.push_back({1, 3, {0xAA, 0xBB, 0xCC}});
    entry.runs.push_back({10, 2, {0xDD, 0xEE}});
    orig.entries.push_back(std::move(entry));

    auto buf = serialize(Message{orig});
    auto msg = deserialize(buf);
    auto& m = std::get<RowHashesMsg>(msg);
    REQUIRE(m.entries.size() == 1);
    CHECK(m.entries[0].table == "t1");
    CHECK(m.entries[0].lo == 0);
    CHECK(m.entries[0].hi == 1023);
    REQUIRE(m.entries[0].runs.size() == 2);
    CHECK(m.entries[0].runs[0].start_rowid == 1);
    CHECK(m.entries[0].runs[0].count == 3);
    REQUIRE(m.entries[0].runs[0].hashes.size() == 3);
    CHECK(m.entries[0].runs[0].hashes[0] == 0xAA);
    CHECK(m.entries[0].runs[1].start_rowid == 10);
    CHECK(m.entries[0].runs[1].count == 2);
}

TEST_CASE("DiffReadyMsg round-trip") {
    DiffReadyMsg orig;
    orig.seq = 42;
    orig.patchset = {0x01, 0x02, 0x03};
    orig.deletes.push_back({"t1", {1, 2, 3}});
    orig.deletes.push_back({"t2", {10, 20}});

    auto buf = serialize(Message{orig});
    auto msg = deserialize(buf);
    auto& m = std::get<DiffReadyMsg>(msg);
    CHECK(m.seq == 42);
    CHECK(m.patchset == Changeset{0x01, 0x02, 0x03});
    REQUIRE(m.deletes.size() == 2);
    CHECK(m.deletes[0].table == "t1");
    CHECK(m.deletes[0].rowids == std::vector<std::int64_t>{1, 2, 3});
    CHECK(m.deletes[1].table == "t2");
    CHECK(m.deletes[1].rowids == std::vector<std::int64_t>{10, 20});
}

TEST_CASE("DiffReadyMsg empty round-trip") {
    DiffReadyMsg orig{5, {}, {}};
    auto buf = serialize(Message{orig});
    auto msg = deserialize(buf);
    auto& m = std::get<DiffReadyMsg>(msg);
    CHECK(m.seq == 5);
    CHECK(m.patchset.empty());
    CHECK(m.deletes.empty());
}

TEST_CASE("deserialize rejects truncated buffer") {
    std::vector<std::uint8_t> buf = {0x00, 0x00};
    CHECK_THROWS_AS(deserialize(buf), Error);
}

TEST_CASE("HelloMsg with owned_tables round-trip") {
    HelloMsg orig;
    orig.protocol_version = kProtocolVersion;
    orig.schema_version = SchemaVersion{0x01, 0x2a};
    orig.owned_tables = {"drafts", "local_prefs", "settings"};

    auto buf = serialize(Message{orig});
    auto msg = deserialize(buf);
    auto& m = std::get<HelloMsg>(msg);
    CHECK(m.protocol_version == kProtocolVersion);
    CHECK(m.schema_version == SchemaVersion{0x01, 0x2a});
    REQUIRE(m.owned_tables.size() == 3);
    CHECK(m.owned_tables.count("drafts") == 1);
    CHECK(m.owned_tables.count("local_prefs") == 1);
    CHECK(m.owned_tables.count("settings") == 1);
}

TEST_CASE("HelloMsg without owned_tables") {
    HelloMsg orig;
    orig.protocol_version = kProtocolVersion;
    orig.schema_version = SchemaVersion{0x01, 0x07};
    // owned_tables is empty by default.

    auto buf = serialize(Message{orig});
    auto msg = deserialize(buf);
    auto& m = std::get<HelloMsg>(msg);
    CHECK(m.owned_tables.empty());
}

TEST_CASE("PeerMessage round-trip (AsMaster)") {
    PeerMessage orig{SenderRole::AsMaster,
                     ChangesetMsg{42, {0x01, 0x02, 0x03}}};
    auto buf = serialize(orig);
    auto decoded = deserialize_peer(buf);
    CHECK(decoded.sender_role == SenderRole::AsMaster);
    auto& cs = std::get<ChangesetMsg>(decoded.payload);
    CHECK(cs.seq == 42);
    CHECK(cs.data == Changeset{0x01, 0x02, 0x03});
}

TEST_CASE("PeerMessage round-trip (AsReplica)") {
    PeerMessage orig{SenderRole::AsReplica, AckMsg{99}};
    auto buf = serialize(orig);
    auto decoded = deserialize_peer(buf);
    CHECK(decoded.sender_role == SenderRole::AsReplica);
    auto& ack = std::get<AckMsg>(decoded.payload);
    CHECK(ack.seq == 99);
}

TEST_CASE("deserialize rejects oversized message") {
    // Create a buffer that exceeds kMaxMessageSize.
    std::vector<std::uint8_t> buf(kMaxMessageSize + 5 + 1);
    // Write a valid length prefix (content = kMaxMessageSize + 1).
    auto len = static_cast<std::uint32_t>(kMaxMessageSize + 1);
    buf[0] = static_cast<std::uint8_t>(len);
    buf[1] = static_cast<std::uint8_t>(len >> 8);
    buf[2] = static_cast<std::uint8_t>(len >> 16);
    buf[3] = static_cast<std::uint8_t>(len >> 24);
    buf[4] = static_cast<std::uint8_t>(MessageTag::Hello);

    CHECK_THROWS_AS(deserialize(buf), Error);
}

TEST_CASE("deserialize rejects absurd array count") {
    // Craft a BucketHashesMsg with count = 0xFFFFFFFF.
    std::vector<std::uint8_t> buf;
    // Length prefix (placeholder).
    buf.resize(4);
    buf.push_back(static_cast<std::uint8_t>(MessageTag::BucketHashes));
    // count = 0xFFFFFFFF (> kMaxArrayCount).
    buf.push_back(0xFF);
    buf.push_back(0xFF);
    buf.push_back(0xFF);
    buf.push_back(0xFF);
    // Patch length.
    auto total = static_cast<std::uint32_t>(buf.size() - 4);
    buf[0] = static_cast<std::uint8_t>(total);
    buf[1] = static_cast<std::uint8_t>(total >> 8);
    buf[2] = static_cast<std::uint8_t>(total >> 16);
    buf[3] = static_cast<std::uint8_t>(total >> 24);

    CHECK_THROWS_AS(deserialize(buf), Error);
}

namespace {

void put_u8(std::vector<std::uint8_t>& b, std::uint8_t v) { b.push_back(v); }

void put_u32(std::vector<std::uint8_t>& b, std::uint32_t v) {
    b.push_back(static_cast<std::uint8_t>(v));
    b.push_back(static_cast<std::uint8_t>(v >> 8));
    b.push_back(static_cast<std::uint8_t>(v >> 16));
    b.push_back(static_cast<std::uint8_t>(v >> 24));
}

void put_i64(std::vector<std::uint8_t>& b, std::int64_t v) {
    auto u = static_cast<std::uint64_t>(v);
    for (int i = 0; i < 8; ++i)
        b.push_back(static_cast<std::uint8_t>(u >> (i * 8)));
}

void patch_len(std::vector<std::uint8_t>& b) {
    auto total = static_cast<std::uint32_t>(b.size() - 4);
    b[0] = static_cast<std::uint8_t>(total);
    b[1] = static_cast<std::uint8_t>(total >> 8);
    b[2] = static_cast<std::uint8_t>(total >> 16);
    b[3] = static_cast<std::uint8_t>(total >> 24);
}

bool throws_with(const std::vector<std::uint8_t>& buf, const char* needle) {
    try {
        deserialize(buf);
    } catch (const Error& e) {
        return std::string(e.what()).find(needle) != std::string::npos;
    } catch (...) {
        return false;
    }
    return false;
}

}  // namespace

// T18/F4: read_changeset must validate the wire-supplied decompressed length
// against kMaxMessageSize before allocating, and surface a ProtocolError
// rather than attempting an unbounded allocation / throwing std::bad_alloc.
TEST_CASE("deserialize rejects oversized decompressed changeset length (T18/F4)") {
    std::vector<std::uint8_t> buf;
    buf.resize(4);  // length placeholder
    put_u8(buf, static_cast<std::uint8_t>(MessageTag::Changeset));
    put_i64(buf, 1);  // seq

    // Changeset frame: [u32 frame_len][u8 type=0x01 LZ4][u32 original_len][data]
    std::uint32_t original_len =
        static_cast<std::uint32_t>(kMaxMessageSize) + 1;  // > limit
    std::vector<std::uint8_t> compressed = {0, 0, 0, 0, 0};  // 5 arbitrary bytes
    std::uint32_t frame_len =
        1 + 4 + static_cast<std::uint32_t>(compressed.size());
    put_u32(buf, frame_len);
    put_u8(buf, 0x01);
    put_u32(buf, original_len);
    buf.insert(buf.end(), compressed.begin(), compressed.end());
    patch_len(buf);

    // Must throw a ProtocolError naming the limit — not "LZ4 decompression
    // failed" (which is what the unbounded pre-fix path reaches after a large
    // allocation), and never std::bad_alloc.
    CHECK(throws_with(buf, "exceeds"));
}

// T19/F5: RowHashRun.count is an i64 read straight off the wire; it must be
// validated before hashes.resize(), surfacing a ProtocolError instead of
// std::length_error (negative) or std::bad_alloc (huge).
TEST_CASE("deserialize rejects out-of-range row hash run count (T19/F5)") {
    std::vector<std::uint8_t> buf;
    buf.resize(4);  // length placeholder
    put_u8(buf, static_cast<std::uint8_t>(MessageTag::RowHashes));
    put_u32(buf, 1);   // entry_count
    put_u32(buf, 0);   // entry.table: empty string (len 0)
    put_i64(buf, 0);   // entry.lo
    put_i64(buf, 0);   // entry.hi
    put_u32(buf, 1);   // run_count
    put_i64(buf, 0);   // run.start_rowid
    put_i64(buf, -1);  // run.count = -1 → resize(SIZE_MAX) before the fix
    patch_len(buf);

    // Before the fix this throws std::length_error (not an sqlpipe::Error),
    // escaping the deserialize contract; after the fix it is a ProtocolError.
    CHECK_THROWS_AS(deserialize(buf), Error);
    CHECK(throws_with(buf, "count"));
}

// T23/F9: the C-API and Wasm FFI shims allocate every buffer they hand back to
// managed runtimes via detail::checked_malloc, which must throw std::bad_alloc
// on failure so the shim's try/catch returns a clean error instead of
// dereferencing a null pointer in the following memcpy.
TEST_CASE("checked_malloc throws on allocation failure (T23/F9)") {
    void* p = detail::checked_malloc(64);
    CHECK(p != nullptr);
    std::free(p);
    // SIZE_MAX bytes cannot be allocated → malloc returns nullptr → must throw.
    CHECK_THROWS_AS(detail::checked_malloc(SIZE_MAX), std::bad_alloc);
}
