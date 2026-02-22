// Copyright 2026 The sqlpipe Authors
// SPDX-License-Identifier: Apache-2.0
#include <doctest.h>
#include <sqlpipe.h>

using namespace sqlpipe;

TEST_CASE("HelloMsg round-trip") {
    HelloMsg orig{kProtocolVersion, 42, 3};
    auto buf = serialize(Message{orig});
    auto msg = deserialize(buf);
    auto& m = std::get<HelloMsg>(msg);
    CHECK(m.protocol_version == kProtocolVersion);
    CHECK(m.seq == 42);
    CHECK(m.schema_version == 3);
}

TEST_CASE("CatchupBeginMsg round-trip") {
    CatchupBeginMsg orig{10, 20};
    auto buf = serialize(Message{orig});
    auto msg = deserialize(buf);
    auto& m = std::get<CatchupBeginMsg>(msg);
    CHECK(m.from_seq == 10);
    CHECK(m.to_seq == 20);
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

TEST_CASE("CatchupEndMsg round-trip") {
    auto buf = serialize(Message{CatchupEndMsg{}});
    auto msg = deserialize(buf);
    CHECK(std::holds_alternative<CatchupEndMsg>(msg));
}

TEST_CASE("ResyncBeginMsg round-trip") {
    ResyncBeginMsg orig{5, "CREATE TABLE foo (id INTEGER PRIMARY KEY)"};
    auto buf = serialize(Message{orig});
    auto msg = deserialize(buf);
    auto& m = std::get<ResyncBeginMsg>(msg);
    CHECK(m.schema_version == 5);
    CHECK(m.schema_sql == "CREATE TABLE foo (id INTEGER PRIMARY KEY)");
}

TEST_CASE("ResyncTableMsg round-trip") {
    Changeset data = {0xAA, 0xBB};
    ResyncTableMsg orig{"users", data};
    auto buf = serialize(Message{orig});
    auto msg = deserialize(buf);
    auto& m = std::get<ResyncTableMsg>(msg);
    CHECK(m.table_name == "users");
    CHECK(m.data == data);
}

TEST_CASE("ResyncEndMsg round-trip") {
    ResyncEndMsg orig{99};
    auto buf = serialize(Message{orig});
    auto msg = deserialize(buf);
    auto& m = std::get<ResyncEndMsg>(msg);
    CHECK(m.seq == 99);
}

TEST_CASE("AckMsg round-trip") {
    AckMsg orig{55};
    auto buf = serialize(Message{orig});
    auto msg = deserialize(buf);
    auto& m = std::get<AckMsg>(msg);
    CHECK(m.seq == 55);
}

TEST_CASE("ErrorMsg round-trip") {
    ErrorMsg orig{ErrorCode::SequenceGap, "gap detected"};
    auto buf = serialize(Message{orig});
    auto msg = deserialize(buf);
    auto& m = std::get<ErrorMsg>(msg);
    CHECK(m.code == ErrorCode::SequenceGap);
    CHECK(m.detail == "gap detected");
}

TEST_CASE("deserialize rejects truncated buffer") {
    std::vector<std::uint8_t> buf = {0x00, 0x00};
    CHECK_THROWS_AS(deserialize(buf), Error);
}

TEST_CASE("HelloMsg with owned_tables round-trip") {
    HelloMsg orig;
    orig.protocol_version = kProtocolVersion;
    orig.seq = 10;
    orig.schema_version = 42;
    orig.owned_tables = {"drafts", "local_prefs", "settings"};

    auto buf = serialize(Message{orig});
    auto msg = deserialize(buf);
    auto& m = std::get<HelloMsg>(msg);
    CHECK(m.protocol_version == kProtocolVersion);
    CHECK(m.seq == 10);
    CHECK(m.schema_version == 42);
    REQUIRE(m.owned_tables.size() == 3);
    CHECK(m.owned_tables.count("drafts") == 1);
    CHECK(m.owned_tables.count("local_prefs") == 1);
    CHECK(m.owned_tables.count("settings") == 1);
}

TEST_CASE("HelloMsg without owned_tables backward compat") {
    // Serialize with empty owned_tables, verify identical to old format.
    HelloMsg orig;
    orig.protocol_version = kProtocolVersion;
    orig.seq = 5;
    orig.schema_version = 7;
    // owned_tables is empty by default.

    auto buf = serialize(Message{orig});
    // Old format: 4 len + 1 tag + 4 version + 8 seq + 4 sv = 21 bytes.
    CHECK(buf.size() == 21);

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
