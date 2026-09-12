// One-shot generator for testdata/serialize_golden.json.
// Not part of the doctest suite. Build:
//   c++ -std=c++23 -Idist -Ivendor/include -Ivendor/github.com/marcelocantos/deepparser/src \
//       tests/dump_serialize_golden.cpp build/libsqlpipe.a -o /tmp/dump_serialize_golden

#include <sqlpipe.h>

#include <iomanip>
#include <iostream>
#include <nlohmann/json.hpp>
#include <sstream>

using namespace sqlpipe;

static std::string to_hex(const std::vector<std::uint8_t>& buf) {
    std::ostringstream os;
    os << std::hex << std::setfill('0');
    for (auto b : buf) {
        os << std::setw(2) << static_cast<int>(b);
    }
    return os.str();
}

int main() {
    nlohmann::json corpus;

    HelloMsg hello{kProtocolVersion, SchemaVersion{0x01, 0x03}, {}, -1};
    corpus["hello"] = to_hex(serialize(Message{hello}));

    ChangesetMsg cs{7, Changeset{0x01, 0x02, 0x03, 0xFF}};
    corpus["changeset"] = to_hex(serialize(Message{cs}));

    corpus["ack"] = to_hex(serialize(Message{AckMsg{55}}));

    ErrorMsg err(ErrorCode::SchemaMismatch, "schema differs", SchemaVersion{0x01, 0x2a},
                 "CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT);");
    corpus["error"] = to_hex(serialize(Message{err}));

    BucketHashesMsg bh;
    bh.buckets.push_back({"t1", 0, 1023, 0xABCDEF0123456789ULL, 100});
    bh.buckets.push_back({"t1", 1024, 2047, 0x1122334455667788ULL, 50});
    corpus["bucket_hashes"] = to_hex(serialize(Message{bh}));

    NeedBucketsMsg nb;
    nb.ranges.push_back({"users", 0, 1023});
    nb.ranges.push_back({"orders", 1024, 2047});
    corpus["need_buckets"] = to_hex(serialize(Message{nb}));

    RowHashesMsg rh;
    RowHashesEntry entry;
    entry.table = "t1";
    entry.lo = 0;
    entry.hi = 1023;
    entry.runs.push_back({1, 3, {0xAA, 0xBB, 0xCC}});
    entry.runs.push_back({10, 2, {0xDD, 0xEE}});
    rh.entries.push_back(std::move(entry));
    corpus["row_hashes"] = to_hex(serialize(Message{rh}));

    DiffReadyMsg dr;
    dr.seq = 42;
    dr.patchset = {0x01, 0x02, 0x03};
    dr.deletes.push_back({"t1", {1, 2, 3}});
    dr.deletes.push_back({"t2", {10, 20}});
    corpus["diff_ready"] = to_hex(serialize(Message{dr}));

    std::cout << corpus.dump(2) << "\n";
    return 0;
}
