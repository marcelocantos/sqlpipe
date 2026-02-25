// Copyright 2026 The sqlpipe Authors
// SPDX-License-Identifier: Apache-2.0
//
// libFuzzer harness for sqlpipe::deserialize and sqlpipe::deserialize_peer.
// Build with: mk fuzz
// Run with:   ./build/fuzz_deserialize corpus/deserialize -max_total_time=60

#include "sqlpipe.h"

#include <cstddef>
#include <cstdint>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Fuzz deserialize (Message).
    try {
        sqlpipe::deserialize(std::span<const uint8_t>(data, size));
    } catch (const sqlpipe::Error&) {
        // Expected for malformed input.
    }

    // Fuzz deserialize_peer (PeerMessage — 1 extra byte for SenderRole).
    try {
        sqlpipe::deserialize_peer(std::span<const uint8_t>(data, size));
    } catch (const sqlpipe::Error&) {
        // Expected for malformed input.
    }

    return 0;
}
