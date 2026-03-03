// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

// Package sqlpipe provides streaming replication for SQLite databases.
//
// The library is message-in / message-out: callers provide the transport.
// Two modes of operation:
//
//   - Unidirectional: [Master] sends changesets to a [Replica].
//   - Bidirectional: [Peer] wraps Master + Replica behind a symmetric API,
//     with each side owning a disjoint set of tables.
//
// Two sync modes:
//
//   - Live streaming: Master calls [Master.Flush] after each write transaction;
//     Replica applies the resulting changeset.
//   - Diff sync: On reconnect, master and replica exchange bucketed row hashes
//     to discover what differs, then the master sends only the delta.
package sqlpipe
