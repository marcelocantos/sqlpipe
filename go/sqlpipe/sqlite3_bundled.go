// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

//go:build sqlpipe_bundled_sqlite

// When the sqlpipe_bundled_sqlite build tag is set, this package compiles
// its own copy of SQLite with session extension support. Use this when
// NOT linking alongside another package that bundles SQLite (e.g.,
// mattn/go-sqlite3).
//
// When the tag is absent (default), the consumer must ensure SQLite is
// compiled elsewhere with SQLITE_ENABLE_SESSION and
// SQLITE_ENABLE_PREUPDATE_HOOK. For mattn/go-sqlite3 users, pass:
//
//	CGO_CFLAGS="-DSQLITE_ENABLE_SESSION -DSQLITE_ENABLE_PREUPDATE_HOOK"
//	go build -tags sqlite_preupdate_hook

package sqlpipe

// #include "sqlite3_impl.c.inc"
import "C"
