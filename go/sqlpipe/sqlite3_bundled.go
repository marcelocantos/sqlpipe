// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

// This package compiles its own copy of SQLite with session extension support.
// SQLite is compiled with SQLITE_ENABLE_SESSION and
// SQLITE_ENABLE_PREUPDATE_HOOK (flags set in wrapper.go CGO_CFLAGS).

package sqlpipe

// #include "sqlite3_impl.c.inc"
import "C"
