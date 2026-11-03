// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package sqlpipe

import (
	"path/filepath"
	"sync/atomic"
	"testing"
)

// TestNewPeerFileCallbackHandles boxes every NewPeer callback in allocated
// memory and runs the ownership trampoline. checkptr rejects a cgo.Handle
// passed as unsafe.Pointer because the handle is a small integer; this
// handshake is the production shape that crashes under -race without the
// malloc'd uintptr_t.
func TestNewPeerFileCallbackHandles(t *testing.T) {
	dir := t.TempDir()
	serverDB := openFile(t, filepath.Join(dir, "server.db"))
	clientDB := openFile(t, filepath.Join(dir, "client.db"))
	for _, db := range []*Database{serverDB, clientDB} {
		mustExec(t, db, "CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)")
		mustExec(t, db, "CREATE TABLE t2 (id INTEGER PRIMARY KEY, val TEXT)")
	}

	var approved atomic.Int32
	server, err := NewPeer(serverDB, PeerConfig{
		ApproveOwnership: func(map[string]bool) bool {
			approved.Add(1)
			return true
		},
		OnConflict:       func(ConflictType, ChangeEvent) ConflictAction { return ConflictAbort },
		OnProgress:       func(DiffProgress) {},
		OnSchemaMismatch: func(SchemaVersion, SchemaVersion, string) bool { return false },
		OnLog:            func(LogLevel, string) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client, err := NewPeer(clientDB, PeerConfig{
		OwnedTables:      map[string]bool{"t2": true},
		OnConflict:       func(ConflictType, ChangeEvent) ConflictAction { return ConflictAbort },
		OnProgress:       func(DiffProgress) {},
		OnSchemaMismatch: func(SchemaVersion, SchemaVersion, string) bool { return false },
		OnLog:            func(LogLevel, string) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	if err := SyncPeerHandshake(client, server); err != nil {
		t.Fatal(err)
	}
	if server.State() != PeerLive || client.State() != PeerLive {
		t.Fatalf("peers not live: server=%d client=%d", server.State(), client.State())
	}
	if approved.Load() == 0 {
		t.Fatal("approve-ownership trampoline did not run")
	}
}

func openFile(t *testing.T, path string) *Database {
	t.Helper()
	db, err := OpenDatabase(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}
