// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package sqlpipe

import (
	"testing"
)

func TestMasterInitialState(t *testing.T) {
	_, conn := openMemory(t)
	mustExec(t, conn, "CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)")

	m, err := NewMaster(conn, MasterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	if m.CurrentSeq() != 0 {
		t.Errorf("initial seq = %d, want 0", m.CurrentSeq())
	}
}

func TestMasterFlushNoChanges(t *testing.T) {
	_, conn := openMemory(t)
	mustExec(t, conn, "CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)")

	m, err := NewMaster(conn, MasterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	msgs, err := m.Flush()
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 0 {
		t.Errorf("expected 0 messages, got %d", len(msgs))
	}
}

func TestMasterFlushAfterInsert(t *testing.T) {
	_, conn := openMemory(t)
	mustExec(t, conn, "CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)")

	m, err := NewMaster(conn, MasterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	mustExec(t, conn, "INSERT INTO t1 VALUES (1, 'hello')")
	msgs, err := m.Flush()
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	cs, ok := msgs[0].(ChangesetMsg)
	if !ok {
		t.Fatalf("expected ChangesetMsg, got %T", msgs[0])
	}
	if cs.Seq != 1 {
		t.Errorf("seq = %d, want 1", cs.Seq)
	}
	if m.CurrentSeq() != 1 {
		t.Errorf("current_seq = %d, want 1", m.CurrentSeq())
	}
}

func TestMasterMultipleFlushes(t *testing.T) {
	_, conn := openMemory(t)
	mustExec(t, conn, "CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)")

	m, err := NewMaster(conn, MasterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	mustExec(t, conn, "INSERT INTO t1 VALUES (1, 'a')")
	if _, err := m.Flush(); err != nil {
		t.Fatal(err)
	}

	mustExec(t, conn, "INSERT INTO t1 VALUES (2, 'b')")
	msgs, err := m.Flush()
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	cs := msgs[0].(ChangesetMsg)
	if cs.Seq != 2 {
		t.Errorf("seq = %d, want 2", cs.Seq)
	}
}

func TestMasterHandleHello(t *testing.T) {
	_, conn := openMemory(t)
	mustExec(t, conn, "CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)")

	m, err := NewMaster(conn, MasterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	sv := m.SchemaVersion()
	msgs, err := m.HandleMessage(HelloMsg{
		ProtocolVersion: ProtocolVersion,
		SchemaVersion:   sv,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	reply, ok := msgs[0].(HelloMsg)
	if !ok {
		t.Fatalf("expected HelloMsg, got %T", msgs[0])
	}
	if reply.SchemaVersion != sv {
		t.Errorf("reply schema_version = %d, want %d", reply.SchemaVersion, sv)
	}
}

func TestMasterSchemaMismatch(t *testing.T) {
	_, conn := openMemory(t)
	mustExec(t, conn, "CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)")

	m, err := NewMaster(conn, MasterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	msgs, err := m.HandleMessage(HelloMsg{
		ProtocolVersion: ProtocolVersion,
		SchemaVersion:   99999,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	errMsg, ok := msgs[0].(ErrorMsg)
	if !ok {
		t.Fatalf("expected ErrorMsg, got %T", msgs[0])
	}
	if errMsg.Code != ErrSchemaMismatch {
		t.Errorf("error code = %d, want %d", errMsg.Code, ErrSchemaMismatch)
	}
}

func TestMasterProtocolVersionMismatch(t *testing.T) {
	_, conn := openMemory(t)
	mustExec(t, conn, "CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)")

	m, err := NewMaster(conn, MasterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	msgs, err := m.HandleMessage(HelloMsg{
		ProtocolVersion: 999,
		SchemaVersion:   0,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	if _, ok := msgs[0].(ErrorMsg); !ok {
		t.Fatalf("expected ErrorMsg, got %T", msgs[0])
	}
}

func TestLiveStreamingEndToEnd(t *testing.T) {
	_, mConn := openMemory(t)
	_, rConn := openMemory(t)

	mustExec(t, mConn, "CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)")
	mustExec(t, rConn, "CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)")

	m, err := NewMaster(mConn, MasterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	r, err := NewReplica(rConn, ReplicaConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	if err := SyncHandshake(m, r); err != nil {
		t.Fatal(err)
	}

	if r.State() != ReplicaLive {
		t.Fatalf("replica state = %d, want Live (%d)", r.State(), ReplicaLive)
	}

	// Insert on master, flush, apply on replica.
	mustExec(t, mConn, "INSERT INTO t1 VALUES (1, 'hello')")
	msgs, err := m.Flush()
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}

	hr, err := r.HandleMessage(msgs[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(hr.Changes) != 1 {
		t.Fatalf("expected 1 change, got %d", len(hr.Changes))
	}
	if hr.Changes[0].Table != "t1" {
		t.Errorf("change table = %q, want t1", hr.Changes[0].Table)
	}
	if hr.Changes[0].Op != OpInsert {
		t.Errorf("change op = %d, want Insert", hr.Changes[0].Op)
	}

	// Verify data on replica.
	var val string
	err = rConn.QueryRowContext(t.Context(), "SELECT val FROM t1 WHERE id=1").Scan(&val)
	if err != nil {
		t.Fatal(err)
	}
	if val != "hello" {
		t.Errorf("replica val = %q, want hello", val)
	}
}

func TestSubscriptions(t *testing.T) {
	_, mConn := openMemory(t)
	_, rConn := openMemory(t)

	mustExec(t, mConn, "CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)")
	mustExec(t, rConn, "CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)")

	m, err := NewMaster(mConn, MasterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	r, err := NewReplica(rConn, ReplicaConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	// Subscribe before handshake.
	qr, err := r.Subscribe("SELECT * FROM t1 ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	if len(qr.Rows) != 0 {
		t.Errorf("expected 0 rows, got %d", len(qr.Rows))
	}

	if err := SyncHandshake(m, r); err != nil {
		t.Fatal(err)
	}

	// Insert and flush.
	mustExec(t, mConn, "INSERT INTO t1 VALUES (1, 'a')")
	msgs, err := m.Flush()
	if err != nil {
		t.Fatal(err)
	}
	hr, err := r.HandleMessage(msgs[0])
	if err != nil {
		t.Fatal(err)
	}

	// Subscription should fire.
	if len(hr.Subscriptions) != 1 {
		t.Fatalf("expected 1 subscription update, got %d", len(hr.Subscriptions))
	}
	sub := hr.Subscriptions[0]
	if sub.ID != qr.ID {
		t.Errorf("subscription id = %d, want %d", sub.ID, qr.ID)
	}
	if len(sub.Rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(sub.Rows))
	}

	// Unsubscribe.
	if err := r.Unsubscribe(qr.ID); err != nil {
		t.Fatal(err)
	}

	// Another insert should not trigger subscription.
	mustExec(t, mConn, "INSERT INTO t1 VALUES (2, 'b')")
	msgs, err = m.Flush()
	if err != nil {
		t.Fatal(err)
	}
	hr, err = r.HandleMessage(msgs[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(hr.Subscriptions) != 0 {
		t.Errorf("expected 0 subscription updates after unsubscribe, got %d", len(hr.Subscriptions))
	}
}

func TestReplicaReset(t *testing.T) {
	_, mConn := openMemory(t)
	_, rConn := openMemory(t)

	mustExec(t, mConn, "CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)")
	mustExec(t, rConn, "CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)")

	m, err := NewMaster(mConn, MasterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	r, err := NewReplica(rConn, ReplicaConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	if r.State() != ReplicaInit {
		t.Fatalf("state = %d, want Init", r.State())
	}

	if err := SyncHandshake(m, r); err != nil {
		t.Fatal(err)
	}
	if r.State() != ReplicaLive {
		t.Fatalf("state = %d, want Live", r.State())
	}

	// Reset.
	r.Reset()
	if r.State() != ReplicaInit {
		t.Errorf("state after reset = %d, want Init", r.State())
	}
}

func TestSchemaMismatchCallback(t *testing.T) {
	_, conn := openMemory(t)
	mustExec(t, conn, "CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)")

	callbackCalled := false
	m, err := NewMaster(conn, MasterConfig{
		OnSchemaMismatch: func(remoteSV, localSV SchemaVersion, remoteSQL string) bool {
			callbackCalled = true
			return false
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	msgs, err := m.HandleMessage(HelloMsg{
		ProtocolVersion: ProtocolVersion,
		SchemaVersion:   99999,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !callbackCalled {
		t.Error("expected OnSchemaMismatch callback to be called")
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	if _, ok := msgs[0].(ErrorMsg); !ok {
		t.Fatalf("expected ErrorMsg, got %T", msgs[0])
	}
}

func TestPeerBidirectional(t *testing.T) {
	_, sConn := openMemory(t)
	_, cConn := openMemory(t)

	mustExec(t, sConn, "CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)")
	mustExec(t, sConn, "CREATE TABLE t2 (id INTEGER PRIMARY KEY, val TEXT)")
	mustExec(t, cConn, "CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)")
	mustExec(t, cConn, "CREATE TABLE t2 (id INTEGER PRIMARY KEY, val TEXT)")

	server, err := NewPeer(sConn, PeerConfig{
		ApproveOwnership: func(tables map[string]bool) bool { return true },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client, err := NewPeer(cConn, PeerConfig{
		OwnedTables: map[string]bool{"t2": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	if err := SyncPeerHandshake(client, server); err != nil {
		t.Fatal(err)
	}
	if server.State() != PeerLive || client.State() != PeerLive {
		t.Fatalf("peers not live: server=%d, client=%d", server.State(), client.State())
	}

	// Client owns t2; server owns t1.
	clientOwned := client.OwnedTables()
	if !clientOwned["t2"] {
		t.Errorf("client should own t2, owns: %v", clientOwned)
	}
	serverOwned := server.OwnedTables()
	if !serverOwned["t1"] {
		t.Errorf("server should own t1, owns: %v", serverOwned)
	}

	// Insert on server's t1, flush, apply on client.
	mustExec(t, sConn, "INSERT INTO t1 VALUES (1, 'from_server')")
	sMsgs, err := server.Flush()
	if err != nil {
		t.Fatal(err)
	}
	for _, msg := range sMsgs {
		if _, err := client.HandleMessage(msg); err != nil {
			t.Fatal(err)
		}
	}

	var val string
	err = cConn.QueryRowContext(t.Context(), "SELECT val FROM t1 WHERE id=1").Scan(&val)
	if err != nil {
		t.Fatal(err)
	}
	if val != "from_server" {
		t.Errorf("client t1 val = %q, want from_server", val)
	}

	// Insert on client's t2, flush, apply on server.
	mustExec(t, cConn, "INSERT INTO t2 VALUES (1, 'from_client')")
	cMsgs, err := client.Flush()
	if err != nil {
		t.Fatal(err)
	}
	for _, msg := range cMsgs {
		if _, err := server.HandleMessage(msg); err != nil {
			t.Fatal(err)
		}
	}

	err = sConn.QueryRowContext(t.Context(), "SELECT val FROM t2 WHERE id=1").Scan(&val)
	if err != nil {
		t.Fatal(err)
	}
	if val != "from_client" {
		t.Errorf("server t2 val = %q, want from_client", val)
	}
}
