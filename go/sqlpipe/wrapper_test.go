// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package sqlpipe

import (
	"testing"
)

func TestMasterInitialState(t *testing.T) {
	db := openMemory(t)
	if err := db.Exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)"); err != nil {
		t.Fatal(err)
	}

	m, err := NewMaster(db, MasterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	if m.CurrentSeq() != 0 {
		t.Errorf("initial seq = %d, want 0", m.CurrentSeq())
	}
}

func TestMasterFlushNoChanges(t *testing.T) {
	db := openMemory(t)
	if err := db.Exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)"); err != nil {
		t.Fatal(err)
	}

	m, err := NewMaster(db, MasterConfig{})
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
	db := openMemory(t)
	if err := db.Exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)"); err != nil {
		t.Fatal(err)
	}

	m, err := NewMaster(db, MasterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	if err := db.Exec("INSERT INTO t1 VALUES (1, 'hello')"); err != nil {
		t.Fatal(err)
	}
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
	db := openMemory(t)
	if err := db.Exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)"); err != nil {
		t.Fatal(err)
	}

	m, err := NewMaster(db, MasterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	if err := db.Exec("INSERT INTO t1 VALUES (1, 'a')"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Flush(); err != nil {
		t.Fatal(err)
	}

	if err := db.Exec("INSERT INTO t1 VALUES (2, 'b')"); err != nil {
		t.Fatal(err)
	}
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
	db := openMemory(t)
	if err := db.Exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)"); err != nil {
		t.Fatal(err)
	}

	m, err := NewMaster(db, MasterConfig{})
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
	db := openMemory(t)
	if err := db.Exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)"); err != nil {
		t.Fatal(err)
	}

	m, err := NewMaster(db, MasterConfig{})
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
	db := openMemory(t)
	if err := db.Exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)"); err != nil {
		t.Fatal(err)
	}

	m, err := NewMaster(db, MasterConfig{})
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
	mDB := openMemory(t)
	rDB := openMemory(t)

	if err := mDB.Exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)"); err != nil {
		t.Fatal(err)
	}
	if err := rDB.Exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)"); err != nil {
		t.Fatal(err)
	}

	m, err := NewMaster(mDB, MasterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	r, err := NewReplica(rDB, ReplicaConfig{})
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
	if err := mDB.Exec("INSERT INTO t1 VALUES (1, 'hello')"); err != nil {
		t.Fatal(err)
	}
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
	qr, err := rDB.Query("SELECT val FROM t1 WHERE id=1")
	if err != nil {
		t.Fatal(err)
	}
	if len(qr.Rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(qr.Rows))
	}
	if val, ok := qr.Rows[0][0].(string); !ok || val != "hello" {
		t.Errorf("replica val = %v, want hello", qr.Rows[0][0])
	}
}

func TestSubscriptions(t *testing.T) {
	mDB := openMemory(t)
	rDB := openMemory(t)

	if err := mDB.Exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)"); err != nil {
		t.Fatal(err)
	}
	if err := rDB.Exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)"); err != nil {
		t.Fatal(err)
	}

	m, err := NewMaster(mDB, MasterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	r, err := NewReplica(rDB, ReplicaConfig{})
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
	if err := mDB.Exec("INSERT INTO t1 VALUES (1, 'a')"); err != nil {
		t.Fatal(err)
	}
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
	if err := mDB.Exec("INSERT INTO t1 VALUES (2, 'b')"); err != nil {
		t.Fatal(err)
	}
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
	mDB := openMemory(t)
	rDB := openMemory(t)

	if err := mDB.Exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)"); err != nil {
		t.Fatal(err)
	}
	if err := rDB.Exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)"); err != nil {
		t.Fatal(err)
	}

	m, err := NewMaster(mDB, MasterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	r, err := NewReplica(rDB, ReplicaConfig{})
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
	db := openMemory(t)
	if err := db.Exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)"); err != nil {
		t.Fatal(err)
	}

	callbackCalled := false
	m, err := NewMaster(db, MasterConfig{
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
	sDB := openMemory(t)
	cDB := openMemory(t)

	if err := sDB.Exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)"); err != nil {
		t.Fatal(err)
	}
	if err := sDB.Exec("CREATE TABLE t2 (id INTEGER PRIMARY KEY, val TEXT)"); err != nil {
		t.Fatal(err)
	}
	if err := cDB.Exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)"); err != nil {
		t.Fatal(err)
	}
	if err := cDB.Exec("CREATE TABLE t2 (id INTEGER PRIMARY KEY, val TEXT)"); err != nil {
		t.Fatal(err)
	}

	server, err := NewPeer(sDB, PeerConfig{
		ApproveOwnership: func(tables map[string]bool) bool { return true },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client, err := NewPeer(cDB, PeerConfig{
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
	if err := sDB.Exec("INSERT INTO t1 VALUES (1, 'from_server')"); err != nil {
		t.Fatal(err)
	}
	sMsgs, err := server.Flush()
	if err != nil {
		t.Fatal(err)
	}
	for _, msg := range sMsgs {
		if _, err := client.HandleMessage(msg); err != nil {
			t.Fatal(err)
		}
	}

	qr, err := cDB.Query("SELECT val FROM t1 WHERE id=1")
	if err != nil {
		t.Fatal(err)
	}
	if len(qr.Rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(qr.Rows))
	}
	if val, ok := qr.Rows[0][0].(string); !ok || val != "from_server" {
		t.Errorf("client t1 val = %v, want from_server", qr.Rows[0][0])
	}

	// Insert on client's t2, flush, apply on server.
	if err := cDB.Exec("INSERT INTO t2 VALUES (1, 'from_client')"); err != nil {
		t.Fatal(err)
	}
	cMsgs, err := client.Flush()
	if err != nil {
		t.Fatal(err)
	}
	for _, msg := range cMsgs {
		if _, err := server.HandleMessage(msg); err != nil {
			t.Fatal(err)
		}
	}

	qr, err = sDB.Query("SELECT val FROM t2 WHERE id=1")
	if err != nil {
		t.Fatal(err)
	}
	if len(qr.Rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(qr.Rows))
	}
	if val, ok := qr.Rows[0][0].(string); !ok || val != "from_client" {
		t.Errorf("server t2 val = %v, want from_client", qr.Rows[0][0])
	}
}

func TestDatabaseQuery(t *testing.T) {
	db := openMemory(t)
	if err := db.Exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)"); err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("INSERT INTO t1 VALUES (1, 'a'), (2, 'b')"); err != nil {
		t.Fatal(err)
	}

	qr, err := db.Query("SELECT id, val FROM t1 ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	if len(qr.Columns) != 2 {
		t.Fatalf("expected 2 columns, got %d", len(qr.Columns))
	}
	if qr.Columns[0] != "id" || qr.Columns[1] != "val" {
		t.Errorf("columns = %v, want [id val]", qr.Columns)
	}
	if len(qr.Rows) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(qr.Rows))
	}
	if qr.Rows[0][0] != int64(1) {
		t.Errorf("row[0][0] = %v, want 1", qr.Rows[0][0])
	}
	if qr.Rows[1][1] != "b" {
		t.Errorf("row[1][1] = %v, want b", qr.Rows[1][1])
	}
}

func TestMasterExecWithFlushCallback(t *testing.T) {
	db := openMemory(t)
	if err := db.Exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)"); err != nil {
		t.Fatal(err)
	}

	var flushedMsgs []Message
	m, err := NewMaster(db, MasterConfig{
		OnFlush: func(msgs []Message) {
			flushedMsgs = append(flushedMsgs, msgs...)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	if err := m.Exec("INSERT INTO t1 VALUES (1, 'auto')"); err != nil {
		t.Fatal(err)
	}

	if len(flushedMsgs) != 1 {
		t.Fatalf("expected 1 flushed message, got %d", len(flushedMsgs))
	}
	cs, ok := flushedMsgs[0].(ChangesetMsg)
	if !ok {
		t.Fatalf("expected ChangesetMsg, got %T", flushedMsgs[0])
	}
	if cs.Seq != 1 {
		t.Errorf("seq = %d, want 1", cs.Seq)
	}
}

func TestPeerSubscribe(t *testing.T) {
	sDB := openMemory(t)
	cDB := openMemory(t)

	for _, db := range []*Database{sDB, cDB} {
		if err := db.Exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)"); err != nil {
			t.Fatal(err)
		}
		if err := db.Exec("CREATE TABLE t2 (id INTEGER PRIMARY KEY, val TEXT)"); err != nil {
			t.Fatal(err)
		}
	}

	server, err := NewPeer(sDB, PeerConfig{
		ApproveOwnership: func(tables map[string]bool) bool { return true },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client, err := NewPeer(cDB, PeerConfig{
		OwnedTables: map[string]bool{"t2": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	if err := SyncPeerHandshake(client, server); err != nil {
		t.Fatal(err)
	}

	// Subscribe on client after handshake (t1 is owned by server).
	qr, err := client.Subscribe("SELECT * FROM t1 ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	if len(qr.Rows) != 0 {
		t.Errorf("expected 0 rows initially, got %d", len(qr.Rows))
	}

	// Insert on server's t1, flush, apply on client.
	if err := sDB.Exec("INSERT INTO t1 VALUES (1, 'x')"); err != nil {
		t.Fatal(err)
	}
	sMsgs, err := server.Flush()
	if err != nil {
		t.Fatal(err)
	}

	var gotSubs []QueryResult
	for _, msg := range sMsgs {
		hr, err := client.HandleMessage(msg)
		if err != nil {
			t.Fatal(err)
		}
		gotSubs = append(gotSubs, hr.Subscriptions...)
	}

	if len(gotSubs) != 1 {
		t.Fatalf("expected 1 subscription update, got %d", len(gotSubs))
	}
	if gotSubs[0].ID != qr.ID {
		t.Errorf("subscription id = %d, want %d", gotSubs[0].ID, qr.ID)
	}
	if len(gotSubs[0].Rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(gotSubs[0].Rows))
	}

	// Unsubscribe.
	if err := client.Unsubscribe(qr.ID); err != nil {
		t.Fatal(err)
	}

	// Another insert on server's t1 should not fire subscription.
	if err := sDB.Exec("INSERT INTO t1 VALUES (2, 'y')"); err != nil {
		t.Fatal(err)
	}
	sMsgs, err = server.Flush()
	if err != nil {
		t.Fatal(err)
	}
	for _, msg := range sMsgs {
		hr, err := client.HandleMessage(msg)
		if err != nil {
			t.Fatal(err)
		}
		if len(hr.Subscriptions) != 0 {
			t.Errorf("expected 0 subscription updates after unsubscribe, got %d", len(hr.Subscriptions))
		}
	}
}

func TestExecWithParams(t *testing.T) {
	db := openMemory(t)
	mustExec(t, db, "CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT, score REAL)")

	if err := db.Exec("INSERT INTO t VALUES (?, ?, ?)", 1, "alice", 95.5); err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("INSERT INTO t VALUES (?, ?, ?)", 2, "bob", 87.3); err != nil {
		t.Fatal(err)
	}

	qr, err := db.Query("SELECT name, score FROM t WHERE score > ?", 90.0)
	if err != nil {
		t.Fatal(err)
	}
	if len(qr.Rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(qr.Rows))
	}
	if qr.Rows[0][0] != "alice" {
		t.Errorf("expected alice, got %v", qr.Rows[0][0])
	}
}

func TestRows(t *testing.T) {
	db := openMemory(t)
	mustExec(t, db, "CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT, score REAL)")
	mustExec(t, db, "INSERT INTO t VALUES (1, 'alice', 95.5)")
	mustExec(t, db, "INSERT INTO t VALUES (2, 'bob', 87.3)")
	mustExec(t, db, "INSERT INTO t VALUES (3, 'carol', 92.1)")

	var names []string
	var scores []float64
	for row := range db.Rows("SELECT name, score FROM t WHERE score > ? ORDER BY name", 90.0) {
		if row.Err() != nil {
			t.Fatal(row.Err())
		}
		names = append(names, row.Text(0))
		scores = append(scores, row.Float64(1))
	}
	if len(names) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(names))
	}
	if names[0] != "alice" || names[1] != "carol" {
		t.Errorf("expected [alice carol], got %v", names)
	}
}

func TestRowsEarlyBreak(t *testing.T) {
	db := openMemory(t)
	mustExec(t, db, "CREATE TABLE t (id INTEGER PRIMARY KEY)")
	for i := range 100 {
		if err := db.Exec("INSERT INTO t VALUES (?)", i); err != nil {
			t.Fatal(err)
		}
	}

	count := 0
	for row := range db.Rows("SELECT id FROM t") {
		if row.Err() != nil {
			t.Fatal(row.Err())
		}
		count++
		if count == 5 {
			break // early exit — statement should be finalized
		}
	}
	if count != 5 {
		t.Errorf("expected 5, got %d", count)
	}

	// Verify the database is still usable after early break.
	qr, err := db.Query("SELECT count(*) FROM t")
	if err != nil {
		t.Fatal(err)
	}
	if qr.Rows[0][0] != int64(100) {
		t.Errorf("expected 100, got %v", qr.Rows[0][0])
	}
}

func TestTransaction(t *testing.T) {
	db := openMemory(t)
	mustExec(t, db, "CREATE TABLE t (id INTEGER PRIMARY KEY, val TEXT)")

	// Successful transaction.
	err := db.Tx(func(tx *Tx) error {
		if err := tx.Exec("INSERT INTO t VALUES (?, ?)", 1, "a"); err != nil {
			return err
		}
		return tx.Exec("INSERT INTO t VALUES (?, ?)", 2, "b")
	})
	if err != nil {
		t.Fatal(err)
	}
	qr, _ := db.Query("SELECT count(*) FROM t")
	if qr.Rows[0][0] != int64(2) {
		t.Errorf("expected 2 rows after commit, got %v", qr.Rows[0][0])
	}

	// Rolled-back transaction.
	err = db.Tx(func(tx *Tx) error {
		if err := tx.Exec("INSERT INTO t VALUES (?, ?)", 3, "c"); err != nil {
			return err
		}
		return &Error{Code: ErrSqlite, Msg: "simulated error"}
	})
	if err == nil {
		t.Fatal("expected error from rolled-back tx")
	}
	qr, _ = db.Query("SELECT count(*) FROM t")
	if qr.Rows[0][0] != int64(2) {
		t.Errorf("expected 2 rows after rollback, got %v", qr.Rows[0][0])
	}
}

func TestRowValueTypes(t *testing.T) {
	db := openMemory(t)
	mustExec(t, db, "CREATE TABLE t (i INTEGER, r REAL, s TEXT, b BLOB, n)")
	if err := db.Exec("INSERT INTO t VALUES (?, ?, ?, ?, ?)",
		42, 3.14, "hello", []byte{0xDE, 0xAD}, nil); err != nil {
		t.Fatal(err)
	}

	for row := range db.Rows("SELECT i, r, s, b, n FROM t") {
		if row.Err() != nil {
			t.Fatal(row.Err())
		}
		if row.Int64(0) != 42 {
			t.Errorf("int64: got %d", row.Int64(0))
		}
		if row.Float64(1) != 3.14 {
			t.Errorf("float64: got %f", row.Float64(1))
		}
		if row.Text(2) != "hello" {
			t.Errorf("text: got %s", row.Text(2))
		}
		blob := row.Blob(3)
		if len(blob) != 2 || blob[0] != 0xDE || blob[1] != 0xAD {
			t.Errorf("blob: got %v", blob)
		}
		if !row.IsNull(4) {
			t.Errorf("expected null at column 4")
		}
	}
}
