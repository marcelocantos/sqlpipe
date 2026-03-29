// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package transport_test

import (
	"context"
	"sync"
	"testing"
	"time"

	sqlpipe "github.com/marcelocantos/sqlpipe/go/sqlpipe"
	"github.com/marcelocantos/sqlpipe/go/sqlpipe/transport"
)

// mockTransport is a bidirectional in-memory Transport for testing.
// Two mockTransports are linked: what one sends, the other receives.
type mockTransport struct {
	streamIn  chan []byte
	streamOut chan []byte
	dgIn      chan []byte
	dgOut     chan []byte
}

func newMockPair() (*mockTransport, *mockTransport) {
	ab := make(chan []byte, 100)
	ba := make(chan []byte, 100)
	dab := make(chan []byte, 100)
	dba := make(chan []byte, 100)
	return &mockTransport{streamIn: ba, streamOut: ab, dgIn: dba, dgOut: dab},
		&mockTransport{streamIn: ab, streamOut: ba, dgIn: dab, dgOut: dba}
}

func (m *mockTransport) Send(_ context.Context, data []byte) error {
	m.streamOut <- data
	return nil
}

func (m *mockTransport) Recv(ctx context.Context) ([]byte, error) {
	select {
	case data := <-m.streamIn:
		return data, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (m *mockTransport) SendDatagram(data []byte) error {
	m.dgOut <- data
	return nil
}

func (m *mockTransport) RecvDatagram(ctx context.Context) ([]byte, error) {
	select {
	case data := <-m.dgIn:
		return data, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestLinkMasterReplica(t *testing.T) {
	// Create two databases with the same schema.
	mDB := openMemory(t)
	rDB := openMemory(t)
	for _, db := range []*sqlpipe.Database{mDB, rDB} {
		if err := db.Exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)"); err != nil {
			t.Fatal(err)
		}
	}

	logFn := func(level sqlpipe.LogLevel, msg string) {
		t.Logf("[%d] %s", level, msg)
	}
	master, err := sqlpipe.NewMaster(mDB, sqlpipe.MasterConfig{OnLog: logFn})
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()

	replica, err := sqlpipe.NewReplica(rDB, sqlpipe.ReplicaConfig{OnLog: logFn})
	if err != nil {
		t.Fatal(err)
	}
	defer replica.Close()

	// Create linked transports.
	mTransport, rTransport := newMockPair()
	mLink := transport.NewLink(mTransport)
	rLink := transport.NewLink(rTransport)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Collect replica changes.
	var mu sync.Mutex
	var changes []sqlpipe.ChangeEvent
	handler := func(hr sqlpipe.HandleResult) error {
		mu.Lock()
		defer mu.Unlock()
		changes = append(changes, hr.Changes...)
		return nil
	}

	// Run both sides.
	flushCh := make(chan struct{}, 10)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		mLink.RunMaster(ctx, master, flushCh)
	}()
	go func() {
		defer wg.Done()
		rLink.RunReplica(ctx, replica, handler)
	}()

	// Wait for handshake to complete — poll replica state.
	deadline := time.Now().Add(3 * time.Second)
	for replica.State() != sqlpipe.ReplicaLive && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if replica.State() != sqlpipe.ReplicaLive {
		t.Fatalf("replica didn't reach Live state, got %d", replica.State())
	}

	// Insert data on master and flush.
	if err := mDB.Exec("INSERT INTO t1 VALUES (1, 'hello')"); err != nil {
		t.Fatal(err)
	}
	flushCh <- struct{}{}

	// Wait for replication — poll for the row.
	for time.Now().Before(deadline) {
		result, err := rDB.Query("SELECT val FROM t1 WHERE id = 1")
		if err == nil && len(result.Rows) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Verify replica has the data.
	result, err := rDB.Query("SELECT val FROM t1 WHERE id = 1")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(result.Rows))
	}
	if result.Rows[0][0] != "hello" {
		t.Fatalf("expected 'hello', got %v", result.Rows[0][0])
	}

	// Verify changes were reported.
	mu.Lock()
	if len(changes) == 0 {
		t.Fatal("expected change events, got none")
	}
	mu.Unlock()

	cancel()
	wg.Wait()
}

func openMemory(t *testing.T) *sqlpipe.Database {
	t.Helper()
	db, err := sqlpipe.OpenDatabase(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}
