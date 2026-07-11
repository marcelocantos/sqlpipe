// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package transport_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sqlpipe "github.com/marcelocantos/sqlpipe/go/sqlpipe"
	"github.com/marcelocantos/sqlpipe/go/sqlpipe/transport"
)

// mockTransport is a bidirectional in-memory Transport for testing.
// Two mockTransports are linked: what one sends, the other receives.
// The stream channel is always reliable; datagrams may be dropped when
// dropDatagram is set (see dropEveryNth / dropFirstN).
type mockTransport struct {
	streamIn  chan []byte
	streamOut chan []byte
	dgIn      chan []byte
	dgOut     chan []byte

	// Datagram loss controls (outbound only). Zero means deliver all.
	dropEveryNth int // drop every Nth outbound datagram (N>=2)
	dropFirstN   int // drop the first N outbound datagrams

	mu          sync.Mutex
	dgSent      int
	dgDropped   int
	dgDelivered int
	streamSent  int
}

func newMockPair() (*mockTransport, *mockTransport) {
	ab := make(chan []byte, 100)
	ba := make(chan []byte, 100)
	dab := make(chan []byte, 100)
	dba := make(chan []byte, 100)
	return &mockTransport{streamIn: ba, streamOut: ab, dgIn: dba, dgOut: dab},
		&mockTransport{streamIn: ab, streamOut: ba, dgIn: dab, dgOut: dba}
}

// newLossyPair returns a linked pair where both sides drop outbound
// datagrams according to the same policy. Stream traffic is never dropped.
func newLossyPair(dropFirstN, dropEveryNth int) (*mockTransport, *mockTransport) {
	a, b := newMockPair()
	a.dropFirstN = dropFirstN
	a.dropEveryNth = dropEveryNth
	b.dropFirstN = dropFirstN
	b.dropEveryNth = dropEveryNth
	return a, b
}

func (m *mockTransport) Send(_ context.Context, data []byte) error {
	m.mu.Lock()
	m.streamSent++
	m.mu.Unlock()
	m.streamOut <- append([]byte(nil), data...)
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
	m.mu.Lock()
	m.dgSent++
	n := m.dgSent
	drop := false
	if m.dropFirstN > 0 && n <= m.dropFirstN {
		drop = true
	}
	if m.dropEveryNth >= 2 && n%m.dropEveryNth == 0 {
		drop = true
	}
	if drop {
		m.dgDropped++
		m.mu.Unlock()
		return nil // silent loss
	}
	m.dgDelivered++
	m.mu.Unlock()
	m.dgOut <- append([]byte(nil), data...)
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

func (m *mockTransport) stats() (streamSent, dgSent, dgDropped, dgDelivered int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.streamSent, m.dgSent, m.dgDropped, m.dgDelivered
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

func setupMasterReplica(t *testing.T) (*sqlpipe.Database, *sqlpipe.Database, *sqlpipe.Master, *sqlpipe.Replica) {
	t.Helper()
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
	t.Cleanup(func() { master.Close() })
	replica, err := sqlpipe.NewReplica(rDB, sqlpipe.ReplicaConfig{OnLog: logFn})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { replica.Close() })
	return mDB, rDB, master, replica
}

func waitLive(t *testing.T, replica *sqlpipe.Replica, deadline time.Time) {
	t.Helper()
	for replica.State() != sqlpipe.ReplicaLive && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if replica.State() != sqlpipe.ReplicaLive {
		t.Fatalf("replica didn't reach Live state, got %d", replica.State())
	}
}

func waitRow(t *testing.T, rDB *sqlpipe.Database, want string, deadline time.Time) {
	t.Helper()
	for time.Now().Before(deadline) {
		result, err := rDB.Query("SELECT val FROM t1 WHERE id = 1")
		if err == nil && len(result.Rows) > 0 && result.Rows[0][0] == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	result, err := rDB.Query("SELECT val FROM t1 WHERE id = 1")
	if err != nil {
		t.Fatal(err)
	}
	t.Fatalf("expected row val=%q, got %v", want, result.Rows)
}

func TestLinkMasterReplica(t *testing.T) {
	mDB, rDB, master, replica := setupMasterReplica(t)
	mTransport, rTransport := newMockPair()
	mLink := transport.NewLink(mTransport)
	rLink := transport.NewLink(rTransport)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var mu sync.Mutex
	var changes []sqlpipe.ChangeEvent
	handler := func(hr sqlpipe.HandleResult) error {
		mu.Lock()
		defer mu.Unlock()
		changes = append(changes, hr.Changes...)
		return nil
	}

	flushCh := make(chan struct{}, 10)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_ = mLink.RunMaster(ctx, master, flushCh)
	}()
	go func() {
		defer wg.Done()
		_ = rLink.RunReplica(ctx, replica, handler)
	}()

	deadline := time.Now().Add(3 * time.Second)
	waitLive(t, replica, deadline)

	if err := mDB.Exec("INSERT INTO t1 VALUES (1, 'hello')"); err != nil {
		t.Fatal(err)
	}
	flushCh <- struct{}{}
	waitRow(t, rDB, "hello", deadline)

	mu.Lock()
	if len(changes) == 0 {
		t.Fatal("expected change events, got none")
	}
	mu.Unlock()

	// Converge probes and responses use the datagram path.
	_, mDg, _, _ := mTransport.stats()
	_, rDg, _, _ := rTransport.stats()
	if mDg == 0 && rDg == 0 {
		t.Fatal("expected BestEffort traffic on datagram channel")
	}

	cancel()
	wg.Wait()
}

// TestLinkMasterReplicaLossyDatagrams drops the first several outbound
// datagrams on both sides (BestEffort probes/responses). Re-converge must
// still reach Live and live-stream a row over the reliable channel.
func TestLinkMasterReplicaLossyDatagrams(t *testing.T) {
	mDB, rDB, master, replica := setupMasterReplica(t)

	// Drop first 4 outbound datagrams on each side — enough to lose the
	// initial BucketHashes / NeedBuckets / RowHashes exchange at least once.
	mTransport, rTransport := newLossyPair(4, 0)
	mLink := transport.NewLink(mTransport)
	rLink := transport.NewLink(rTransport)
	rLink.ReConvergeInterval = 20 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	flushCh := make(chan struct{}, 10)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_ = mLink.RunMaster(ctx, master, flushCh)
	}()
	go func() {
		defer wg.Done()
		_ = rLink.RunReplica(ctx, replica, nil)
	}()

	deadline := time.Now().Add(8 * time.Second)
	waitLive(t, replica, deadline)

	_, _, mDrop, mDeliv := mTransport.stats()
	_, _, rDrop, rDeliv := rTransport.stats()
	if mDrop+rDrop == 0 {
		t.Fatal("lossy pair never dropped a datagram; test is vacuous")
	}
	if mDeliv+rDeliv == 0 {
		t.Fatal("no datagrams delivered after drops; re-converge failed")
	}
	t.Logf("datagrams master drop=%d deliv=%d; replica drop=%d deliv=%d",
		mDrop, mDeliv, rDrop, rDeliv)

	if err := mDB.Exec("INSERT INTO t1 VALUES (1, 'lossy-ok')"); err != nil {
		t.Fatal(err)
	}
	flushCh <- struct{}{}
	waitRow(t, rDB, "lossy-ok", deadline)

	// Live changesets must use the reliable stream, never the lossy path.
	mStream, _, _, _ := mTransport.stats()
	if mStream == 0 {
		t.Fatal("expected Reliable stream traffic for DiffReady/Changeset/Ack")
	}

	cancel()
	wg.Wait()
}

// TestLinkMasterReplicaDropEveryOtherDatagram stresses re-converge under
// sustained ~50% BestEffort loss after the first datagram.
func TestLinkMasterReplicaDropEveryOtherDatagram(t *testing.T) {
	mDB, rDB, master, replica := setupMasterReplica(t)
	mTransport, rTransport := newLossyPair(0, 2) // drop every 2nd outbound dg
	mLink := transport.NewLink(mTransport)
	rLink := transport.NewLink(rTransport)
	rLink.ReConvergeInterval = 15 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	flushCh := make(chan struct{}, 10)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_ = mLink.RunMaster(ctx, master, flushCh)
	}()
	go func() {
		defer wg.Done()
		_ = rLink.RunReplica(ctx, replica, nil)
	}()

	deadline := time.Now().Add(8 * time.Second)
	waitLive(t, replica, deadline)

	_, _, mDrop, _ := mTransport.stats()
	_, _, rDrop, _ := rTransport.stats()
	if mDrop+rDrop == 0 {
		t.Fatal("expected some datagram drops with dropEveryNth=2")
	}

	if err := mDB.Exec("INSERT INTO t1 VALUES (1, 'half-drop')"); err != nil {
		t.Fatal(err)
	}
	flushCh <- struct{}{}
	waitRow(t, rDB, "half-drop", deadline)

	cancel()
	wg.Wait()
}

// TestBestEffortNeverOnStream asserts that a Converge probe is sent as a
// datagram, not on the reliable stream.
func TestBestEffortNeverOnStream(t *testing.T) {
	_, _, _, replica := setupMasterReplica(t)

	streamSends := atomic.Int32{}
	dgSends := atomic.Int32{}

	// One-sided stub: only observe replica outbound routing.
	stub := &countTransport{
		streamSends: &streamSends,
		dgSends:     &dgSends,
		// Block recvs so RunReplica doesn't spin after the probe.
		blockRecv: make(chan struct{}),
	}
	link := transport.NewLink(stub)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errc := make(chan error, 1)
	go func() { errc <- link.RunReplica(ctx, replica, nil) }()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && dgSends.Load() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if dgSends.Load() == 0 {
		t.Fatal("Converge probe was not sent as a datagram")
	}
	if streamSends.Load() != 0 {
		t.Fatalf("BestEffort probe used stream: streamSends=%d", streamSends.Load())
	}

	cancel()
	<-errc
}

// countTransport records which channel send used; recvs block until ctx done.
type countTransport struct {
	streamSends *atomic.Int32
	dgSends     *atomic.Int32
	blockRecv   chan struct{}
}

func (c *countTransport) Send(ctx context.Context, _ []byte) error {
	c.streamSends.Add(1)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.blockRecv:
		return context.Canceled
	}
}

func (c *countTransport) Recv(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.blockRecv:
		return nil, context.Canceled
	}
}

func (c *countTransport) SendDatagram(_ []byte) error {
	c.dgSends.Add(1)
	return nil
}

func (c *countTransport) RecvDatagram(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.blockRecv:
		return nil, context.Canceled
	}
}
