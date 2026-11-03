// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sqlpipe "github.com/marcelocantos/sqlpipe/go/sqlpipe"
)

// memTransport is an in-memory dual channel. Send and Recv honor ctx so
// RunPeer can join receivers after cancel. When joinHold is set, each
// receive returns only after release is closed, which is how the test
// sees a runner that returns before its receivers have left Recv.
type memTransport struct {
	streamIn  chan []byte
	streamOut chan []byte
	dgIn      chan []byte
	dgOut     chan []byte
	failSend  atomic.Bool
	joinHold  atomic.Bool
	release   chan struct{}
	exits     atomic.Int32
}

func newMemPair() (*memTransport, *memTransport) {
	ab := make(chan []byte, 64)
	ba := make(chan []byte, 64)
	dab := make(chan []byte, 64)
	dba := make(chan []byte, 64)
	release := make(chan struct{})
	return &memTransport{streamIn: ba, streamOut: ab, dgIn: dba, dgOut: dab, release: release},
		&memTransport{streamIn: ab, streamOut: ba, dgIn: dab, dgOut: dba, release: release}
}

func (m *memTransport) gate() {
	if !m.joinHold.Load() {
		return
	}
	m.exits.Add(1)
	<-m.release
}

func (m *memTransport) Send(ctx context.Context, data []byte) error {
	if m.failSend.Load() {
		return errors.New("transport down")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case m.streamOut <- append([]byte(nil), data...):
		return nil
	}
}

func (m *memTransport) Recv(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		m.gate()
		return nil, ctx.Err()
	case data := <-m.streamIn:
		return data, nil
	}
}

func (m *memTransport) SendDatagram(data []byte) error {
	if m.failSend.Load() {
		return errors.New("transport down")
	}
	m.dgOut <- append([]byte(nil), data...)
	return nil
}

func (m *memTransport) RecvDatagram(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		m.gate()
		return nil, ctx.Err()
	case data := <-m.dgIn:
		return data, nil
	}
}

// pausingLock is the owner lock shared by RunPeer and the test's writes.
// The sleep widens the window the race detector sees if a native peer
// call runs without this lock.
type pausingLock struct {
	sync.Mutex
}

func (p *pausingLock) Lock() {
	p.Mutex.Lock()
	time.Sleep(time.Millisecond)
}

func TestRunPeerSerializesJoinsAndReportsTransportFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	var runners sync.WaitGroup
	t.Cleanup(func() {
		cancel()
		runners.Wait()
	})

	dir := t.TempDir()
	schema := "CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT);" +
		"CREATE TABLE t2 (id INTEGER PRIMARY KEY, val TEXT)"
	sDB, err := sqlpipe.OpenDatabase(filepath.Join(dir, "server.sqlite"), schema)
	if err != nil {
		t.Fatal(err)
	}
	cDB, err := sqlpipe.OpenDatabase(filepath.Join(dir, "client.sqlite"), schema)
	if err != nil {
		t.Fatal(err)
	}

	server, err := sqlpipe.NewPeer(sDB, sqlpipe.PeerConfig{
		ApproveOwnership: func(map[string]bool) bool { return true },
	})
	if err != nil {
		t.Fatal(err)
	}
	client, err := sqlpipe.NewPeer(cDB, sqlpipe.PeerConfig{
		OwnedTables: map[string]bool{"t2": true},
	})
	if err != nil {
		t.Fatal(err)
	}

	sMem, cMem := newMemPair()
	sLink := NewLink(sMem)
	cLink := NewLink(cMem)
	sLock := &pausingLock{}
	cLock := &pausingLock{}
	sLink.OwnerLock = sLock
	cLink.OwnerLock = cLock
	sFlush := make(chan struct{}, 32)
	cFlush := make(chan struct{}, 32)

	var clientSubs atomic.Int32
	var serverSubs atomic.Int32
	clientHandler := func(hr sqlpipe.PeerHandleResult) error {
		cLock.Lock()
		defer cLock.Unlock()
		_ = client.State()
		if len(hr.Subscriptions) > 0 {
			clientSubs.Add(int32(len(hr.Subscriptions)))
		}
		return nil
	}
	serverHandler := func(hr sqlpipe.PeerHandleResult) error {
		sLock.Lock()
		defer sLock.Unlock()
		_ = server.State()
		if len(hr.Subscriptions) > 0 {
			serverSubs.Add(int32(len(hr.Subscriptions)))
		}
		return nil
	}

	clientDone := make(chan error, 1)
	serverDone := make(chan error, 1)
	runners.Add(2)
	go func() {
		defer runners.Done()
		clientDone <- cLink.RunPeer(ctx, client, true, cFlush, clientHandler)
	}()
	go func() {
		defer runners.Done()
		serverDone <- sLink.RunPeer(ctx, server, false, sFlush, serverHandler)
	}()

	// Flush is already queued while handshake messages are in flight.
	// RunPeer must take the same owner lock for that flush as for stream
	// and datagram handling.
	sFlush <- struct{}{}
	cFlush <- struct{}{}

	deadline := time.Now().Add(15 * time.Second)
	var cs, ss sqlpipe.PeerState
	for time.Now().Before(deadline) {
		cLock.Lock()
		cs = client.State()
		cLock.Unlock()
		sLock.Lock()
		ss = server.State()
		sLock.Unlock()
		if cs == sqlpipe.PeerLive && ss == sqlpipe.PeerLive {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if cs != sqlpipe.PeerLive || ss != sqlpipe.PeerLive {
		t.Fatalf("peers not live: client=%d server=%d", cs, ss)
	}
	cLock.Lock()
	_, err = client.Subscribe("SELECT id, val FROM t1 ORDER BY id")
	cLock.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	sLock.Lock()
	_, err = server.Subscribe("SELECT id, val FROM t2 ORDER BY id")
	sLock.Unlock()
	if err != nil {
		t.Fatal(err)
	}

	const n = 20
	writeErr := make(chan error, 2)
	go func() {
		for i := 1; i <= n; i++ {
			sLock.Lock()
			err := sDB.Exec(fmt.Sprintf("INSERT INTO t1 VALUES (%d, 's%d')", i, i))
			sLock.Unlock()
			if err != nil {
				writeErr <- err
				return
			}
			sFlush <- struct{}{}
		}
		writeErr <- nil
	}()
	go func() {
		for i := 1; i <= n; i++ {
			cLock.Lock()
			err := cDB.Exec(fmt.Sprintf("INSERT INTO t2 VALUES (%d, 'c%d')", i, i))
			cLock.Unlock()
			if err != nil {
				writeErr <- err
				return
			}
			cFlush <- struct{}{}
		}
		writeErr <- nil
	}()
	for i := 0; i < 2; i++ {
		if err := <-writeErr; err != nil {
			t.Fatal(err)
		}
	}

	waitRows := func(lock *pausingLock, db *sqlpipe.Database, sql string) {
		t.Helper()
		until := time.Now().Add(10 * time.Second)
		for time.Now().Before(until) {
			select {
			case err := <-clientDone:
				t.Fatalf("client RunPeer ended before rows arrived: %v", err)
			case err := <-serverDone:
				t.Fatalf("server RunPeer ended before rows arrived: %v", err)
			default:
			}
			lock.Lock()
			qr, qerr := db.Query(sql)
			lock.Unlock()
			if qerr == nil && len(qr.Rows) == n {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatalf("timed out waiting for %d rows from %s", n, sql)
	}
	waitRows(cLock, cDB, "SELECT id, val FROM t1 ORDER BY id")
	waitRows(sLock, sDB, "SELECT id, val FROM t2 ORDER BY id")
	if clientSubs.Load() == 0 || serverSubs.Load() == 0 {
		t.Fatalf("subscription callbacks did not run: client=%d server=%d", clientSubs.Load(), serverSubs.Load())
	}

	cMem.joinHold.Store(true)
	cMem.failSend.Store(true)
	sLock.Lock()
	err = sDB.Exec("INSERT INTO t1 VALUES (99, 'boom')")
	sLock.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	sFlush <- struct{}{}

	joined := time.After(5 * time.Second)
	for cMem.exits.Load() < 2 {
		select {
		case err = <-clientDone:
			t.Fatalf("RunPeer returned before receivers joined: %v (exits=%d)", err, cMem.exits.Load())
		case <-joined:
			t.Fatalf("receivers did not reach the join gate: exits=%d", cMem.exits.Load())
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
	select {
	case err = <-clientDone:
		t.Fatalf("RunPeer returned while receivers were still gated: %v", err)
	default:
	}
	close(cMem.release)
	select {
	case err = <-clientDone:
		if err == nil || err.Error() != "transport down" {
			t.Fatalf("RunPeer error = %v, want transport down", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunPeer did not return after receivers joined")
	}

	cancel()
	select {
	case <-serverDone:
	case <-time.After(5 * time.Second):
		t.Fatal("server RunPeer did not return after cancel")
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if err := cDB.Close(); err != nil {
		t.Fatal(err)
	}
	if err := sDB.Close(); err != nil {
		t.Fatal(err)
	}

	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	dir2 := t.TempDir()
	sDB2, err := sqlpipe.OpenDatabase(filepath.Join(dir2, "server.sqlite"), schema)
	if err != nil {
		t.Fatal(err)
	}
	cDB2, err := sqlpipe.OpenDatabase(filepath.Join(dir2, "client.sqlite"), schema)
	if err != nil {
		t.Fatal(err)
	}
	server2, err := sqlpipe.NewPeer(sDB2, sqlpipe.PeerConfig{
		ApproveOwnership: func(map[string]bool) bool { return true },
	})
	if err != nil {
		t.Fatal(err)
	}
	client2, err := sqlpipe.NewPeer(cDB2, sqlpipe.PeerConfig{
		OwnedTables: map[string]bool{"t2": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	sMem2, cMem2 := newMemPair()
	sMem2.joinHold.Store(true)
	cMem2.joinHold.Store(true)
	sLink2 := NewLink(sMem2)
	cLink2 := NewLink(cMem2)
	sLink2.OwnerLock = &pausingLock{}
	cLink2.OwnerLock = &pausingLock{}
	flush2 := make(chan struct{})
	done2 := make(chan error, 2)
	go func() { done2 <- cLink2.RunPeer(ctx2, client2, true, flush2, nil) }()
	go func() { done2 <- sLink2.RunPeer(ctx2, server2, false, flush2, nil) }()
	time.Sleep(50 * time.Millisecond)
	cancel2()
	joined = time.After(5 * time.Second)
	for sMem2.exits.Load() < 2 || cMem2.exits.Load() < 2 {
		select {
		case err := <-done2:
			t.Fatalf("cancel returned before receivers joined: %v", err)
		case <-joined:
			t.Fatalf("cancel receivers did not reach the join gate: server=%d client=%d", sMem2.exits.Load(), cMem2.exits.Load())
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
	close(sMem2.release)
	for i := 0; i < 2; i++ {
		select {
		case err := <-done2:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("cancel error = %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("RunPeer did not return on cancel")
		}
	}
	if err := client2.Close(); err != nil {
		t.Fatal(err)
	}
	if err := server2.Close(); err != nil {
		t.Fatal(err)
	}
	_ = cDB2.Close()
	_ = sDB2.Close()
}
