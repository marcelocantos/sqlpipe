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
// RunPeer can join receivers after cancel.
type memTransport struct {
	streamIn  chan []byte
	streamOut chan []byte
	dgIn      chan []byte
	dgOut     chan []byte
	failSend  atomic.Bool
}

func newMemPair() (*memTransport, *memTransport) {
	ab := make(chan []byte, 64)
	ba := make(chan []byte, 64)
	dab := make(chan []byte, 64)
	dba := make(chan []byte, 64)
	return &memTransport{streamIn: ba, streamOut: ab, dgIn: dba, dgOut: dab},
		&memTransport{streamIn: ab, streamOut: ba, dgIn: dab, dgOut: dba}
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
		return nil, ctx.Err()
	case data := <-m.dgIn:
		return data, nil
	}
}

type peerDepth struct {
	depth atomic.Int32
	max   atomic.Int32
}

func TestRunPeerSerializesJoinsAndReportsTransportFailure(t *testing.T) {
	depths := &sync.Map{}
	probe := func(p *sqlpipe.Peer) *peerDepth {
		v, _ := depths.LoadOrStore(p, &peerDepth{})
		return v.(*peerDepth)
	}
	nativeEnter = func(p *sqlpipe.Peer) {
		d := probe(p)
		n := d.depth.Add(1)
		for {
			old := d.max.Load()
			if n <= old || d.max.CompareAndSwap(old, n) {
				break
			}
		}
		// Widen the window so a missing owner lock overlaps stream,
		// datagram, and flush on this peer.
		time.Sleep(time.Millisecond)
	}
	nativeLeave = func(p *sqlpipe.Peer) {
		probe(p).depth.Add(-1)
	}
	var earlyExits atomic.Int32
	receiverExit = func() { earlyExits.Add(1) }

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	var runners sync.WaitGroup
	t.Cleanup(func() {
		cancel()
		runners.Wait()
		nativeEnter = func(*sqlpipe.Peer) {}
		nativeLeave = func(*sqlpipe.Peer) {}
		receiverExit = func() {}
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
	sFlush := make(chan struct{}, 32)
	cFlush := make(chan struct{}, 32)

	var clientSubs atomic.Int32
	var serverSubs atomic.Int32
	clientHandler := func(hr sqlpipe.PeerHandleResult) error {
		cLink.Lock()
		defer cLink.Unlock()
		_ = client.State()
		if len(hr.Subscriptions) > 0 {
			clientSubs.Add(int32(len(hr.Subscriptions)))
		}
		return nil
	}
	serverHandler := func(hr sqlpipe.PeerHandleResult) error {
		sLink.Lock()
		defer sLink.Unlock()
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
	for time.Now().Before(deadline) {
		cLink.Lock()
		cs := client.State()
		cLink.Unlock()
		sLink.Lock()
		ss := server.State()
		sLink.Unlock()
		if cs == sqlpipe.PeerLive && ss == sqlpipe.PeerLive {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	cLink.Lock()
	cs := client.State()
	cLink.Unlock()
	sLink.Lock()
	ss := server.State()
	sLink.Unlock()
	if cs != sqlpipe.PeerLive || ss != sqlpipe.PeerLive {
		t.Fatalf("peers not live: client=%d server=%d", cs, ss)
	}
	cLink.Lock()
	_, err = client.Subscribe("SELECT id, val FROM t1 ORDER BY id")
	cLink.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	sLink.Lock()
	_, err = server.Subscribe("SELECT id, val FROM t2 ORDER BY id")
	sLink.Unlock()
	if err != nil {
		t.Fatal(err)
	}

	const n = 20
	writeErr := make(chan error, 2)
	go func() {
		for i := 1; i <= n; i++ {
			sLink.Lock()
			err := sDB.Exec(fmt.Sprintf("INSERT INTO t1 VALUES (%d, 's%d')", i, i))
			sLink.Unlock()
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
			cLink.Lock()
			err := cDB.Exec(fmt.Sprintf("INSERT INTO t2 VALUES (%d, 'c%d')", i, i))
			cLink.Unlock()
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

	waitRows := func(link *Link, db *sqlpipe.Database, sql string) {
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
			link.Lock()
			qr, qerr := db.Query(sql)
			link.Unlock()
			if qerr == nil && len(qr.Rows) == n {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatalf("timed out waiting for %d rows from %s", n, sql)
	}
	waitRows(cLink, cDB, "SELECT id, val FROM t1 ORDER BY id")
	waitRows(sLink, sDB, "SELECT id, val FROM t2 ORDER BY id")
	if clientSubs.Load() == 0 || serverSubs.Load() == 0 {
		t.Fatalf("subscription callbacks did not run: client=%d server=%d", clientSubs.Load(), serverSubs.Load())
	}
	if earlyExits.Load() != 0 {
		t.Fatalf("a RunPeer receiver exited before shutdown: %d", earlyExits.Load())
	}

	var exits atomic.Int32
	receiverExit = func() {
		time.Sleep(200 * time.Millisecond)
		exits.Add(1)
	}
	cMem.failSend.Store(true)
	sLink.Lock()
	err = sDB.Exec("INSERT INTO t1 VALUES (99, 'boom')")
	sLink.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	sFlush <- struct{}{}

	select {
	case err = <-clientDone:
		if err == nil || err.Error() != "transport down" {
			t.Fatalf("RunPeer error = %v, want transport down", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunPeer did not return after the transport error")
	}
	if got := exits.Load(); got < 3 {
		t.Fatalf("RunPeer returned before receivers joined: exits=%d", got)
	}

	depths.Range(func(_, v any) bool {
		d := v.(*peerDepth)
		if d.max.Load() < 1 {
			t.Fatal("native peer calls were not observed")
		}
		if d.max.Load() > 1 {
			t.Fatalf("native peer calls overlapped, depth %d", d.max.Load())
		}
		return true
	})

	cancel()
	select {
	case <-serverDone:
	case <-time.After(5 * time.Second):
		t.Fatal("server RunPeer did not return after cancel")
	}
	// Close only after both runners have joined. Closing earlier races
	// the native peer.
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

	// Cancellation joins receivers before return.
	exits.Store(0)
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
	sLink2 := NewLink(sMem2)
	cLink2 := NewLink(cMem2)
	flush2 := make(chan struct{})
	done2 := make(chan error, 2)
	go func() { done2 <- cLink2.RunPeer(ctx2, client2, true, flush2, nil) }()
	go func() { done2 <- sLink2.RunPeer(ctx2, server2, false, flush2, nil) }()
	time.Sleep(50 * time.Millisecond)
	cancel2()
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
	if got := exits.Load(); got < 6 {
		t.Fatalf("cancel returned before receivers joined: exits=%d", got)
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
