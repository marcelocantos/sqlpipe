// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package transport_test

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sqlpipe "github.com/marcelocantos/sqlpipe/go/sqlpipe"
	"github.com/marcelocantos/sqlpipe/go/sqlpipe/transport"
)

// These peer lifecycle tests model the intended Unix adapter: both delivery
// hints use one ordered reliable channel. RunPeer still routes BestEffort via
// SendDatagram. Independent-channel peer reorder recovery is separate T37;
// the existing lossy Master/Replica tests remain unchanged.
type orderedTransport struct {
	*mockTransport
	ctx context.Context
}

func newOrderedPair(ctx context.Context) (*orderedTransport, *orderedTransport) {
	a, b := newMockPair()
	return &orderedTransport{a, ctx}, &orderedTransport{b, ctx}
}
func (o *orderedTransport) Send(ctx context.Context, data []byte) error {
	select {
	case o.streamOut <- append([]byte(nil), data...):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (o *orderedTransport) SendDatagram(data []byte) error { return o.Send(o.ctx, data) }
func (o *orderedTransport) RecvDatagram(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

type filePeer struct {
	db   *sqlpipe.Database
	peer *sqlpipe.Peer
	mu   sync.Mutex
}

func openFilePeer(t *testing.T, client bool) *filePeer {
	t.Helper()
	db, err := sqlpipe.OpenDatabase(filepath.Join(t.TempDir(), "peer.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("CREATE TABLE c_rows(id INTEGER PRIMARY KEY, val TEXT); CREATE TABLE s_rows(id INTEGER PRIMARY KEY, val TEXT)"); err != nil {
		t.Fatal(err)
	}
	cfg := sqlpipe.PeerConfig{ApproveOwnership: func(tables map[string]bool) bool { return len(tables) == 1 && tables["c_rows"] }}
	if client {
		cfg = sqlpipe.PeerConfig{OwnedTables: map[string]bool{"c_rows": true}}
	}
	p, err := sqlpipe.NewPeer(db, cfg)
	if err != nil {
		t.Fatal(err)
	}
	f := &filePeer{db: db, peer: p}
	t.Cleanup(func() { f.mu.Lock(); defer f.mu.Unlock(); _ = f.peer.Close(); _ = db.Close() })
	return f
}
func awaitPeer(t *testing.T, what string, condition func() bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for !condition() {
		select {
		case <-ctx.Done():
			t.Fatalf("waiting for %s: %v", what, ctx.Err())
		case <-tick.C:
		}
	}
}
func (f *filePeer) live() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.peer.State() == sqlpipe.PeerLive
}
func (f *filePeer) count(t *testing.T, table string) int64 {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	// Both identifiers are fixed test-owned table names.
	q, err := f.db.Query("SELECT COUNT(id) FROM " + table)
	if err != nil {
		t.Fatal(err)
	}
	return q.Rows[0][0].(int64)
}
func startPeer(t *testing.T, ctx context.Context, f *filePeer, tr transport.Transport, client bool, flush <-chan struct{}, h transport.PeerHandler) <-chan error {
	t.Helper()
	link := transport.NewLink(tr)
	link.OwnerLock = &f.mu
	done := make(chan error, 1)
	go func() { done <- link.RunPeer(ctx, f.peer, client, flush, h) }()
	return done
}
func TestRunPeerFileOwnersAndSubscriptionCallbacks(t *testing.T) {
	c, s := openFilePeer(t, true), openFilePeer(t, false)
	cf, sf := make(chan struct{}, 1), make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(t.Context())
	a, b := newOrderedPair(ctx)
	var subscriptions atomic.Int32
	handler := func(hr sqlpipe.PeerHandleResult) error {
		// Reenter the owner lock: the callback cannot run under that lock.
		c.mu.Lock()
		defer c.mu.Unlock()
		if _, err := c.db.Query("SELECT COUNT(id) FROM s_rows"); err != nil {
			return err
		}
		subscriptions.Add(int32(len(hr.Subscriptions)))
		return nil
	}
	cd := startPeer(t, ctx, c, a, true, cf, handler)
	sd := startPeer(t, ctx, s, b, false, sf, nil)
	t.Cleanup(func() { cancel(); <-cd; <-sd })
	awaitPeer(t, "both live", func() bool { return c.live() && s.live() })
	c.mu.Lock()
	_, err := c.peer.Subscribe("SELECT id, val FROM s_rows ORDER BY id")
	c.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	const writes = 30
	var writers sync.WaitGroup
	for _, side := range []struct {
		f     *filePeer
		table string
		flush chan struct{}
	}{{c, "c_rows", cf}, {s, "s_rows", sf}} {
		writers.Add(1)
		go func() {
			defer writers.Done()
			for i := 1; i <= writes; i++ {
				side.f.mu.Lock()
				err := side.f.db.Exec("INSERT INTO "+side.table+" VALUES (?, ?)", i, "local")
				side.f.mu.Unlock()
				if err != nil {
					t.Error(err)
					return
				}
				select {
				case side.flush <- struct{}{}:
				default:
				}
			}
		}()
	}
	writers.Wait()
	defer func() {
		if t.Failed() {
			t.Logf("final local client=%d server=%d; received client=%d server=%d subscriptions=%d", c.count(t, "c_rows"), s.count(t, "s_rows"), c.count(t, "s_rows"), s.count(t, "c_rows"), subscriptions.Load())
		}
	}()
	awaitPeer(t, "all writes and subscription", func() bool {
		return c.count(t, "s_rows") == writes && s.count(t, "c_rows") == writes && subscriptions.Load() > 0
	})
}

// Hold a diff after its snapshot. A subsequent write cannot ride that diff.
type heldDiff struct {
	*orderedTransport
	reached, release chan struct{}
	once             sync.Once
}

func (h *heldDiff) Send(ctx context.Context, data []byte) error {
	msg, err := sqlpipe.DeserializePeer(data)
	if err != nil {
		return err
	}
	if _, ok := msg.Payload.(sqlpipe.DiffReadyMsg); ok {
		h.once.Do(func() { close(h.reached) })
		select {
		case <-h.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return h.orderedTransport.Send(ctx, data)
}

// The server has no Start call. Its first owner-lock acquisition therefore
// proves that the buffered pre-handshake flush was processed, not just queued.
type observedUnlock struct {
	sync.Locker
	observed chan struct{}
	once     sync.Once
}

func (o *observedUnlock) Unlock() { o.once.Do(func() { close(o.observed) }); o.Locker.Unlock() }
func TestRunPeerRetainsPreLiveFlushAndClosedChannel(t *testing.T) {
	c, s := openFilePeer(t, true), openFilePeer(t, false)
	ctx, cancel := context.WithCancel(t.Context())
	a, b := newOrderedPair(ctx)
	held := &heldDiff{orderedTransport: b, reached: make(chan struct{}), release: make(chan struct{})}
	cf, sf := make(chan struct{}, 1), make(chan struct{}, 1)
	sf <- struct{}{}
	close(sf)
	observed := make(chan struct{})
	link := transport.NewLink(held)
	link.OwnerLock = &observedUnlock{Locker: &s.mu, observed: observed}
	sd := make(chan error, 1)
	go func() { sd <- link.RunPeer(ctx, s.peer, false, sf, nil) }()
	var cd <-chan error
	t.Cleanup(func() {
		cancel()
		if cd != nil {
			<-cd
		}
		<-sd
	})
	select {
	case <-observed:
	case <-time.After(10 * time.Second):
		t.Fatal("pre-live flush was not processed")
	}
	cd = startPeer(t, ctx, c, a, true, cf, nil)
	select {
	case <-held.reached:
	case <-time.After(10 * time.Second):
		t.Fatal("diff never held")
	}
	s.mu.Lock()
	err := s.db.Exec("INSERT INTO s_rows VALUES (1,'after-snapshot')")
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	// No new flush signal: the pre-live request must remain pending.
	close(held.release)
	awaitPeer(t, "post-snapshot write", func() bool { return c.live() && s.live() && c.count(t, "s_rows") == 1 })
	c.mu.Lock()
	err = c.db.Exec("INSERT INTO c_rows VALUES (1,'other direction')")
	c.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	cf <- struct{}{}
	awaitPeer(t, "incoming work after flush channel closed", func() bool { return s.count(t, "c_rows") == 1 })
}

type joinedTransport struct {
	fail               chan struct{}
	cancelled, release chan struct{}
	exits              atomic.Int32
	datagramFailure    bool
	datagrams          atomic.Int32
}

func (*joinedTransport) Send(context.Context, []byte) error { return nil }
func (*joinedTransport) SendDatagram([]byte) error          { return nil }
func (j *joinedTransport) awaitCancellation(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	close(j.cancelled)
	<-j.release
	return nil, ctx.Err()
}
func (j *joinedTransport) Recv(ctx context.Context) ([]byte, error) {
	defer j.exits.Add(1)
	if j.datagramFailure {
		return j.awaitCancellation(ctx)
	}
	select {
	case <-j.fail:
		return nil, errors.New("controlled stream error")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (j *joinedTransport) RecvDatagram(ctx context.Context) ([]byte, error) {
	if !j.datagramFailure {
		defer j.exits.Add(1)
		return j.awaitCancellation(ctx)
	}
	// A malformed BestEffort payload is dropped, not confused with a failed
	// receive channel. The following I/O error must be the terminal result.
	if j.datagrams.Add(1) == 1 {
		return []byte{0}, nil
	}
	defer j.exits.Add(1)
	select {
	case <-j.fail:
		return nil, errors.New("controlled datagram error")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func TestRunPeerJoinsReceiversOnErrorAndCancellation(t *testing.T) {
	for _, mode := range []string{"cancel", "stream-error", "datagram-error", "hook-error"} {
		t.Run(mode, func(t *testing.T) {
			f := openFilePeer(t, mode == "hook-error")
			tr := &joinedTransport{fail: make(chan struct{}), cancelled: make(chan struct{}), release: make(chan struct{}), datagramFailure: mode == "datagram-error"}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			link := transport.NewLink(tr)
			link.OwnerLock = &f.mu
			if mode == "hook-error" {
				link.OnPeerInitialized = func() error {
					f.mu.Lock()
					defer f.mu.Unlock()
					return errors.New("controlled hook error")
				}
			}
			done := make(chan error, 1)
			go func() { done <- link.RunPeer(ctx, f.peer, mode == "hook-error", nil, nil) }()
			if mode == "cancel" {
				cancel()
			} else if mode != "hook-error" {
				close(tr.fail)
			}
			select {
			case <-tr.cancelled:
			case <-time.After(10 * time.Second):
				t.Fatal("receiver was not cancelled")
			}
			select {
			case err := <-done:
				t.Fatalf("returned before receiver joined: %v", err)
			default:
			}
			close(tr.release)
			select {
			case err := <-done:
				if mode == "cancel" {
					if !errors.Is(err, context.Canceled) {
						t.Fatal(err)
					}
				} else {
					want := "controlled stream error"
					if tr.datagramFailure {
						want = "controlled datagram error"
					}
					if mode == "hook-error" {
						want = "controlled hook error"
					}
					if err == nil || err.Error() != want {
						t.Fatalf("result=%v want %s", err, want)
					}
				}
			case <-time.After(10 * time.Second):
				t.Fatal("RunPeer did not return")
			}
			if tr.exits.Load() != 2 {
				t.Fatalf("joined %d receivers", tr.exits.Load())
			}
		})
	}
}

// Both runs begin with identical replicas, so their initial subscription
// notifications must come from entering Live, not a changed-row shortcut.
func TestRunPeerSubscriptionBootstrapAndReconnect(t *testing.T) {
	c, s := openFilePeer(t, true), openFilePeer(t, false)
	for run := 0; run < 2; run++ {
		func() {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			a, b := newOrderedPair(ctx)
			var done []chan error
			defer func() {
				cancel()
				for _, d := range done {
					<-d
				}
			}()
			var hooks [2]atomic.Int32
			notified := []chan struct{}{make(chan struct{}, 4), make(chan struct{}, 4)}
			flush := []chan struct{}{make(chan struct{}, 1), make(chan struct{}, 1)}
			for i, side := range []struct {
				f      *filePeer
				tr     transport.Transport
				client bool
				table  string
			}{
				{c, a, true, "s_rows"}, {s, b, false, "c_rows"},
			} {
				link := transport.NewLink(side.tr)
				link.OwnerLock = &side.f.mu
				link.OnPeerInitialized = func() error {
					side.f.mu.Lock()
					defer side.f.mu.Unlock()
					if side.f.peer.State() == sqlpipe.PeerLive {
						return errors.New("bootstrap arrived after Live")
					}
					if _, err := side.f.peer.Subscribe("SELECT id FROM " + side.table); err != nil {
						return err
					}
					if _, err := side.f.db.Query("SELECT id FROM " + side.table); err != nil {
						return err
					}
					hooks[i].Add(1)
					return nil
				}
				d := make(chan error, 1)
				done = append(done, d)
				go func() {
					d <- link.RunPeer(ctx, side.f.peer, side.client, flush[i], func(hr sqlpipe.PeerHandleResult) error {
						if len(hr.Subscriptions) > 0 {
							select {
							case notified[i] <- struct{}{}:
							case <-ctx.Done():
							}
						}
						return nil
					})
				}()
			}
			for i := range notified {
				select {
				case <-notified[i]:
				case <-ctx.Done():
					t.Fatal("empty handshake did not produce initial subscription", ctx.Err())
				}
				if hooks[i].Load() != 1 {
					t.Fatalf("run %d side %d hooks=%d", run, i, hooks[i].Load())
				}
			}
			for i, side := range []struct {
				f     *filePeer
				table string
			}{{c, "c_rows"}, {s, "s_rows"}} {
				side.f.mu.Lock()
				err := side.f.db.Exec("INSERT INTO "+side.table+" VALUES (?, 'after-bootstrap')", run+1)
				side.f.mu.Unlock()
				if err != nil {
					t.Fatal(err)
				}
				flush[i] <- struct{}{}
			}
			for i := range notified {
				select {
				case <-notified[i]:
				case <-ctx.Done():
					t.Fatal("bootstrapped subscription missed later write", ctx.Err())
				}
				if hooks[i].Load() != 1 {
					t.Fatal("hook repeated after initialization")
				}
			}
		}()
		for _, f := range []*filePeer{c, s} {
			f.mu.Lock()
			f.peer.Reset()
			f.mu.Unlock()
		}
	}
}

func TestRunPeerRejectedHandshakeDoesNotInitializeHook(t *testing.T) {
	c, s := openFilePeer(t, true), openFilePeer(t, false)
	// Claim the wrong table; the real server's ownership callback rejects it.
	if err := c.peer.Close(); err != nil {
		t.Fatal(err)
	}
	var err error
	c.peer, err = sqlpipe.NewPeer(c.db, sqlpipe.PeerConfig{OwnedTables: map[string]bool{"s_rows": true}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	a, b := newOrderedPair(ctx)
	link := transport.NewLink(b)
	link.OwnerLock = &s.mu
	var hooks atomic.Int32
	link.OnPeerInitialized = func() error { hooks.Add(1); return nil }
	done := make(chan error, 1)
	go func() { done <- link.RunPeer(ctx, s.peer, false, nil, nil) }()
	defer func() { cancel(); <-done }()
	messages, err := c.peer.Start()
	if err != nil {
		t.Fatal(err)
	}
	for _, msg := range messages {
		if err := a.Send(ctx, sqlpipe.SerializePeer(msg.Msg)); err != nil {
			t.Fatal(err)
		}
	}
	data, err := a.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := sqlpipe.DeserializePeer(data)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := msg.Payload.(sqlpipe.ErrorMsg); !ok {
		t.Fatalf("expected rejection, got %T", msg.Payload)
	}
	s.mu.Lock()
	state := s.peer.State()
	s.mu.Unlock()
	if state != sqlpipe.PeerError || hooks.Load() != 0 {
		t.Fatalf("state=%v hooks=%d", state, hooks.Load())
	}
}
