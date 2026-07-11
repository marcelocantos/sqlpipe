// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

// Package transport provides a dual-channel transport adapter for sqlpipe
// replication over network connections that support both reliable streams
// and unreliable datagrams (e.g. QUIC).
//
// The adapter routes outgoing messages based on their Delivery hint:
// Reliable messages go to the stream channel, BestEffort messages go
// to the datagram channel. Incoming messages from both channels are
// merged and delivered to the sqlpipe message handler.
//
// BestEffort traffic is always routed to the datagram channel. The
// convergence loop is regenerable: if a BestEffort probe is lost, the
// replica re-converges until it reaches Live (or the context ends).
//
// Usage:
//
//	link := transport.NewLink(conn) // any Transport implementation
//	link.RunMaster(ctx, master, flushCh)
//	// or link.RunReplica(ctx, replica, handler)
package transport

import (
	"context"
	"errors"
	"sync"
	"time"

	sqlpipe "github.com/marcelocantos/sqlpipe/go/sqlpipe"
)

// DefaultReConvergeInterval is how often RunReplica re-issues Converge
// while the replica is not yet Live. Zero on Link means use this default.
const DefaultReConvergeInterval = 50 * time.Millisecond

// Transport is the interface for a dual-channel connection.
// Any stack with ordered reliable send/recv plus a datagram path
// (QUIC, a test mock, etc.) can implement this.
type Transport interface {
	// Send writes data on the reliable ordered channel.
	Send(ctx context.Context, data []byte) error

	// Recv reads the next message from the reliable channel.
	Recv(ctx context.Context) ([]byte, error)

	// SendDatagram writes data on the unreliable channel.
	SendDatagram(data []byte) error

	// RecvDatagram reads the next datagram.
	RecvDatagram(ctx context.Context) ([]byte, error)
}

// Link connects a sqlpipe instance to a Transport, routing messages
// by delivery hint and merging incoming messages from both channels.
type Link struct {
	t Transport

	// ReConvergeInterval controls how often the replica re-probes while
	// not Live. Zero means DefaultReConvergeInterval.
	ReConvergeInterval time.Duration
}

// NewLink creates a Link over the given Transport.
func NewLink(t Transport) *Link {
	return &Link{t: t}
}

func (l *Link) reConvergeInterval() time.Duration {
	if l.ReConvergeInterval > 0 {
		return l.ReConvergeInterval
	}
	return DefaultReConvergeInterval
}

// send routes an OutMessage to the appropriate channel by delivery hint.
func (l *Link) send(ctx context.Context, om sqlpipe.OutMessage) error {
	wire := sqlpipe.Serialize(om.Msg)
	if om.Delivery == sqlpipe.DeliveryBestEffort {
		return l.t.SendDatagram(wire)
	}
	return l.t.Send(ctx, wire)
}

// sendPeer routes a PeerOutMessage to the appropriate channel.
func (l *Link) sendPeer(ctx context.Context, pom sqlpipe.PeerOutMessage) error {
	wire := sqlpipe.SerializePeer(pom.Msg)
	if pom.Delivery == sqlpipe.DeliveryBestEffort {
		return l.t.SendDatagram(wire)
	}
	return l.t.Send(ctx, wire)
}

// ReplicaHandler is called when the replica processes incoming messages.
type ReplicaHandler func(hr sqlpipe.HandleResult) error

// RunMaster runs the master side of the replication protocol over the
// transport. It receives messages from the remote replica, passes them
// to the Master, and sends responses back. It also sends flushed
// changesets from the master.
//
// flushCh should emit whenever the master has new data to flush.
// Cancel ctx to stop the link.
func (l *Link) RunMaster(ctx context.Context, m *sqlpipe.Master, flushCh <-chan struct{}) error {
	errc := make(chan error, 3)
	var once sync.Once
	fail := func(err error) { once.Do(func() { errc <- err }) }

	dispatch := func(data []byte, bestEffort bool) {
		msg, err := sqlpipe.Deserialize(data)
		if err != nil {
			if bestEffort {
				return // drop malformed datagrams
			}
			fail(err)
			return
		}
		resp, err := m.HandleMessage(msg)
		if err != nil {
			if bestEffort {
				return
			}
			fail(err)
			return
		}
		for _, om := range resp {
			if err := l.send(ctx, om); err != nil {
				fail(err)
				return
			}
		}
	}

	// Stream receiver.
	go func() {
		for {
			data, err := l.t.Recv(ctx)
			if err != nil {
				fail(err)
				return
			}
			dispatch(data, false)
		}
	}()

	// Datagram receiver.
	go func() {
		for {
			data, err := l.t.RecvDatagram(ctx)
			if err != nil {
				if errors.Is(err, ctx.Err()) {
					fail(err)
				}
				continue
			}
			dispatch(data, true)
		}
	}()

	// Flush forwarder.
	go func() {
		for {
			select {
			case <-ctx.Done():
				fail(ctx.Err())
				return
			case <-flushCh:
				msgs, err := m.Flush()
				if err != nil {
					fail(err)
					return
				}
				for _, om := range msgs {
					if err := l.send(ctx, om); err != nil {
						fail(err)
						return
					}
				}
			}
		}
	}()

	return <-errc
}

// RunReplica runs the replica side of the replication protocol over the
// transport. It initiates convergence, re-probes while not Live (so
// BestEffort loss is recoverable), receives messages from the remote
// master, and sends responses back.
//
// handler is called for each HandleResult that contains changes or
// subscription updates. Cancel ctx to stop the link.
func (l *Link) RunReplica(ctx context.Context, r *sqlpipe.Replica, handler ReplicaHandler) error {
	// Initial converge probe (BestEffort → datagram).
	probe, err := r.Converge()
	if err != nil {
		return err
	}
	if err := l.send(ctx, probe); err != nil {
		return err
	}

	errc := make(chan error, 3)
	var once sync.Once
	fail := func(err error) { once.Do(func() { errc <- err }) }

	dispatch := func(data []byte, bestEffort bool) {
		msg, err := sqlpipe.Deserialize(data)
		if err != nil {
			if bestEffort {
				return
			}
			fail(err)
			return
		}
		hr, err := r.HandleMessage(msg)
		if err != nil {
			if bestEffort {
				return
			}
			fail(err)
			return
		}
		for _, om := range hr.Messages {
			if err := l.send(ctx, om); err != nil {
				fail(err)
				return
			}
		}
		if handler != nil && (len(hr.Changes) > 0 || len(hr.Subscriptions) > 0) {
			if err := handler(hr); err != nil {
				fail(err)
				return
			}
		}
	}

	// Re-converge while not Live so lost BestEffort probes recover.
	go func() {
		ticker := time.NewTicker(l.reConvergeInterval())
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				fail(ctx.Err())
				return
			case <-ticker.C:
				if r.State() == sqlpipe.ReplicaLive {
					// Stay running until ctx ends so the stream/datagram
					// receivers remain the exit path; just stop probing.
					return
				}
				probe, err := r.Converge()
				if err != nil {
					fail(err)
					return
				}
				if err := l.send(ctx, probe); err != nil {
					fail(err)
					return
				}
			}
		}
	}()

	// Stream receiver.
	go func() {
		for {
			data, err := l.t.Recv(ctx)
			if err != nil {
				fail(err)
				return
			}
			dispatch(data, false)
		}
	}()

	// Datagram receiver.
	go func() {
		for {
			data, err := l.t.RecvDatagram(ctx)
			if err != nil {
				if errors.Is(err, ctx.Err()) {
					fail(err)
				}
				continue
			}
			dispatch(data, true)
		}
	}()

	return <-errc
}

// PeerHandler is called when the peer processes incoming messages.
type PeerHandler func(hr sqlpipe.PeerHandleResult) error

// RunPeer runs a bidirectional peer replication protocol over the
// transport. For client peers, it initiates the handshake. For server
// peers, it waits for the client's hello.
//
// flushCh should emit whenever the peer has new local data to flush.
// handler is called for each PeerHandleResult with changes or subscriptions.
// Cancel ctx to stop the link.
func (l *Link) RunPeer(ctx context.Context, p *sqlpipe.Peer, isClient bool, flushCh <-chan struct{}, handler PeerHandler) error {
	if isClient {
		msgs, err := p.Start()
		if err != nil {
			return err
		}
		for _, pom := range msgs {
			if err := l.sendPeer(ctx, pom); err != nil {
				return err
			}
		}
	}

	errc := make(chan error, 3)
	var once sync.Once
	fail := func(err error) { once.Do(func() { errc <- err }) }

	dispatch := func(data []byte, bestEffort bool) {
		msg, err := sqlpipe.DeserializePeer(data)
		if err != nil {
			if bestEffort {
				return
			}
			fail(err)
			return
		}
		hr, err := p.HandleMessage(msg)
		if err != nil {
			if bestEffort {
				return
			}
			fail(err)
			return
		}
		for _, pom := range hr.Messages {
			if err := l.sendPeer(ctx, pom); err != nil {
				fail(err)
				return
			}
		}
		if handler != nil && (len(hr.Changes) > 0 || len(hr.Subscriptions) > 0) {
			if err := handler(hr); err != nil {
				fail(err)
				return
			}
		}
	}

	// Stream receiver.
	go func() {
		for {
			data, err := l.t.Recv(ctx)
			if err != nil {
				fail(err)
				return
			}
			dispatch(data, false)
		}
	}()

	// Datagram receiver.
	go func() {
		for {
			data, err := l.t.RecvDatagram(ctx)
			if err != nil {
				if errors.Is(err, ctx.Err()) {
					fail(err)
				}
				continue
			}
			dispatch(data, true)
		}
	}()

	// Flush forwarder.
	go func() {
		for {
			select {
			case <-ctx.Done():
				fail(ctx.Err())
				return
			case <-flushCh:
				msgs, err := p.Flush()
				if err != nil {
					fail(err)
					return
				}
				for _, pom := range msgs {
					if err := l.sendPeer(ctx, pom); err != nil {
						fail(err)
						return
					}
				}
			}
		}
	}()

	return <-errc
}
