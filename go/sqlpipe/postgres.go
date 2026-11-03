// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

//go:build postgres

package sqlpipe

/*
#cgo pkg-config: libpq
#cgo CXXFLAGS: -DSQLPIPE_HAVE_POSTGRES

#include <stdlib.h>
#include <libpq-fe.h>
#include "sqlpipe_capi.h"

extern void cProgressTrampoline(void*, uint8_t, const char*, int64_t, int64_t);
extern int cSchemaMismatchTrampoline(void*, const uint8_t*, size_t, const uint8_t*, size_t, const char*);
extern uint8_t cConflictTrampoline(void*, uint8_t, const uint8_t*, size_t);
extern int cApproveOwnershipTrampoline(void*, const char**, size_t);
extern void cLogTrampoline(void*, uint8_t, const char*);
extern void cFlushTrampoline(void*, const uint8_t*, size_t);
*/
import "C"

import (
	"unsafe"
)

// PGConn is a borrowed-or-owned libpq connection used with the v8 engine.
type PGConn struct {
	conn *C.PGconn
	own  bool
}

// OpenPostgres connects with libpq conninfo (or the usual PG* environment).
func OpenPostgres(conninfo string) (*PGConn, error) {
	cci := C.CString(conninfo)
	defer C.free(unsafe.Pointer(cci))
	c := C.PQconnectdb(cci)
	if c == nil || C.PQstatus(c) != C.CONNECTION_OK {
		msg := "PQconnectdb failed"
		if c != nil {
			msg = C.GoString(C.PQerrorMessage(c))
			C.PQfinish(c)
		}
		return nil, &Error{Code: ErrPostgres, Msg: msg}
	}
	return &PGConn{conn: c, own: true}, nil
}

// Close finishes an owned connection.
func (c *PGConn) Close() {
	if c != nil && c.own && c.conn != nil {
		C.PQfinish(c.conn)
		c.conn = nil
	}
}

// NewMasterPG constructs a protocol-v8 Master on a Postgres connection.
func NewMasterPG(conn *PGConn, config MasterConfig) (*Master, error) {
	m := &Master{}
	var cfg C.sqlpipe_master_config
	tfPtrs, tfCount := tableFilterToCStrings(config.TableFilter)
	defer freeCStrings(tfPtrs, tfCount)
	cfg.table_filter = tfPtrs
	cfg.table_filter_count = tfCount
	if config.SeqKey != "" {
		csk := C.CString(config.SeqKey)
		defer C.free(unsafe.Pointer(csk))
		cfg.seq_key = csk
	}
	cfg.bucket_size = C.int64_t(config.BucketSize)
	cfg.changeset_queue_size = C.uint64_t(config.ChangesetQueueSize)
	if config.OnProgress != nil {
		h := m.handles.add(config.OnProgress)
		cfg.on_progress = C.sqlpipe_progress_fn(C.cProgressTrampoline)
		cfg.progress_ctx = h
	}
	if config.OnSchemaMismatch != nil {
		h := m.handles.add(config.OnSchemaMismatch)
		cfg.on_schema_mismatch = C.sqlpipe_schema_mismatch_fn(C.cSchemaMismatchTrampoline)
		cfg.schema_mismatch_ctx = h
	}
	if config.OnLog != nil {
		h := m.handles.add(config.OnLog)
		cfg.on_log = C.sqlpipe_log_fn(C.cLogTrampoline)
		cfg.log_ctx = h
	}
	if config.OnFlush != nil {
		h := m.handles.add(config.OnFlush)
		cfg.on_flush = C.sqlpipe_flush_fn(C.cFlushTrampoline)
		cfg.flush_ctx = h
	}

	if err := convertError(C.sqlpipe_master_new_pg(conn.conn, cfg, &m.ptr)); err != nil {
		m.handles.free()
		return nil, err
	}
	return m, nil
}

// NewReplicaPG constructs a protocol-v8 Replica on a Postgres connection.
func NewReplicaPG(conn *PGConn, config ReplicaConfig) (*Replica, error) {
	r := &Replica{}
	var cfg C.sqlpipe_replica_config
	tfPtrs, tfCount := tableFilterToCStrings(config.TableFilter)
	defer freeCStrings(tfPtrs, tfCount)
	cfg.table_filter = tfPtrs
	cfg.table_filter_count = tfCount
	if config.SeqKey != "" {
		csk := C.CString(config.SeqKey)
		defer C.free(unsafe.Pointer(csk))
		cfg.seq_key = csk
	}
	cfg.bucket_size = C.int64_t(config.BucketSize)
	if config.OnConflict != nil {
		h := r.handles.add(config.OnConflict)
		cfg.on_conflict = C.sqlpipe_conflict_fn(C.cConflictTrampoline)
		cfg.conflict_ctx = h
	}

	if config.OnProgress != nil {
		h := r.handles.add(config.OnProgress)
		cfg.on_progress = C.sqlpipe_progress_fn(C.cProgressTrampoline)
		cfg.progress_ctx = h
	}
	if config.OnSchemaMismatch != nil {
		h := r.handles.add(config.OnSchemaMismatch)
		cfg.on_schema_mismatch = C.sqlpipe_schema_mismatch_fn(C.cSchemaMismatchTrampoline)
		cfg.schema_mismatch_ctx = h
	}
	if config.OnLog != nil {
		h := r.handles.add(config.OnLog)
		cfg.on_log = C.sqlpipe_log_fn(C.cLogTrampoline)
		cfg.log_ctx = h
	}
	if config.QueueWhilePredicting {
		cfg.queue_while_predicting = 1
	}

	if err := convertError(C.sqlpipe_replica_new_pg(conn.conn, cfg, &r.ptr)); err != nil {
		r.handles.free()
		return nil, err
	}
	return r, nil
}

// NewPeerPG constructs a protocol-v8 Peer on a Postgres connection.
func NewPeerPG(conn *PGConn, config PeerConfig) (*Peer, error) {
	p := &Peer{}
	var cfg C.sqlpipe_peer_config

	otPtrs, otCount := toCStrings(config.OwnedTables)
	defer freeCStrings(otPtrs, otCount)
	cfg.owned_tables = otPtrs
	cfg.owned_table_count = otCount

	tfPtrs, tfCount := tableFilterToCStrings(config.TableFilter)
	defer freeCStrings(tfPtrs, tfCount)
	cfg.table_filter = tfPtrs
	cfg.table_filter_count = tfCount

	if config.ApproveOwnership != nil {
		h := p.handles.add(config.ApproveOwnership)
		cfg.approve_ownership = C.sqlpipe_approve_ownership_fn(C.cApproveOwnershipTrampoline)
		cfg.approve_ownership_ctx = h
	}
	if config.OnConflict != nil {
		h := p.handles.add(config.OnConflict)
		cfg.on_conflict = C.sqlpipe_conflict_fn(C.cConflictTrampoline)
		cfg.conflict_ctx = h
	}
	if config.OnProgress != nil {
		h := p.handles.add(config.OnProgress)
		cfg.on_progress = C.sqlpipe_progress_fn(C.cProgressTrampoline)
		cfg.progress_ctx = h
	}
	if config.OnSchemaMismatch != nil {
		h := p.handles.add(config.OnSchemaMismatch)
		cfg.on_schema_mismatch = C.sqlpipe_schema_mismatch_fn(C.cSchemaMismatchTrampoline)
		cfg.schema_mismatch_ctx = h
	}
	if config.OnLog != nil {
		h := p.handles.add(config.OnLog)
		cfg.on_log = C.sqlpipe_log_fn(C.cLogTrampoline)
		cfg.log_ctx = h
	}

	if err := convertError(C.sqlpipe_peer_new_pg(conn.conn, cfg, &p.ptr)); err != nil {
		p.handles.free()
		return nil, err
	}
	return p, nil
}
