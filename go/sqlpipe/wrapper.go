// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package sqlpipe

/*
#cgo CXXFLAGS: -std=c++23 -DSQLITE_ENABLE_SESSION -DSQLITE_ENABLE_PREUPDATE_HOOK -I${SRCDIR}/../../dist -I${SRCDIR}/../../vendor/include
#cgo CFLAGS: -DSQLITE_ENABLE_SESSION -DSQLITE_ENABLE_PREUPDATE_HOOK -I${SRCDIR}/../../vendor/include

#include <stdlib.h>
#include "../../vendor/include/sqlite3.h"
#include "sqlpipe_capi.h"

// SQLITE_TRANSIENT is a macro casting -1 to a function pointer,
// which CGo can't handle. Provide a C wrapper.
#define SQLPIPE_TRANSIENT ((sqlite3_destructor_type)-1)

static int sqlpipe_bind_text(sqlite3_stmt* s, int i, const char* v, int n) {
	return sqlite3_bind_text(s, i, v, n, SQLPIPE_TRANSIENT);
}
static int sqlpipe_bind_blob(sqlite3_stmt* s, int i, const void* v, int n) {
	return sqlite3_bind_blob(s, i, v, n, SQLPIPE_TRANSIENT);
}

// Forward-declare Go callback trampolines (defined in cgo_exports.go).
extern void goProgressTrampoline(uintptr_t, uint8_t, const char*, int64_t, int64_t);
extern int goSchemaMismatchTrampoline(uintptr_t, int32_t, int32_t, const char*);
extern uint8_t goConflictTrampoline(uintptr_t, uint8_t, const uint8_t*, size_t);
extern int goApproveOwnershipTrampoline(uintptr_t, const char**, size_t);
extern void goLogTrampoline(uintptr_t, uint8_t, const char*);
extern void goFlushTrampoline(uintptr_t, const uint8_t*, size_t);

// C trampolines that cast void* ctx to uintptr_t for Go.
// These cannot be static because CGo needs them as exported symbols.
void cProgressTrampoline(void* ctx, uint8_t phase, const char* table, int64_t done, int64_t total) {
	goProgressTrampoline((uintptr_t)ctx, phase, table, done, total);
}
int cSchemaMismatchTrampoline(void* ctx, int32_t remote_sv, int32_t local_sv, const char* remote_sql) {
	return goSchemaMismatchTrampoline((uintptr_t)ctx, remote_sv, local_sv, remote_sql);
}
uint8_t cConflictTrampoline(void* ctx, uint8_t ct, const uint8_t* data, size_t len) {
	return goConflictTrampoline((uintptr_t)ctx, ct, data, len);
}
int cApproveOwnershipTrampoline(void* ctx, const char** tables, size_t count) {
	return goApproveOwnershipTrampoline((uintptr_t)ctx, tables, count);
}
void cLogTrampoline(void* ctx, uint8_t level, const char* message) {
	goLogTrampoline((uintptr_t)ctx, level, message);
}
void cFlushTrampoline(void* ctx, const uint8_t* data, size_t len) {
	goFlushTrampoline((uintptr_t)ctx, data, len);
}
*/
import "C"

import (
	"encoding/binary"
	"fmt"
	"iter"
	"math"
	"runtime/cgo"
	"unsafe"
)

// ── Database ─────────────────────────────────────────────────────

// Database wraps a raw sqlite3* handle. It provides a self-contained
// SQLite connection without depending on database/sql or mattn/go-sqlite3.
type Database struct {
	db *C.sqlite3
}

// OpenDatabase opens a SQLite database at the given path.
// Use ":memory:" for an in-memory database.
func OpenDatabase(path string) (*Database, error) {
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))
	var db *C.sqlite3
	rc := C.sqlite3_open(cpath, &db)
	if rc != C.SQLITE_OK {
		msg := C.GoString(C.sqlite3_errmsg(db))
		C.sqlite3_close(db)
		return nil, &Error{Code: ErrSqlite, Msg: msg}
	}
	return &Database{db: db}, nil
}

// Close closes the database connection.
func (d *Database) Close() error {
	if d.db != nil {
		rc := C.sqlite3_close(d.db)
		if rc != C.SQLITE_OK {
			return &Error{Code: ErrSqlite, Msg: C.GoString(C.sqlite3_errmsg(d.db))}
		}
		d.db = nil
	}
	return nil
}

// Exec executes one or more SQL statements without returning results.
// Use ? placeholders for parameters to avoid SQL injection.
func (d *Database) Exec(sql string, args ...any) error {
	if len(args) == 0 {
		csql := C.CString(sql)
		defer C.free(unsafe.Pointer(csql))
		return convertError(C.sqlpipe_db_exec(d.db, csql))
	}
	stmt, err := d.prepare(sql)
	if err != nil {
		return err
	}
	defer C.sqlite3_finalize(stmt)
	if err := bindArgs(d.db, stmt, args); err != nil {
		return err
	}
	rc := C.sqlite3_step(stmt)
	if rc != C.SQLITE_DONE && rc != C.SQLITE_ROW {
		return d.sqliteErr()
	}
	return nil
}

// Query executes a SQL query and returns the full result set in memory.
// Use ? placeholders for parameters. Suitable for small result sets.
func (d *Database) Query(sql string, args ...any) (QueryResult, error) {
	if len(args) == 0 {
		csql := C.CString(sql)
		defer C.free(unsafe.Pointer(csql))
		var buf C.sqlpipe_buf
		if err := convertError(C.sqlpipe_db_query(d.db, csql, &buf)); err != nil {
			return QueryResult{}, err
		}
		defer C.sqlpipe_free_buf(buf)
		data := C.GoBytes(unsafe.Pointer(buf.data), C.int(buf.len))
		dec := &decoder{data: data}
		return decodeQueryResult(dec), nil
	}
	// Parameterized query — use prepared statement.
	stmt, err := d.prepare(sql)
	if err != nil {
		return QueryResult{}, err
	}
	defer C.sqlite3_finalize(stmt)
	if err := bindArgs(d.db, stmt, args); err != nil {
		return QueryResult{}, err
	}
	return stmtToQueryResult(stmt), nil
}

// Rows executes a SQL query and returns an iterator over the result rows.
// Use ? placeholders for parameters. The iterator streams rows one at a
// time — suitable for large result sets. The statement is finalized when
// the iterator is exhausted or the loop breaks early.
//
// Check Row.Err() after the loop to detect errors during iteration.
//
//	for row := range db.Rows("SELECT id, name FROM t WHERE score > ?", 90) {
//	    fmt.Println(row.Int64(0), row.Text(1))
//	}
func (d *Database) Rows(sql string, args ...any) iter.Seq[*Row] {
	return func(yield func(*Row) bool) {
		stmt, err := d.prepare(sql)
		if err != nil {
			yield(&Row{err: err})
			return
		}
		defer C.sqlite3_finalize(stmt)
		if err := bindArgs(d.db, stmt, args); err != nil {
			yield(&Row{err: err})
			return
		}
		ncols := int(C.sqlite3_column_count(stmt))
		for {
			rc := C.sqlite3_step(stmt)
			if rc == C.SQLITE_DONE {
				return
			}
			if rc != C.SQLITE_ROW {
				yield(&Row{err: d.sqliteErr()})
				return
			}
			if !yield(&Row{stmt: stmt, ncols: ncols}) {
				return
			}
		}
	}
}

// Begin starts a transaction. Call Commit() or Rollback() on the
// returned Tx to end it. For convenience, use Database.Tx() instead.
func (d *Database) Begin() (*Tx, error) {
	if err := d.Exec("BEGIN"); err != nil {
		return nil, err
	}
	return &Tx{db: d}, nil
}

// Tx runs fn inside a transaction. If fn returns nil, the transaction
// is committed. If fn returns an error (or panics), it is rolled back.
func (d *Database) Tx(fn func(tx *Tx) error) error {
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if r := recover(); r != nil {
			_ = tx.Rollback()
			panic(r)
		}
	}()
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// Handle returns the raw sqlite3* pointer for use with CGo.
func (d *Database) Handle() unsafe.Pointer {
	return unsafe.Pointer(d.db)
}

func (d *Database) prepare(sql string) (*C.sqlite3_stmt, error) {
	csql := C.CString(sql)
	defer C.free(unsafe.Pointer(csql))
	var stmt *C.sqlite3_stmt
	rc := C.sqlite3_prepare_v2(d.db, csql, -1, &stmt, nil)
	if rc != C.SQLITE_OK {
		return nil, d.sqliteErr()
	}
	return stmt, nil
}

func (d *Database) sqliteErr() error {
	return &Error{Code: ErrSqlite, Msg: C.GoString(C.sqlite3_errmsg(d.db))}
}

// ── Tx ──────────────────────────────────────────────────────────

// Tx represents an active database transaction.
type Tx struct {
	db   *Database
	done bool
}

// Exec executes a parameterized SQL statement within the transaction.
func (tx *Tx) Exec(sql string, args ...any) error {
	if tx.done {
		return &Error{Code: ErrInvalidState, Msg: "transaction already ended"}
	}
	return tx.db.Exec(sql, args...)
}

// Query executes a parameterized SQL query within the transaction.
func (tx *Tx) Query(sql string, args ...any) (QueryResult, error) {
	if tx.done {
		return QueryResult{}, &Error{Code: ErrInvalidState, Msg: "transaction already ended"}
	}
	return tx.db.Query(sql, args...)
}

// Rows returns a row iterator within the transaction.
func (tx *Tx) Rows(sql string, args ...any) iter.Seq[*Row] {
	if tx.done {
		return func(yield func(*Row) bool) {
			yield(&Row{err: &Error{Code: ErrInvalidState, Msg: "transaction already ended"}})
		}
	}
	return tx.db.Rows(sql, args...)
}

// Commit commits the transaction.
func (tx *Tx) Commit() error {
	if tx.done {
		return &Error{Code: ErrInvalidState, Msg: "transaction already ended"}
	}
	tx.done = true
	return tx.db.Exec("COMMIT")
}

// Rollback rolls back the transaction.
func (tx *Tx) Rollback() error {
	if tx.done {
		return &Error{Code: ErrInvalidState, Msg: "transaction already ended"}
	}
	tx.done = true
	return tx.db.Exec("ROLLBACK")
}

// ── Row ─────────────────────────────────────────────────────────

// Row provides access to column values of the current result row.
// Column accessors use zero-based indices.
type Row struct {
	stmt  *C.sqlite3_stmt
	ncols int
	err   error
}

// Err returns any error that occurred during iteration.
func (r *Row) Err() error { return r.err }

// ColumnCount returns the number of columns in the result.
func (r *Row) ColumnCount() int { return r.ncols }

// IsNull returns true if the column value is NULL.
func (r *Row) IsNull(col int) bool {
	return C.sqlite3_column_type(r.stmt, C.int(col)) == C.SQLITE_NULL
}

// Int64 returns the column value as int64.
func (r *Row) Int64(col int) int64 {
	return int64(C.sqlite3_column_int64(r.stmt, C.int(col)))
}

// Float64 returns the column value as float64.
func (r *Row) Float64(col int) float64 {
	return float64(C.sqlite3_column_double(r.stmt, C.int(col)))
}

// Text returns the column value as string.
func (r *Row) Text(col int) string {
	p := C.sqlite3_column_text(r.stmt, C.int(col))
	if p == nil {
		return ""
	}
	return C.GoString((*C.char)(unsafe.Pointer(p)))
}

// Blob returns the column value as []byte.
func (r *Row) Blob(col int) []byte {
	p := C.sqlite3_column_blob(r.stmt, C.int(col))
	n := C.sqlite3_column_bytes(r.stmt, C.int(col))
	if p == nil || n == 0 {
		return nil
	}
	return C.GoBytes(p, n)
}

// Value returns the column value using SQLite's type affinity.
// Returns nil (NULL), int64, float64, string, or []byte.
func (r *Row) Value(col int) any {
	switch C.sqlite3_column_type(r.stmt, C.int(col)) {
	case C.SQLITE_NULL:
		return nil
	case C.SQLITE_INTEGER:
		return r.Int64(col)
	case C.SQLITE_FLOAT:
		return r.Float64(col)
	case C.SQLITE_TEXT:
		return r.Text(col)
	case C.SQLITE_BLOB:
		return r.Blob(col)
	default:
		return nil
	}
}

// ── Bind helpers ────────────────────────────────────────────────

func bindArgs(db *C.sqlite3, stmt *C.sqlite3_stmt, args []any) error {
	for i, arg := range args {
		idx := C.int(i + 1) // SQLite bind indices are 1-based
		var rc C.int
		switch v := arg.(type) {
		case nil:
			rc = C.sqlite3_bind_null(stmt, idx)
		case int:
			rc = C.sqlite3_bind_int64(stmt, idx, C.sqlite3_int64(v))
		case int64:
			rc = C.sqlite3_bind_int64(stmt, idx, C.sqlite3_int64(v))
		case float64:
			rc = C.sqlite3_bind_double(stmt, idx, C.double(v))
		case string:
			cs := C.CString(v)
			rc = C.sqlpipe_bind_text(stmt, idx, cs, C.int(len(v)))
			C.free(unsafe.Pointer(cs))
		case []byte:
			if len(v) == 0 {
				rc = C.sqlite3_bind_zeroblob(stmt, idx, 0)
			} else {
				rc = C.sqlpipe_bind_blob(stmt, idx, unsafe.Pointer(&v[0]), C.int(len(v)))
			}
		case bool:
			if v {
				rc = C.sqlite3_bind_int64(stmt, idx, 1)
			} else {
				rc = C.sqlite3_bind_int64(stmt, idx, 0)
			}
		default:
			return fmt.Errorf("unsupported bind type %T at index %d", arg, i)
		}
		if rc != C.SQLITE_OK {
			return &Error{Code: ErrSqlite, Msg: C.GoString(C.sqlite3_errmsg(db))}
		}
	}
	return nil
}

func stmtToQueryResult(stmt *C.sqlite3_stmt) QueryResult {
	ncols := int(C.sqlite3_column_count(stmt))
	columns := make([]string, ncols)
	for i := range ncols {
		name := C.sqlite3_column_name(stmt, C.int(i))
		if name != nil {
			columns[i] = C.GoString(name)
		}
	}
	var rows [][]Value
	for {
		rc := C.sqlite3_step(stmt)
		if rc == C.SQLITE_DONE {
			break
		}
		if rc != C.SQLITE_ROW {
			break
		}
		row := make([]Value, ncols)
		for i := range ncols {
			switch C.sqlite3_column_type(stmt, C.int(i)) {
			case C.SQLITE_NULL:
				row[i] = nil
			case C.SQLITE_INTEGER:
				row[i] = int64(C.sqlite3_column_int64(stmt, C.int(i)))
			case C.SQLITE_FLOAT:
				row[i] = float64(C.sqlite3_column_double(stmt, C.int(i)))
			case C.SQLITE_TEXT:
				p := C.sqlite3_column_text(stmt, C.int(i))
				row[i] = C.GoString((*C.char)(unsafe.Pointer(p)))
			case C.SQLITE_BLOB:
				p := C.sqlite3_column_blob(stmt, C.int(i))
				n := C.sqlite3_column_bytes(stmt, C.int(i))
				if p != nil && n > 0 {
					row[i] = C.GoBytes(p, n)
				} else {
					row[i] = []byte(nil)
				}
			}
		}
		rows = append(rows, row)
	}
	return QueryResult{Columns: columns, Rows: rows}
}

// ── Error conversion ────────────────────────────────────────────

func convertError(e C.sqlpipe_error) error {
	if e.code == 0 {
		return nil
	}
	err := &Error{Code: ErrorCode(e.code), Msg: C.GoString(e.msg)}
	C.sqlpipe_free_error(e)
	return err
}

// ── Message buffer decoding ─────────────────────────────────────

// decodeMessages reads [u32 count][msg1][msg2]... from a C buffer.
func decodeMessages(buf C.sqlpipe_buf) ([]Message, error) {
	if buf.data == nil || buf.len == 0 {
		return nil, nil
	}
	defer C.sqlpipe_free_buf(buf)
	data := C.GoBytes(unsafe.Pointer(buf.data), C.int(buf.len))
	return decodeMessagesFromBytes(data)
}

func decodeMessagesFromBytes(data []byte) ([]Message, error) {
	if len(data) < 4 {
		return nil, nil
	}
	count := binary.LittleEndian.Uint32(data[:4])
	pos := 4
	msgs := make([]Message, 0, count)
	for i := uint32(0); i < count; i++ {
		if pos+4 > len(data) {
			break
		}
		mlen := binary.LittleEndian.Uint32(data[pos:])
		total := 4 + int(mlen)
		if pos+total > len(data) {
			break
		}
		msg, err := Deserialize(data[pos : pos+total])
		if err != nil {
			return nil, err
		}
		msgs = append(msgs, msg)
		pos += total
	}
	return msgs, nil
}

// decodePeerMessages reads [u32 count][pmsg1][pmsg2]... from a C buffer.
func decodePeerMessages(buf C.sqlpipe_buf) ([]PeerMessage, error) {
	if buf.data == nil || buf.len == 0 {
		return nil, nil
	}
	defer C.sqlpipe_free_buf(buf)
	data := C.GoBytes(unsafe.Pointer(buf.data), C.int(buf.len))
	if len(data) < 4 {
		return nil, nil
	}
	count := binary.LittleEndian.Uint32(data[:4])
	pos := 4
	msgs := make([]PeerMessage, 0, count)
	for i := uint32(0); i < count; i++ {
		if pos+4 > len(data) {
			break
		}
		mlen := binary.LittleEndian.Uint32(data[pos:])
		total := 4 + int(mlen)
		if pos+total > len(data) {
			break
		}
		msg, err := DeserializePeer(data[pos : pos+total])
		if err != nil {
			return nil, err
		}
		msgs = append(msgs, msg)
		pos += total
	}
	return msgs, nil
}

// ── Value decoding ──────────────────────────────────────────────

type decoder struct {
	data []byte
	pos  int
}

func (d *decoder) u8() uint8       { v := d.data[d.pos]; d.pos++; return v }
func (d *decoder) u32() uint32     { v := binary.LittleEndian.Uint32(d.data[d.pos:]); d.pos += 4; return v }
func (d *decoder) i32() int32      { return int32(d.u32()) }
func (d *decoder) u64() uint64     { v := binary.LittleEndian.Uint64(d.data[d.pos:]); d.pos += 8; return v }
func (d *decoder) i64() int64      { return int64(d.u64()) }
func (d *decoder) str() string     { n := d.u32(); s := string(d.data[d.pos : d.pos+int(n)]); d.pos += int(n); return s }
func (d *decoder) bytes(n int) []byte { b := make([]byte, n); copy(b, d.data[d.pos:]); d.pos += n; return b }

func (d *decoder) value() Value {
	tag := d.u8()
	switch tag {
	case 0x00:
		return nil
	case 0x01:
		return d.i64()
	case 0x02:
		bits := d.u64()
		return math.Float64frombits(bits)
	case 0x03:
		return d.str()
	case 0x04:
		n := d.u32()
		return d.bytes(int(n))
	default:
		return nil
	}
}

func decodeChangeEvent(data []byte) ChangeEvent {
	d := &decoder{data: data}
	table := d.str()
	op := OpType(d.u8())
	ncols := d.u32()
	pkFlags := make([]bool, ncols)
	for i := uint32(0); i < ncols; i++ {
		pkFlags[i] = d.u8() != 0
	}
	oldCount := d.u32()
	oldValues := make([]Value, oldCount)
	for i := uint32(0); i < oldCount; i++ {
		oldValues[i] = d.value()
	}
	newCount := d.u32()
	newValues := make([]Value, newCount)
	for i := uint32(0); i < newCount; i++ {
		newValues[i] = d.value()
	}
	return ChangeEvent{
		Table:     table,
		Op:        op,
		PKFlags:   pkFlags,
		OldValues: oldValues,
		NewValues: newValues,
	}
}

func decodeQueryResult(d *decoder) QueryResult {
	id := d.u64()
	colCount := d.u32()
	columns := make([]string, colCount)
	for i := uint32(0); i < colCount; i++ {
		columns[i] = d.str()
	}
	rowCount := d.u32()
	rows := make([][]Value, rowCount)
	for i := uint32(0); i < rowCount; i++ {
		row := make([]Value, colCount)
		for j := uint32(0); j < colCount; j++ {
			row[j] = d.value()
		}
		rows[i] = row
	}
	return QueryResult{
		ID:      SubscriptionID(id),
		Columns: columns,
		Rows:    rows,
	}
}

// decodeHandleResult decodes the binary HandleResult encoding from C.
func decodeHandleResult(buf C.sqlpipe_buf) (HandleResult, error) {
	if buf.data == nil || buf.len == 0 {
		return HandleResult{}, nil
	}
	defer C.sqlpipe_free_buf(buf)
	data := C.GoBytes(unsafe.Pointer(buf.data), C.int(buf.len))
	d := &decoder{data: data}

	// Messages.
	msgCount := d.u32()
	var msgs []Message
	for i := uint32(0); i < msgCount; i++ {
		mlen := binary.LittleEndian.Uint32(d.data[d.pos:])
		total := 4 + int(mlen)
		msg, err := Deserialize(d.data[d.pos : d.pos+total])
		if err != nil {
			return HandleResult{}, err
		}
		msgs = append(msgs, msg)
		d.pos += total
	}

	// Changes.
	changeCount := d.u32()
	var changes []ChangeEvent
	for i := uint32(0); i < changeCount; i++ {
		table := d.str()
		op := OpType(d.u8())
		ncols := d.u32()
		pkFlags := make([]bool, ncols)
		for j := uint32(0); j < ncols; j++ {
			pkFlags[j] = d.u8() != 0
		}
		oldCount := d.u32()
		oldValues := make([]Value, oldCount)
		for j := uint32(0); j < oldCount; j++ {
			oldValues[j] = d.value()
		}
		newCount := d.u32()
		newValues := make([]Value, newCount)
		for j := uint32(0); j < newCount; j++ {
			newValues[j] = d.value()
		}
		changes = append(changes, ChangeEvent{
			Table: table, Op: op, PKFlags: pkFlags,
			OldValues: oldValues, NewValues: newValues,
		})
	}

	// Subscriptions.
	subCount := d.u32()
	var subs []QueryResult
	for i := uint32(0); i < subCount; i++ {
		subs = append(subs, decodeQueryResult(d))
	}

	return HandleResult{Messages: msgs, Changes: changes, Subscriptions: subs}, nil
}

// decodePeerHandleResult decodes the binary PeerHandleResult encoding.
func decodePeerHandleResult(buf C.sqlpipe_buf) (PeerHandleResult, error) {
	if buf.data == nil || buf.len == 0 {
		return PeerHandleResult{}, nil
	}
	defer C.sqlpipe_free_buf(buf)
	data := C.GoBytes(unsafe.Pointer(buf.data), C.int(buf.len))
	d := &decoder{data: data}

	// PeerMessages.
	msgCount := d.u32()
	var msgs []PeerMessage
	for i := uint32(0); i < msgCount; i++ {
		mlen := binary.LittleEndian.Uint32(d.data[d.pos:])
		total := 4 + int(mlen)
		msg, err := DeserializePeer(d.data[d.pos : d.pos+total])
		if err != nil {
			return PeerHandleResult{}, err
		}
		msgs = append(msgs, msg)
		d.pos += total
	}

	// Changes.
	changeCount := d.u32()
	var changes []ChangeEvent
	for i := uint32(0); i < changeCount; i++ {
		table := d.str()
		op := OpType(d.u8())
		ncols := d.u32()
		pkFlags := make([]bool, ncols)
		for j := uint32(0); j < ncols; j++ {
			pkFlags[j] = d.u8() != 0
		}
		oldCount := d.u32()
		oldValues := make([]Value, oldCount)
		for j := uint32(0); j < oldCount; j++ {
			oldValues[j] = d.value()
		}
		newCount := d.u32()
		newValues := make([]Value, newCount)
		for j := uint32(0); j < newCount; j++ {
			newValues[j] = d.value()
		}
		changes = append(changes, ChangeEvent{
			Table: table, Op: op, PKFlags: pkFlags,
			OldValues: oldValues, NewValues: newValues,
		})
	}

	// Subscriptions.
	subCount := d.u32()
	var subs []QueryResult
	for i := uint32(0); i < subCount; i++ {
		subs = append(subs, decodeQueryResult(d))
	}

	return PeerHandleResult{Messages: msgs, Changes: changes, Subscriptions: subs}, nil
}

// ── Callback handle management ──────────────────────────────────

// callbackHandles holds cgo.Handles that must be kept alive for the
// lifetime of a Master/Replica/Peer. Freed on Close().
type callbackHandles []cgo.Handle

func (h *callbackHandles) add(v any) cgo.Handle {
	handle := cgo.NewHandle(v)
	*h = append(*h, handle)
	return handle
}

func (h *callbackHandles) free() {
	for _, handle := range *h {
		handle.Delete()
	}
	*h = nil
}

// ── C string array helpers ──────────────────────────────────────

// toCStrings converts a map[string]bool to a C string array.
// Caller must free with freeCStrings.
func toCStrings(m map[string]bool) (**C.char, C.size_t) {
	if len(m) == 0 {
		return nil, 0
	}
	ptrs := make([]*C.char, 0, len(m))
	for k := range m {
		ptrs = append(ptrs, C.CString(k))
	}
	return &ptrs[0], C.size_t(len(ptrs))
}

func freeCStrings(ptrs **C.char, n C.size_t) {
	if ptrs == nil {
		return
	}
	s := unsafe.Slice(ptrs, int(n))
	for _, p := range s {
		C.free(unsafe.Pointer(p))
	}
}

// tableFilterToCStrings converts a *TableFilter.
func tableFilterToCStrings(tf *TableFilter) (**C.char, C.size_t) {
	if tf == nil {
		return nil, 0
	}
	return toCStrings(tf.Tables)
}

// ── Master ──────────────────────────────────────────────────────

// Master is the sending side of the replication protocol.
type Master struct {
	ptr     *C.sqlpipe_master
	db      *Database
	handles callbackHandles
}

// NewMaster creates a Master that tracks changes on the database.
func NewMaster(db *Database, config MasterConfig) (*Master, error) {
	m := &Master{db: db}
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

	if config.OnProgress != nil {
		h := m.handles.add(config.OnProgress)
		cfg.on_progress = C.sqlpipe_progress_fn(C.cProgressTrampoline)
		cfg.progress_ctx = unsafe.Pointer(uintptr(h))
	}
	if config.OnSchemaMismatch != nil {
		h := m.handles.add(config.OnSchemaMismatch)
		cfg.on_schema_mismatch = C.sqlpipe_schema_mismatch_fn(C.cSchemaMismatchTrampoline)
		cfg.schema_mismatch_ctx = unsafe.Pointer(uintptr(h))
	}
	if config.OnLog != nil {
		h := m.handles.add(config.OnLog)
		cfg.on_log = C.sqlpipe_log_fn(C.cLogTrampoline)
		cfg.log_ctx = unsafe.Pointer(uintptr(h))
	}
	if config.OnFlush != nil {
		h := m.handles.add(config.OnFlush)
		cfg.on_flush = C.sqlpipe_flush_fn(C.cFlushTrampoline)
		cfg.flush_ctx = unsafe.Pointer(uintptr(h))
	}

	if err := convertError(C.sqlpipe_master_new(db.db, cfg, &m.ptr)); err != nil {
		m.handles.free()
		return nil, err
	}
	return m, nil
}

// Exec executes SQL on the master's database. If OnFlush is set, any
// committed changes are automatically delivered via the callback.
func (m *Master) Exec(sql string) error {
	csql := C.CString(sql)
	defer C.free(unsafe.Pointer(csql))
	return convertError(C.sqlpipe_master_exec(m.ptr, csql))
}

// Flush extracts the changeset since the last flush and returns messages to send.
func (m *Master) Flush() ([]Message, error) {
	var buf C.sqlpipe_buf
	if err := convertError(C.sqlpipe_master_flush(m.ptr, &buf)); err != nil {
		return nil, err
	}
	return decodeMessages(buf)
}

// HandleMessage processes an incoming message from a replica.
func (m *Master) HandleMessage(msg Message) ([]Message, error) {
	wire := Serialize(msg)
	var buf C.sqlpipe_buf
	if err := convertError(C.sqlpipe_master_handle_message(
		m.ptr,
		(*C.uint8_t)(unsafe.Pointer(&wire[0])), C.size_t(len(wire)),
		&buf,
	)); err != nil {
		return nil, err
	}
	return decodeMessages(buf)
}

// CurrentSeq returns the latest sequence number.
func (m *Master) CurrentSeq() Seq {
	return Seq(C.sqlpipe_master_current_seq(m.ptr))
}

// SchemaVersion returns the current schema fingerprint.
func (m *Master) SchemaVersion() SchemaVersion {
	return SchemaVersion(C.sqlpipe_master_schema_version(m.ptr))
}

// Close releases the Master.
func (m *Master) Close() error {
	if m.ptr != nil {
		C.sqlpipe_master_free(m.ptr)
		m.ptr = nil
	}
	m.handles.free()
	return nil
}

// ── Replica ─────────────────────────────────────────────────────

// Replica is the receiving side of the replication protocol.
type Replica struct {
	ptr     *C.sqlpipe_replica
	db      *Database
	handles callbackHandles
}

// NewReplica creates a Replica.
func NewReplica(db *Database, config ReplicaConfig) (*Replica, error) {
	r := &Replica{db: db}
	var cfg C.sqlpipe_replica_config

	if config.OnConflict != nil {
		h := r.handles.add(config.OnConflict)
		cfg.on_conflict = C.sqlpipe_conflict_fn(C.cConflictTrampoline)
		cfg.conflict_ctx = unsafe.Pointer(uintptr(h))
	}

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

	if config.OnProgress != nil {
		h := r.handles.add(config.OnProgress)
		cfg.on_progress = C.sqlpipe_progress_fn(C.cProgressTrampoline)
		cfg.progress_ctx = unsafe.Pointer(uintptr(h))
	}
	if config.OnSchemaMismatch != nil {
		h := r.handles.add(config.OnSchemaMismatch)
		cfg.on_schema_mismatch = C.sqlpipe_schema_mismatch_fn(C.cSchemaMismatchTrampoline)
		cfg.schema_mismatch_ctx = unsafe.Pointer(uintptr(h))
	}
	if config.OnLog != nil {
		h := r.handles.add(config.OnLog)
		cfg.on_log = C.sqlpipe_log_fn(C.cLogTrampoline)
		cfg.log_ctx = unsafe.Pointer(uintptr(h))
	}

	if err := convertError(C.sqlpipe_replica_new(db.db, cfg, &r.ptr)); err != nil {
		r.handles.free()
		return nil, err
	}
	return r, nil
}

// Hello generates the initial HelloMsg to send to the master.
func (r *Replica) Hello() (Message, error) {
	var buf C.sqlpipe_buf
	if err := convertError(C.sqlpipe_replica_hello(r.ptr, &buf)); err != nil {
		return nil, err
	}
	defer C.sqlpipe_free_buf(buf)
	data := C.GoBytes(unsafe.Pointer(buf.data), C.int(buf.len))
	return Deserialize(data)
}

// HandleMessage processes an incoming message from the master.
func (r *Replica) HandleMessage(msg Message) (HandleResult, error) {
	wire := Serialize(msg)
	var buf C.sqlpipe_buf
	if err := convertError(C.sqlpipe_replica_handle_message(
		r.ptr,
		(*C.uint8_t)(unsafe.Pointer(&wire[0])), C.size_t(len(wire)),
		&buf,
	)); err != nil {
		return HandleResult{}, err
	}
	return decodeHandleResult(buf)
}

// HandleMessages processes multiple messages, deferring subscription
// evaluation until all are applied.
func (r *Replica) HandleMessages(msgs []Message) (HandleResult, error) {
	// Encode as [u32 count][msg1][msg2]...
	var enc []byte
	enc = binary.LittleEndian.AppendUint32(enc, uint32(len(msgs)))
	for _, msg := range msgs {
		enc = append(enc, Serialize(msg)...)
	}
	var buf C.sqlpipe_buf
	if err := convertError(C.sqlpipe_replica_handle_messages(
		r.ptr,
		(*C.uint8_t)(unsafe.Pointer(&enc[0])), C.size_t(len(enc)),
		&buf,
	)); err != nil {
		return HandleResult{}, err
	}
	return decodeHandleResult(buf)
}

// Subscribe registers a query and returns the current result.
func (r *Replica) Subscribe(sql string) (QueryResult, error) {
	csql := C.CString(sql)
	defer C.free(unsafe.Pointer(csql))
	var buf C.sqlpipe_buf
	if err := convertError(C.sqlpipe_replica_subscribe(r.ptr, csql, &buf)); err != nil {
		return QueryResult{}, err
	}
	defer C.sqlpipe_free_buf(buf)
	data := C.GoBytes(unsafe.Pointer(buf.data), C.int(buf.len))
	d := &decoder{data: data}
	return decodeQueryResult(d), nil
}

// Unsubscribe removes a subscription.
func (r *Replica) Unsubscribe(id SubscriptionID) error {
	return convertError(C.sqlpipe_replica_unsubscribe(r.ptr, C.uint64_t(id)))
}

// Reset returns to Init state for reconnection.
func (r *Replica) Reset() { C.sqlpipe_replica_reset(r.ptr) }

// State returns the current replica state.
func (r *Replica) State() ReplicaState {
	return ReplicaState(C.sqlpipe_replica_state(r.ptr))
}

// CurrentSeq returns the latest applied sequence number.
func (r *Replica) CurrentSeq() Seq {
	return Seq(C.sqlpipe_replica_current_seq(r.ptr))
}

// SchemaVersion returns the current schema fingerprint.
func (r *Replica) SchemaVersion() SchemaVersion {
	return SchemaVersion(C.sqlpipe_replica_schema_version(r.ptr))
}

// Close releases the Replica.
func (r *Replica) Close() error {
	if r.ptr != nil {
		C.sqlpipe_replica_free(r.ptr)
		r.ptr = nil
	}
	r.handles.free()
	return nil
}

// ── Peer ────────────────────────────────────────────────────────

// Peer is a bidirectional replication peer.
type Peer struct {
	ptr     *C.sqlpipe_peer
	db      *Database
	handles callbackHandles
}

// NewPeer creates a Peer.
func NewPeer(db *Database, config PeerConfig) (*Peer, error) {
	p := &Peer{db: db}
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
		cfg.approve_ownership_ctx = unsafe.Pointer(uintptr(h))
	}
	if config.OnConflict != nil {
		h := p.handles.add(config.OnConflict)
		cfg.on_conflict = C.sqlpipe_conflict_fn(C.cConflictTrampoline)
		cfg.conflict_ctx = unsafe.Pointer(uintptr(h))
	}
	if config.OnProgress != nil {
		h := p.handles.add(config.OnProgress)
		cfg.on_progress = C.sqlpipe_progress_fn(C.cProgressTrampoline)
		cfg.progress_ctx = unsafe.Pointer(uintptr(h))
	}
	if config.OnSchemaMismatch != nil {
		h := p.handles.add(config.OnSchemaMismatch)
		cfg.on_schema_mismatch = C.sqlpipe_schema_mismatch_fn(C.cSchemaMismatchTrampoline)
		cfg.schema_mismatch_ctx = unsafe.Pointer(uintptr(h))
	}
	if config.OnLog != nil {
		h := p.handles.add(config.OnLog)
		cfg.on_log = C.sqlpipe_log_fn(C.cLogTrampoline)
		cfg.log_ctx = unsafe.Pointer(uintptr(h))
	}

	if err := convertError(C.sqlpipe_peer_new(db.db, cfg, &p.ptr)); err != nil {
		p.handles.free()
		return nil, err
	}
	return p, nil
}

// Start initiates the handshake (client only).
func (p *Peer) Start() ([]PeerMessage, error) {
	var buf C.sqlpipe_buf
	if err := convertError(C.sqlpipe_peer_start(p.ptr, &buf)); err != nil {
		return nil, err
	}
	return decodePeerMessages(buf)
}

// Flush extracts changes on owned tables.
func (p *Peer) Flush() ([]PeerMessage, error) {
	var buf C.sqlpipe_buf
	if err := convertError(C.sqlpipe_peer_flush(p.ptr, &buf)); err != nil {
		return nil, err
	}
	return decodePeerMessages(buf)
}

// Subscribe registers a query on the peer's replica side.
func (p *Peer) Subscribe(sql string) (QueryResult, error) {
	csql := C.CString(sql)
	defer C.free(unsafe.Pointer(csql))
	var buf C.sqlpipe_buf
	if err := convertError(C.sqlpipe_peer_subscribe(p.ptr, csql, &buf)); err != nil {
		return QueryResult{}, err
	}
	defer C.sqlpipe_free_buf(buf)
	data := C.GoBytes(unsafe.Pointer(buf.data), C.int(buf.len))
	d := &decoder{data: data}
	return decodeQueryResult(d), nil
}

// Unsubscribe removes a subscription from the peer's replica side.
func (p *Peer) Unsubscribe(id SubscriptionID) error {
	return convertError(C.sqlpipe_peer_unsubscribe(p.ptr, C.uint64_t(id)))
}

// HandleMessage processes an incoming PeerMessage.
func (p *Peer) HandleMessage(msg PeerMessage) (PeerHandleResult, error) {
	wire := SerializePeer(msg)
	var buf C.sqlpipe_buf
	if err := convertError(C.sqlpipe_peer_handle_message(
		p.ptr,
		(*C.uint8_t)(unsafe.Pointer(&wire[0])), C.size_t(len(wire)),
		&buf,
	)); err != nil {
		return PeerHandleResult{}, err
	}
	return decodePeerHandleResult(buf)
}

// Reset returns to Init state for reconnection.
func (p *Peer) Reset() { C.sqlpipe_peer_reset(p.ptr) }

// State returns the current peer state.
func (p *Peer) State() PeerState {
	return PeerState(C.sqlpipe_peer_state(p.ptr))
}

// OwnedTables returns the tables this peer owns.
func (p *Peer) OwnedTables() map[string]bool {
	var arr **C.char
	var count C.size_t
	C.sqlpipe_peer_owned_tables(p.ptr, &arr, &count)
	defer C.sqlpipe_free_string_array(arr, count)
	return cStringArrayToMap(arr, count)
}

// RemoteTables returns the tables the remote peer owns.
func (p *Peer) RemoteTables() map[string]bool {
	var arr **C.char
	var count C.size_t
	C.sqlpipe_peer_remote_tables(p.ptr, &arr, &count)
	defer C.sqlpipe_free_string_array(arr, count)
	return cStringArrayToMap(arr, count)
}

// Close releases the Peer.
func (p *Peer) Close() error {
	if p.ptr != nil {
		C.sqlpipe_peer_free(p.ptr)
		p.ptr = nil
	}
	p.handles.free()
	return nil
}

func cStringArrayToMap(arr **C.char, count C.size_t) map[string]bool {
	if arr == nil || count == 0 {
		return nil
	}
	n := int(count)
	ptrs := unsafe.Slice(arr, n)
	m := make(map[string]bool, n)
	for _, p := range ptrs {
		m[C.GoString(p)] = true
	}
	return m
}

// ── Convenience utilities ────────────────────────────────────────

// SyncHandshake drives the Master/Replica handshake protocol to completion
// when both are in the same process. Exchanges messages until no more remain.
func SyncHandshake(m *Master, r *Replica) error {
	hello, err := r.Hello()
	if err != nil {
		return err
	}
	pending, err := m.HandleMessage(hello)
	if err != nil {
		return err
	}
	for len(pending) > 0 {
		var forMaster []Message
		for _, msg := range pending {
			hr, err := r.HandleMessage(msg)
			if err != nil {
				return err
			}
			forMaster = append(forMaster, hr.Messages...)
		}
		pending = nil
		for _, msg := range forMaster {
			resp, err := m.HandleMessage(msg)
			if err != nil {
				return err
			}
			pending = append(pending, resp...)
		}
	}
	return nil
}

// SyncPeerHandshake drives the Peer handshake protocol to completion when
// both peers are in the same process. The client initiates; messages are
// exchanged until both peers reach Live state or no more messages remain.
func SyncPeerHandshake(client, server *Peer) error {
	pendingForServer, err := client.Start()
	if err != nil {
		return err
	}
	for len(pendingForServer) > 0 ||
		client.State() != PeerLive || server.State() != PeerLive {
		var pendingForClient []PeerMessage
		for _, msg := range pendingForServer {
			hr, err := server.HandleMessage(msg)
			if err != nil {
				return err
			}
			pendingForClient = append(pendingForClient, hr.Messages...)
		}
		pendingForServer = nil
		for _, msg := range pendingForClient {
			hr, err := client.HandleMessage(msg)
			if err != nil {
				return err
			}
			pendingForServer = append(pendingForServer, hr.Messages...)
		}
		if len(pendingForServer) == 0 &&
			(client.State() != PeerLive || server.State() != PeerLive) {
			break
		}
	}
	return nil
}
