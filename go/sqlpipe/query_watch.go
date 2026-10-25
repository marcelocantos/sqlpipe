// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package sqlpipe

/*
#include <stdlib.h>
#include "sqlpipe_capi.h"
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// QueryWatch keeps native query dependencies and result hashes for a database,
// independently of any replication connection. Tables must have explicit primary
// keys, as required by sqlpipe replication. Serialize access with all database
// operations and close the watch before its database. Only one watch is needed
// for any number of subscriptions.
type QueryWatch struct{ ptr *C.sqlpipe_query_watch }

func NewQueryWatch(db *Database) (*QueryWatch, error) {
	w := &QueryWatch{}
	if err := convertError(C.sqlpipe_query_watch_new(db.db, &w.ptr)); err != nil {
		return nil, err
	}
	return w, nil
}

// Subscribe registers SQL or sqldeep and returns its initial cached result.
// It does not drain pending changes or notify other subscriptions.
func (w *QueryWatch) Subscribe(query string) (QueryResult, error) {
	if w.ptr == nil {
		return QueryResult{}, fmt.Errorf("sqlpipe: query watch closed")
	}
	sql, err := transpile(query)
	if err != nil {
		return QueryResult{}, err
	}
	csql := C.CString(sql)
	defer C.free(unsafe.Pointer(csql))
	var buf C.sqlpipe_buf
	if err := convertError(C.sqlpipe_query_watch_subscribe(w.ptr, csql, &buf)); err != nil {
		return QueryResult{}, err
	}
	defer C.sqlpipe_free_buf(buf)
	d := decoder{data: C.GoBytes(unsafe.Pointer(buf.data), C.int(buf.len))}
	return decodeQueryResult(&d), nil
}

func (w *QueryWatch) Unsubscribe(id SubscriptionID) {
	if w.ptr != nil {
		C.sqlpipe_query_watch_unsubscribe(w.ptr, C.uint64_t(id))
	}
}

// Notify evaluates native dependencies against net changes since the previous
// notification, including writes by replication. Call after a complete local
// batch or after replication reaches Live, never during incomplete sync. An open
// transaction defers notification; rollbacks and same-value writes emit nothing.
func (w *QueryWatch) Notify() ([]QueryResult, error) {
	if w.ptr == nil {
		return nil, fmt.Errorf("sqlpipe: query watch closed")
	}
	var buf C.sqlpipe_buf
	if err := convertError(C.sqlpipe_query_watch_notify(w.ptr, &buf)); err != nil {
		return nil, err
	}
	if buf.data == nil {
		return nil, nil
	}
	defer C.sqlpipe_free_buf(buf)
	d := decoder{data: C.GoBytes(unsafe.Pointer(buf.data), C.int(buf.len))}
	results := make([]QueryResult, d.u32())
	for i := range results {
		results[i] = decodeQueryResult(&d)
	}
	return results, nil
}

func (w *QueryWatch) Close() error {
	if w.ptr != nil {
		C.sqlpipe_query_watch_free(w.ptr)
		w.ptr = nil
	}
	return nil
}
