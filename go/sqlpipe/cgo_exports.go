// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

// This file contains //export functions for CGo callback trampolines.
package sqlpipe

/*
#include <stdint.h>
#include <stddef.h>
*/
import "C"

import (
	"runtime/cgo"
	"unsafe"
)

//export goProgressTrampoline
func goProgressTrampoline(handle C.uintptr_t, phase C.uint8_t, table *C.char, done C.int64_t, total C.int64_t) {
	h := cgo.Handle(handle)
	fn := h.Value().(ProgressCallback)
	fn(DiffProgress{
		Phase:      DiffPhase(phase),
		Table:      C.GoString(table),
		ItemsDone:  int64(done),
		ItemsTotal: int64(total),
	})
}

//export goSchemaMismatchTrampoline
func goSchemaMismatchTrampoline(handle C.uintptr_t, remoteSV C.int32_t, localSV C.int32_t, remoteSQL *C.char) C.int {
	h := cgo.Handle(handle)
	fn := h.Value().(SchemaMismatchCallback)
	if fn(SchemaVersion(remoteSV), SchemaVersion(localSV), C.GoString(remoteSQL)) {
		return 1
	}
	return 0
}

//export goConflictTrampoline
func goConflictTrampoline(handle C.uintptr_t, conflictType C.uint8_t, eventData *C.uint8_t, eventLen C.size_t) C.uint8_t {
	h := cgo.Handle(handle)
	fn := h.Value().(ConflictCallback)
	data := C.GoBytes(unsafe.Pointer(eventData), C.int(eventLen))
	event := decodeChangeEvent(data)
	action := fn(ConflictType(conflictType), event)
	return C.uint8_t(action)
}

//export goLogTrampoline
func goLogTrampoline(handle C.uintptr_t, level C.uint8_t, message *C.char) {
	h := cgo.Handle(handle)
	fn := h.Value().(LogCallback)
	fn(LogLevel(level), C.GoString(message))
}

//export goFlushTrampoline
func goFlushTrampoline(handle C.uintptr_t, data *C.uint8_t, dataLen C.size_t) {
	h := cgo.Handle(handle)
	fn := h.Value().(FlushCallback)
	buf := C.GoBytes(unsafe.Pointer(data), C.int(dataLen))
	msgs, err := decodeMessagesFromBytes(buf)
	if err != nil {
		return // Best-effort: silently drop on decode error.
	}
	fn(msgs)
}

//export goApproveOwnershipTrampoline
func goApproveOwnershipTrampoline(handle C.uintptr_t, tables **C.char, count C.size_t) C.int {
	h := cgo.Handle(handle)
	fn := h.Value().(ApproveOwnershipCallback)
	n := int(count)
	goTables := make(map[string]bool, n)
	ptrs := unsafe.Slice(tables, n)
	for _, p := range ptrs {
		goTables[C.GoString(p)] = true
	}
	if fn(goTables) {
		return 1
	}
	return 0
}
