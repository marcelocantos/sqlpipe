// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package sqlpipe

import "fmt"

// ErrorCode identifies the category of a sqlpipe error.
type ErrorCode int

const (
	ErrOk               ErrorCode = 0
	ErrSqlite           ErrorCode = 1
	ErrProtocol         ErrorCode = 2
	ErrSchemaMismatch   ErrorCode = 3
	ErrInvalidState     ErrorCode = 4
	ErrOwnershipReject  ErrorCode = 5
	ErrWithoutRowidTbl  ErrorCode = 6
)

// Error is the error type returned by sqlpipe operations.
type Error struct {
	Code ErrorCode
	Msg  string
}

func (e *Error) Error() string { return e.Msg }

func errorf(code ErrorCode, format string, args ...any) *Error {
	return &Error{Code: code, Msg: fmt.Sprintf(format, args...)}
}
