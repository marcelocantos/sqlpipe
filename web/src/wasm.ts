// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0
//
// Low-level Wasm module interface. Not part of the public API.

/** Emscripten module instance type (subset of what we use). */
export interface WasmModule {
  _malloc(size: number): number;
  _free(ptr: number): void;

  HEAPU8: Uint8Array;
  getValue(ptr: number, type: string): number;
  setValue(ptr: number, value: number, type: string): void;
  UTF8ToString(ptr: number, maxLength?: number): string;
  stringToUTF8OnStack(str: string): number;
  stackSave(): number;
  stackRestore(sp: number): void;
  addFunction(fn: Function, sig: string): number;
  removeFunction(ptr: number): void;

  // All our exported C functions.
  [key: `_${string}`]: (...args: any[]) => any;
}

/** Read a sqlpipe_buf {data, len} from the heap. Returns a copy. */
export function readBuf(M: WasmModule, bufPtr: number): Uint8Array {
  const data = M.getValue(bufPtr, 'i32');
  const len = M.getValue(bufPtr + 4, 'i32');
  if (len === 0 || data === 0) return new Uint8Array(0);
  const copy = new Uint8Array(M.HEAPU8.buffer, data, len).slice();
  M._sqlpipe_free_buf(data);
  return copy;
}

/** Check a sqlpipe_error {code, msg} and throw if non-zero. */
export function checkError(M: WasmModule, errPtr: number): void {
  const code = M.getValue(errPtr, 'i32');
  if (code !== 0) {
    const msgPtr = M.getValue(errPtr + 4, 'i32');
    const msg = msgPtr ? M.UTF8ToString(msgPtr) : 'unknown error';
    M._sqlpipe_free_error(msgPtr);
    throw new SqlpipeError(code, msg);
  }
}

export class SqlpipeError extends Error {
  code: number;
  constructor(code: number, message: string) {
    super(message);
    this.name = 'SqlpipeError';
    this.code = code;
  }
}

/** Allocate a C string array on the stack. Returns [ptr, count]. */
export function stackStringArray(
  M: WasmModule, strings: string[]
): [number, number] {
  const ptrs = M.stackSave();
  // Allocate space for the pointer array.
  const arr = M._malloc(strings.length * 4);
  for (let i = 0; i < strings.length; i++) {
    const sPtr = M.stringToUTF8OnStack(strings[i]);
    M.setValue(arr + i * 4, sPtr, 'i32');
  }
  return [arr, strings.length];
}

/** Helper to run a function with stack save/restore. */
export function withStack<T>(M: WasmModule, fn: () => T): T {
  const sp = M.stackSave();
  try {
    return fn();
  } finally {
    M.stackRestore(sp);
  }
}
