// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

export * from './types.js';

import type {
  ApproveOwnershipCallback, ConflictCallback, HandleResult,
  LogCallback, MasterConfig, PeerConfig, PeerHandleResult,
  ProgressCallback, QueryResult, ReplicaConfig, SchemaMismatchCallback,
} from './types.js';
import { ConflictAction, PeerState, ReplicaState, SqldeepBackend } from './types.js';
import { decodeHandleResult, decodeMessages, decodePeerHandleResult, decodeQueryResult, decodeChangeEvent, Reader } from './decode.js';
import { type WasmModule, SqlpipeError, readBuf, checkError, withStack } from './wasm.js';

export { SqlpipeError };

// Re-export for tree-shaking convenience.
export { Reader, decodeHandleResult, decodeMessages, decodePeerHandleResult, decodeQueryResult };

// ── Callback registration ───────────────────────────────────────

type RegisteredFn = number; // Emscripten function pointer

function registerLogCb(M: WasmModule, cb: LogCallback | undefined, fns: RegisteredFn[]): number {
  if (!cb) return 0;
  const ptr = M.addFunction((ctx: number, level: number, msgPtr: number) => {
    cb(level, M.UTF8ToString(msgPtr));
  }, 'viii');
  fns.push(ptr);
  return ptr;
}

function registerProgressCb(M: WasmModule, cb: ProgressCallback | undefined, fns: RegisteredFn[]): number {
  if (!cb) return 0;
  const ptr = M.addFunction(
    (ctx: number, phase: number, tablePtr: number, done: number, total: number) => {
      cb(phase, M.UTF8ToString(tablePtr), done, total);
    }, 'viiiii');
  fns.push(ptr);
  return ptr;
}

function registerSchemaMismatchCb(
  M: WasmModule, cb: SchemaMismatchCallback | undefined, fns: RegisteredFn[]
): number {
  if (!cb) return 0;
  const ptr = M.addFunction(
    (ctx: number, rsv: number, lsv: number, rsqlPtr: number) => {
      return cb(rsv, lsv, M.UTF8ToString(rsqlPtr)) ? 1 : 0;
    }, 'iiiii');
  fns.push(ptr);
  return ptr;
}

function registerConflictCb(
  M: WasmModule, cb: ConflictCallback | undefined, fns: RegisteredFn[]
): number {
  if (!cb) return 0;
  const ptr = M.addFunction(
    (ctx: number, ctype: number, dataPtr: number, dataLen: number) => {
      const buf = new Uint8Array(M.HEAPU8.buffer, dataPtr, dataLen).slice();
      const event = decodeChangeEvent(new Reader(buf));
      return cb(ctype, event);
    }, 'iiiii');
  fns.push(ptr);
  return ptr;
}

function registerApproveOwnershipCb(
  M: WasmModule, cb: ApproveOwnershipCallback | undefined, fns: RegisteredFn[]
): number {
  if (!cb) return 0;
  const ptr = M.addFunction(
    (ctx: number, tablesPtr: number, count: number) => {
      const tables: string[] = [];
      for (let i = 0; i < count; i++) {
        const sPtr = M.getValue(tablesPtr + i * 4, 'i32');
        tables.push(M.UTF8ToString(sPtr));
      }
      return cb(tables) ? 1 : 0;
    }, 'iiii');
  fns.push(ptr);
  return ptr;
}

function unregisterAll(M: WasmModule, fns: RegisteredFn[]): void {
  for (const ptr of fns) M.removeFunction(ptr);
  fns.length = 0;
}

// ── Database ────────────────────────────────────────────────────

/** A SQLite database handle managed by the Wasm module. */
export class Database {
  /** @internal */ readonly _M: WasmModule;
  /** @internal */ readonly _ptr: number;

  /** @internal */
  constructor(M: WasmModule, ptr: number) {
    this._M = M;
    this._ptr = ptr;
  }

  /** Execute SQL (no result). Throws on error. */
  exec(sql: string): void {
    const rc = withStack(this._M, () =>
      this._M._sqlpipe_db_exec(this._ptr, this._M.stringToUTF8OnStack(sql))
    );
    if (rc !== 0) {
      const msg = this._M.UTF8ToString(this._M._sqlpipe_db_errmsg(this._ptr));
      throw new SqlpipeError(rc, msg);
    }
  }

  /** Serialize the database to a byte array. */
  serialize(): Uint8Array {
    const dataPtr = this._M._malloc(4);
    const lenPtr = this._M._malloc(8);
    try {
      const rc = this._M._sqlpipe_db_serialize(this._ptr, dataPtr, lenPtr);
      if (rc !== 0) throw new SqlpipeError(rc, 'serialize failed');
      const data = this._M.getValue(dataPtr, 'i32');
      const len = this._M.getValue(lenPtr, 'i32');
      const copy = new Uint8Array(this._M.HEAPU8.buffer, data, len).slice();
      this._M._sqlpipe_db_free_serialized(data);
      return copy;
    } finally {
      this._M._free(dataPtr);
      this._M._free(lenPtr);
    }
  }

  /** Deserialize a byte array into this database, replacing its contents. */
  deserialize(data: Uint8Array): void {
    const ptr = this._M._malloc(data.length);
    this._M.HEAPU8.set(data, ptr);
    const rc = this._M._sqlpipe_db_deserialize(this._ptr, ptr, BigInt(data.length));
    this._M._free(ptr);
    if (rc !== 0) {
      const msg = this._M.UTF8ToString(this._M._sqlpipe_db_errmsg(this._ptr));
      throw new SqlpipeError(rc, `deserialize failed: ${msg}`);
    }
  }

  /** Save database to OPFS. Requires browser with File System API. */
  async saveToOPFS(filename: string): Promise<void> {
    const root = await navigator.storage.getDirectory();
    const handle = await root.getFileHandle(filename, { create: true });
    const writable = await handle.createWritable();
    const data = this.serialize();
    await writable.write(data.buffer as ArrayBuffer);
    await writable.close();
  }

  /** Load database contents from OPFS. */
  async loadFromOPFS(filename: string): Promise<void> {
    const root = await navigator.storage.getDirectory();
    const handle = await root.getFileHandle(filename);
    const file = await handle.getFile();
    const buf = new Uint8Array(await file.arrayBuffer());
    this.deserialize(buf);
  }

  close(): void {
    this._M._sqlpipe_db_close(this._ptr);
  }
}

// ── Master ──────────────────────────────────────────────────────

export class Master {
  private M: WasmModule;
  private ptr: number;
  private fns: RegisteredFn[] = [];
  private errPtr: number;
  private bufPtr: number;

  /** @internal */
  constructor(M: WasmModule, db: Database, config: MasterConfig = {}) {
    this.M = M;
    this.errPtr = M._malloc(8);
    this.bufPtr = M._malloc(8);

    const outPtr = M._malloc(4);
    try {
      withStack(M, () => {
        const [tfPtr, tfCount] = config.tableFilter
          ? allocStringArray(M, config.tableFilter) : [0, 0];
        const seqKeyPtr = config.seqKey ? M.stringToUTF8OnStack(config.seqKey) : 0;

        M._sqlpipe_master_new(
          db._ptr,
          tfPtr, tfCount,
          seqKeyPtr, BigInt(config.bucketSize ?? 0),
          registerProgressCb(M, config.onProgress, this.fns), 0,
          registerSchemaMismatchCb(M, config.onSchemaMismatch, this.fns), 0,
          registerLogCb(M, config.onLog, this.fns), 0,
          outPtr, this.errPtr);
        checkError(M, this.errPtr);

        if (tfPtr) M._free(tfPtr);
      });
      this.ptr = M.getValue(outPtr, 'i32');
    } finally {
      M._free(outPtr);
    }
  }

  /** Flush pending changes. Returns wire-format messages to send to replicas. */
  flush(): Uint8Array[] {
    this.M._sqlpipe_master_flush(this.ptr, this.bufPtr, this.errPtr);
    checkError(this.M, this.errPtr);
    const raw = readBuf(this.M, this.bufPtr);
    return raw.length > 0 ? decodeMessages(raw) : [];
  }

  /** Handle a message from a replica. Returns response messages. */
  handleMessage(msg: Uint8Array): Uint8Array[] {
    const msgPtr = this.M._malloc(msg.length);
    this.M.HEAPU8.set(msg, msgPtr);
    try {
      this.M._sqlpipe_master_handle_message(
        this.ptr, msgPtr, msg.length, this.bufPtr, this.errPtr);
      checkError(this.M, this.errPtr);
      const raw = readBuf(this.M, this.bufPtr);
      return raw.length > 0 ? decodeMessages(raw) : [];
    } finally {
      this.M._free(msgPtr);
    }
  }

  get currentSeq(): bigint {
    return this.M._sqlpipe_master_current_seq(this.ptr);
  }

  get schemaVersion(): number {
    return this.M._sqlpipe_master_schema_version(this.ptr);
  }

  close(): void {
    this.M._sqlpipe_master_free(this.ptr);
    unregisterAll(this.M, this.fns);
    this.M._free(this.errPtr);
    this.M._free(this.bufPtr);
  }
}

// ── Replica ─────────────────────────────────────────────────────

export class Replica {
  private M: WasmModule;
  private ptr: number;
  private fns: RegisteredFn[] = [];
  private errPtr: number;
  private bufPtr: number;

  /** @internal */
  constructor(M: WasmModule, db: Database, config: ReplicaConfig = {}) {
    this.M = M;
    this.errPtr = M._malloc(8);
    this.bufPtr = M._malloc(8);

    const outPtr = M._malloc(4);
    try {
      withStack(M, () => {
        const [tfPtr, tfCount] = config.tableFilter
          ? allocStringArray(M, config.tableFilter) : [0, 0];
        const seqKeyPtr = config.seqKey ? M.stringToUTF8OnStack(config.seqKey) : 0;

        M._sqlpipe_replica_new(
          db._ptr,
          registerConflictCb(M, config.onConflict, this.fns), 0,
          tfPtr, tfCount,
          seqKeyPtr, BigInt(config.bucketSize ?? 0),
          registerProgressCb(M, config.onProgress, this.fns), 0,
          registerSchemaMismatchCb(M, config.onSchemaMismatch, this.fns), 0,
          registerLogCb(M, config.onLog, this.fns), 0,
          outPtr, this.errPtr);
        checkError(M, this.errPtr);

        if (tfPtr) M._free(tfPtr);
      });
      this.ptr = M.getValue(outPtr, 'i32');
    } finally {
      M._free(outPtr);
    }
  }

  /** Generate the HelloMsg to send to the master. */
  hello(): Uint8Array {
    this.M._sqlpipe_replica_hello(this.ptr, this.bufPtr, this.errPtr);
    checkError(this.M, this.errPtr);
    return readBuf(this.M, this.bufPtr);
  }

  /** Handle a message from the master. */
  handleMessage(msg: Uint8Array): HandleResult {
    const msgPtr = this.M._malloc(msg.length);
    this.M.HEAPU8.set(msg, msgPtr);
    try {
      this.M._sqlpipe_replica_handle_message(
        this.ptr, msgPtr, msg.length, this.bufPtr, this.errPtr);
      checkError(this.M, this.errPtr);
      const raw = readBuf(this.M, this.bufPtr);
      return decodeHandleResult(raw);
    } finally {
      this.M._free(msgPtr);
    }
  }

  /** Subscribe to a SQL query. Returns the current result. */
  subscribe(sql: string): QueryResult {
    withStack(this.M, () => {
      this.M._sqlpipe_replica_subscribe(
        this.ptr, this.M.stringToUTF8OnStack(sql), this.bufPtr, this.errPtr);
    });
    checkError(this.M, this.errPtr);
    const raw = readBuf(this.M, this.bufPtr);
    return decodeQueryResult(new Reader(raw));
  }

  /** Remove a subscription. */
  unsubscribe(id: bigint): void {
    this.M._sqlpipe_replica_unsubscribe(this.ptr, id, this.errPtr);
    checkError(this.M, this.errPtr);
  }

  /** Reset to Init state for reconnection. Subscriptions are preserved. */
  reset(): void {
    this.M._sqlpipe_replica_reset(this.ptr);
  }

  get state(): ReplicaState {
    return this.M._sqlpipe_replica_state(this.ptr);
  }

  get currentSeq(): bigint {
    return this.M._sqlpipe_replica_current_seq(this.ptr);
  }

  get schemaVersion(): number {
    return this.M._sqlpipe_replica_schema_version(this.ptr);
  }

  close(): void {
    this.M._sqlpipe_replica_free(this.ptr);
    unregisterAll(this.M, this.fns);
    this.M._free(this.errPtr);
    this.M._free(this.bufPtr);
  }
}

// ── Peer ────────────────────────────────────────────────────────

export class Peer {
  private M: WasmModule;
  private ptr: number;
  private fns: RegisteredFn[] = [];
  private errPtr: number;
  private bufPtr: number;

  /** @internal */
  constructor(M: WasmModule, db: Database, config: PeerConfig) {
    this.M = M;
    this.errPtr = M._malloc(8);
    this.bufPtr = M._malloc(8);

    const outPtr = M._malloc(4);
    try {
      withStack(M, () => {
        const [otPtr, otCount] = allocStringArray(M, config.ownedTables);
        const [tfPtr, tfCount] = config.tableFilter
          ? allocStringArray(M, config.tableFilter) : [0, 0];

        M._sqlpipe_peer_new(
          db._ptr,
          otPtr, otCount,
          tfPtr, tfCount,
          registerApproveOwnershipCb(M, config.approveOwnership, this.fns), 0,
          registerConflictCb(M, config.onConflict, this.fns), 0,
          registerProgressCb(M, config.onProgress, this.fns), 0,
          registerSchemaMismatchCb(M, config.onSchemaMismatch, this.fns), 0,
          registerLogCb(M, config.onLog, this.fns), 0,
          outPtr, this.errPtr);
        checkError(M, this.errPtr);

        M._free(otPtr);
        if (tfPtr) M._free(tfPtr);
      });
      this.ptr = M.getValue(outPtr, 'i32');
    } finally {
      M._free(outPtr);
    }
  }

  /** Initiate the handshake (client only). Returns messages to send. */
  start(): Uint8Array[] {
    this.M._sqlpipe_peer_start(this.ptr, this.bufPtr, this.errPtr);
    checkError(this.M, this.errPtr);
    const raw = readBuf(this.M, this.bufPtr);
    return raw.length > 0 ? decodeMessages(raw) : [];
  }

  /** Flush local changes on owned tables. Returns messages to send. */
  flush(): Uint8Array[] {
    this.M._sqlpipe_peer_flush(this.ptr, this.bufPtr, this.errPtr);
    checkError(this.M, this.errPtr);
    const raw = readBuf(this.M, this.bufPtr);
    return raw.length > 0 ? decodeMessages(raw) : [];
  }

  /** Handle an incoming PeerMessage. */
  handleMessage(msg: Uint8Array): PeerHandleResult {
    const msgPtr = this.M._malloc(msg.length);
    this.M.HEAPU8.set(msg, msgPtr);
    try {
      this.M._sqlpipe_peer_handle_message(
        this.ptr, msgPtr, msg.length, this.bufPtr, this.errPtr);
      checkError(this.M, this.errPtr);
      const raw = readBuf(this.M, this.bufPtr);
      return decodePeerHandleResult(raw);
    } finally {
      this.M._free(msgPtr);
    }
  }

  /** Subscribe to a query on the replica side. Returns current result. */
  subscribe(sql: string): QueryResult {
    withStack(this.M, () => {
      this.M._sqlpipe_peer_subscribe(
        this.ptr, this.M.stringToUTF8OnStack(sql), this.bufPtr, this.errPtr);
    });
    checkError(this.M, this.errPtr);
    const raw = readBuf(this.M, this.bufPtr);
    return decodeQueryResult(new Reader(raw));
  }

  /** Remove a subscription. */
  unsubscribe(id: bigint): void {
    this.M._sqlpipe_peer_unsubscribe(this.ptr, id, this.errPtr);
    checkError(this.M, this.errPtr);
  }

  reset(): void { this.M._sqlpipe_peer_reset(this.ptr); }

  get state(): PeerState {
    return this.M._sqlpipe_peer_state(this.ptr);
  }

  close(): void {
    this.M._sqlpipe_peer_free(this.ptr);
    unregisterAll(this.M, this.fns);
    this.M._free(this.errPtr);
    this.M._free(this.bufPtr);
  }
}

// ── QueryWatch ──────────────────────────────────────────────────

export class QueryWatch {
  private M: WasmModule;
  private ptr: number;
  private errPtr: number;
  private bufPtr: number;

  /** @internal */
  constructor(M: WasmModule, db: Database) {
    this.M = M;
    this.ptr = M._sqlpipe_query_watch_new(db._ptr);
    this.errPtr = M._malloc(8);
    this.bufPtr = M._malloc(8);
  }

  /** Subscribe to a query. Returns the current result. */
  subscribe(sql: string): QueryResult {
    withStack(this.M, () => {
      this.M._sqlpipe_query_watch_subscribe(
        this.ptr, this.M.stringToUTF8OnStack(sql), this.bufPtr, this.errPtr);
    });
    checkError(this.M, this.errPtr);
    const raw = readBuf(this.M, this.bufPtr);
    return decodeQueryResult(new Reader(raw));
  }

  unsubscribe(id: bigint): void {
    this.M._sqlpipe_query_watch_unsubscribe(this.ptr, id);
  }

  /** Re-evaluate subscriptions affected by changes to the given tables. */
  notify(tables: string[]): QueryResult[] {
    const [arrPtr, count] = allocStringArray(this.M, tables);
    try {
      this.M._sqlpipe_query_watch_notify(
        this.ptr, arrPtr, count, this.bufPtr, this.errPtr);
      checkError(this.M, this.errPtr);
      const raw = readBuf(this.M, this.bufPtr);
      if (raw.length === 0) return [];
      const r = new Reader(raw);
      const n = r.u32();
      const results: QueryResult[] = [];
      for (let i = 0; i < n; i++) results.push(decodeQueryResult(r));
      return results;
    } finally {
      this.M._free(arrPtr);
    }
  }

  get empty(): boolean {
    return this.M._sqlpipe_query_watch_empty(this.ptr) !== 0;
  }

  close(): void {
    this.M._sqlpipe_query_watch_free(this.ptr);
    this.M._free(this.errPtr);
    this.M._free(this.bufPtr);
  }
}

// ── Sqlpipe (top-level) ─────────────────────────────────────────

export class Sqlpipe {
  /** @internal */
  readonly _M: WasmModule;
  private errPtr: number;

  /** @internal */
  constructor(M: WasmModule) {
    this._M = M;
    this.errPtr = M._malloc(8);
  }

  /** Library version string. */
  get version(): string {
    return this._M.UTF8ToString(this._M._sqlpipe_version());
  }

  /** Wire protocol version. */
  get protocolVersion(): number {
    return this._M._sqlpipe_protocol_version();
  }

  /** Open a SQLite database. Use ":memory:" for in-memory. */
  openDatabase(path: string): Database {
    const ptr = withStack(this._M, () =>
      this._M._sqlpipe_db_open(this._M.stringToUTF8OnStack(path))
    );
    if (!ptr) throw new SqlpipeError(1, `failed to open database: ${path}`);
    return new Database(this._M, ptr);
  }

  createMaster(db: Database, config?: MasterConfig): Master {
    return new Master(this._M, db, config);
  }

  createReplica(db: Database, config?: ReplicaConfig): Replica {
    return new Replica(this._M, db, config);
  }

  createPeer(db: Database, config: PeerConfig): Peer {
    return new Peer(this._M, db, config);
  }

  createQueryWatch(db: Database): QueryWatch {
    return new QueryWatch(this._M, db);
  }

  /** Drive the Master/Replica handshake to completion (same-process). */
  syncHandshake(master: Master, replica: Replica): void {
    (this._M as any)._sqlpipe_sync_handshake(
      (master as any).ptr, (replica as any).ptr, this.errPtr);
    checkError(this._M, this.errPtr);
  }

  /** Drive the Peer handshake to completion (same-process). */
  syncHandshakePeer(client: Peer, server: Peer): void {
    (this._M as any)._sqlpipe_sync_handshake_peer(
      (client as any).ptr, (server as any).ptr, this.errPtr);
    checkError(this._M, this.errPtr);
  }

  /** Transpile sqldeep syntax to standard SQL (SQLite backend). */
  transpile(input: string, backend: SqldeepBackend = SqldeepBackend.SQLite): string {
    const errMsgPtr = this._M._malloc(4);
    const errLinePtr = this._M._malloc(4);
    const errColPtr = this._M._malloc(4);
    this._M.setValue(errMsgPtr, 0, 'i32');

    try {
      const resultPtr = withStack(this._M, () =>
        this._M._wasm_sqldeep_transpile_backend(
          this._M.stringToUTF8OnStack(input), backend,
          errMsgPtr, errLinePtr, errColPtr)
      );

      if (resultPtr) {
        const result = this._M.UTF8ToString(resultPtr);
        this._M._wasm_sqldeep_free(resultPtr);
        return result;
      } else {
        const msgPtr = this._M.getValue(errMsgPtr, 'i32');
        const msg = msgPtr ? this._M.UTF8ToString(msgPtr) : 'transpile failed';
        const line = this._M.getValue(errLinePtr, 'i32');
        const col = this._M.getValue(errColPtr, 'i32');
        if (msgPtr) this._M._wasm_sqldeep_free(msgPtr);
        throw new SqlpipeError(1, `${msg} at line ${line}, col ${col}`);
      }
    } finally {
      this._M._free(errMsgPtr);
      this._M._free(errLinePtr);
      this._M._free(errColPtr);
    }
  }

  /** sqldeep version string. */
  get sqldeepVersion(): string {
    return this._M.UTF8ToString(this._M._wasm_sqldeep_version());
  }
}

// ── Helpers ─────────────────────────────────────────────────────

/** Allocate a heap string array (caller must free the array pointer). */
function allocStringArray(M: WasmModule, strings: string[]): [number, number] {
  const arr = M._malloc(strings.length * 4);
  for (let i = 0; i < strings.length; i++) {
    // Each string needs its own heap allocation since stack strings
    // may be invalidated. Use a simple approach: stringToUTF8OnStack
    // inside a withStack and immediately copy the C function call.
    // Actually — for the C API, the strings are read immediately
    // during the _new() call, so stack allocation is fine as long
    // as this is called inside withStack.
    const sPtr = M.stringToUTF8OnStack(strings[i]);
    M.setValue(arr + i * 4, sPtr, 'i32');
  }
  return [arr, strings.length];
}

// ── Module initialisation ───────────────────────────────────────

/** Initialise the Wasm module and return a Sqlpipe instance. */
export async function createSqlpipe(
  wasmModuleFactory?: () => Promise<WasmModule>
): Promise<Sqlpipe> {
  let M: WasmModule;
  if (wasmModuleFactory) {
    M = await wasmModuleFactory();
  } else {
    // Default: import the Emscripten-generated JS glue.
    // The caller should provide a factory if the .js/.wasm files
    // are hosted at a custom path.
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore — Emscripten-generated JS module
    const mod = await import('../../build/wasm/sqlpipe.js');
    M = await mod.default();
  }
  return new Sqlpipe(M);
}
