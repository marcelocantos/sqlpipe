// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

import type { ChangeEvent, HandleResult, PeerHandleResult, QueryResult, Value } from './types.js';
import { OpType } from './types.js';

/** Little-endian binary reader over a Uint8Array. */
export class Reader {
  private view: DataView;
  pos: number;

  constructor(buf: Uint8Array, offset = 0) {
    this.view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    this.pos = offset;
  }

  u8(): number {
    return this.view.getUint8(this.pos++);
  }

  u32(): number {
    const v = this.view.getUint32(this.pos, true);
    this.pos += 4;
    return v;
  }

  i64(): bigint {
    const v = this.view.getBigInt64(this.pos, true);
    this.pos += 8;
    return v;
  }

  u64(): bigint {
    const v = this.view.getBigUint64(this.pos, true);
    this.pos += 8;
    return v;
  }

  f64(): number {
    const v = this.view.getFloat64(this.pos, true);
    this.pos += 8;
    return v;
  }

  bytes(n: number): Uint8Array {
    const b = new Uint8Array(this.view.buffer, this.view.byteOffset + this.pos, n);
    this.pos += n;
    return b.slice(); // return a copy
  }

  string(): string {
    const len = this.u32();
    const bytes = this.bytes(len);
    return new TextDecoder().decode(bytes);
  }

  value(): Value {
    const tag = this.u8();
    switch (tag) {
      case 0x00: return null;
      case 0x01: return this.i64();
      case 0x02: return this.f64();
      case 0x03: return this.string();
      case 0x04: { const len = this.u32(); return this.bytes(len); }
      default: throw new Error(`unknown value type: ${tag}`);
    }
  }
}

/** Decode a ChangeEvent from a Reader. */
export function decodeChangeEvent(r: Reader): ChangeEvent {
  const table = r.string();
  const op = r.u8() as OpType;
  const pkCount = r.u32();
  const pkFlags: boolean[] = [];
  for (let i = 0; i < pkCount; i++) pkFlags.push(r.u8() !== 0);
  const oldCount = r.u32();
  const oldValues: Value[] = [];
  for (let i = 0; i < oldCount; i++) oldValues.push(r.value());
  const newCount = r.u32();
  const newValues: Value[] = [];
  for (let i = 0; i < newCount; i++) newValues.push(r.value());
  return { table, op, pkFlags, oldValues, newValues };
}

/** Decode a QueryResult from a Reader. */
export function decodeQueryResult(r: Reader): QueryResult {
  const id = r.u64();
  const colCount = r.u32();
  const columns: string[] = [];
  for (let i = 0; i < colCount; i++) columns.push(r.string());
  const rowCount = r.u32();
  const rows: Value[][] = [];
  for (let i = 0; i < rowCount; i++) {
    const row: Value[] = [];
    for (let j = 0; j < colCount; j++) row.push(r.value());
    rows.push(row);
  }
  return { id, columns, rows };
}

/** Extract wire messages from an encoded messages buffer. */
export function decodeMessages(buf: Uint8Array): Uint8Array[] {
  const r = new Reader(buf);
  const count = r.u32();
  const msgs: Uint8Array[] = [];
  for (let i = 0; i < count; i++) {
    const len = r.u32();
    // Include the 4-byte length prefix in the message.
    const start = r.pos - 4;
    r.pos += len;
    msgs.push(buf.slice(start, r.pos));
  }
  return msgs;
}

/** Decode a HandleResult buffer. */
export function decodeHandleResult(buf: Uint8Array): HandleResult {
  const r = new Reader(buf);

  // Response messages.
  const msgCount = r.u32();
  const messages: Uint8Array[] = [];
  for (let i = 0; i < msgCount; i++) {
    const len = r.u32();
    const start = r.pos - 4;
    r.pos += len;
    messages.push(buf.slice(start, r.pos));
  }

  // Changes.
  const changeCount = r.u32();
  const changes: ChangeEvent[] = [];
  for (let i = 0; i < changeCount; i++) changes.push(decodeChangeEvent(r));

  // Subscriptions.
  const subCount = r.u32();
  const subscriptions: QueryResult[] = [];
  for (let i = 0; i < subCount; i++) subscriptions.push(decodeQueryResult(r));

  return { messages, changes, subscriptions };
}

/** Decode a PeerHandleResult buffer. */
export function decodePeerHandleResult(buf: Uint8Array): PeerHandleResult {
  const r = new Reader(buf);

  const msgCount = r.u32();
  const messages: Uint8Array[] = [];
  for (let i = 0; i < msgCount; i++) {
    const len = r.u32();
    const start = r.pos - 4;
    r.pos += len;
    messages.push(buf.slice(start, r.pos));
  }

  const changeCount = r.u32();
  const changes: ChangeEvent[] = [];
  for (let i = 0; i < changeCount; i++) changes.push(decodeChangeEvent(r));

  const subCount = r.u32();
  const subscriptions: QueryResult[] = [];
  for (let i = 0; i < subCount; i++) subscriptions.push(decodeQueryResult(r));

  return { messages, changes, subscriptions };
}
