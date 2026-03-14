// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

/** Column value — mirrors SQLite types. */
export type Value = null | bigint | number | string | Uint8Array;

/** Row operation type. */
export enum OpType {
  Insert = 1,
  Update = 2,
  Delete = 3,
}

/** A row-level change extracted from a changeset. */
export interface ChangeEvent {
  table: string;
  op: OpType;
  pkFlags: boolean[];
  oldValues: Value[];
  newValues: Value[];
}

/** Result set of a subscribed query. */
export interface QueryResult {
  id: bigint;
  columns: string[];
  rows: Value[][];
}

/** Conflict resolution action. */
export enum ConflictAction {
  Omit = 0,
  Replace = 1,
  Abort = 2,
}

/** Conflict type during changeset application. */
export enum ConflictType {
  Data = 0,
  NotFound = 1,
  Conflict = 2,
  Constraint = 3,
  ForeignKey = 4,
}

/** Diff sync progress phase. */
export enum DiffPhase {
  ComputingBuckets = 0,
  ComparingBuckets = 1,
  ComputingRowHashes = 2,
  BuildingPatchset = 3,
  ApplyingPatchset = 4,
}

/** Log severity level. */
export enum LogLevel {
  Debug = 0,
  Info = 1,
  Warn = 2,
  Error = 3,
}

/** Replica connection state. */
export enum ReplicaState {
  Init = 0,
  Handshake = 1,
  DiffBuckets = 2,
  DiffRows = 3,
  Live = 4,
  Error = 5,
}

/** Peer connection state. */
export enum PeerState {
  Init = 0,
  Negotiating = 1,
  Diffing = 2,
  Live = 3,
  Error = 4,
}

/** sqldeep target backend. */
export enum SqldeepBackend {
  SQLite = 0,
  Postgres = 1,
}

/** Progress callback. */
export type ProgressCallback = (
  phase: DiffPhase, table: string, done: number, total: number
) => void;

/** Log callback. */
export type LogCallback = (level: LogLevel, message: string) => void;

/** Schema mismatch callback. Return true to retry after ALTER. */
export type SchemaMismatchCallback = (
  remoteSchemaVersion: number, localSchemaVersion: number,
  remoteSchemaSQL: string
) => boolean;

/** Conflict callback. Return the desired action. */
export type ConflictCallback = (
  type: ConflictType, event: ChangeEvent
) => ConflictAction;

/** Approve ownership callback (peer server side). Return true to approve. */
export type ApproveOwnershipCallback = (tables: string[]) => boolean;

/** Master configuration. */
export interface MasterConfig {
  tableFilter?: string[];
  seqKey?: string;
  bucketSize?: number;
  onProgress?: ProgressCallback;
  onSchemaMismatch?: SchemaMismatchCallback;
  onLog?: LogCallback;
}

/** Replica configuration. */
export interface ReplicaConfig {
  onConflict?: ConflictCallback;
  tableFilter?: string[];
  seqKey?: string;
  bucketSize?: number;
  onProgress?: ProgressCallback;
  onSchemaMismatch?: SchemaMismatchCallback;
  onLog?: LogCallback;
}

/** Peer configuration. */
export interface PeerConfig {
  ownedTables: string[];
  tableFilter?: string[];
  approveOwnership?: ApproveOwnershipCallback;
  onConflict?: ConflictCallback;
  onProgress?: ProgressCallback;
  onSchemaMismatch?: SchemaMismatchCallback;
  onLog?: LogCallback;
}

/** Result from Replica.handleMessage(). */
export interface HandleResult {
  messages: Uint8Array[];
  changes: ChangeEvent[];
  subscriptions: QueryResult[];
}

/** Result from Peer.handleMessage(). */
export interface PeerHandleResult {
  messages: Uint8Array[];
  changes: ChangeEvent[];
  subscriptions: QueryResult[];
}
