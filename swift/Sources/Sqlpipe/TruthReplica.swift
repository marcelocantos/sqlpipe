// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

import Foundation
import CSqlpipe

/// Truth-side sqlpipe **Replica** with optimistic prediction for low-latency
/// paint over server-owned tables (see sqlpipe-agents-guide § Optimistic prediction).
///
/// Transport is caller's responsibility (message-in / message-out).
public final class TruthReplica: @unchecked Sendable {
    private var db: OpaquePointer?
    private var replica: OpaquePointer?

    /// Open a truth database as a Replica.
    /// - Parameters:
    ///   - dbPath: File path or ":memory:".
    ///   - queueWhilePredicting: Hold inbound truth during a gesture (freehand).
    public init(dbPath: String, queueWhilePredicting: Bool = true) throws {
        let rc = sqlite3_open_v2(
            dbPath,
            &db,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOMUTEX,
            nil
        )
        guard rc == SQLITE_OK, let db else {
            let msg = db.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown"
            sqlite3_close(db)
            self.db = nil
            throw SqlpipeError.openFailed(msg)
        }
        sqlite3_exec(db, "PRAGMA journal_mode=WAL", nil, nil, nil)

        var cfg = sqlpipe_replica_config()
        cfg.queue_while_predicting = queueWhilePredicting ? 1 : 0
        var rep: OpaquePointer?
        let err = sqlpipe_replica_new(db, cfg, &rep)
        if err.code != 0 {
            let msg = err.msg.flatMap { String(cString: $0) } ?? "unknown"
            sqlpipe_free_error(err)
            throw SqlpipeError.peerCreateFailed(msg)
        }
        self.replica = rep
    }

    deinit {
        if let replica { sqlpipe_replica_free(replica) }
        if let db { sqlite3_close(db) }
    }

    /// Raw sqlite3* for advanced use (schema migrate, etc.).
    public var sqliteHandle: OpaquePointer? { db }

    public func beginPrediction() throws {
        guard let replica else { throw SqlpipeError.closed }
        let err = sqlpipe_replica_begin_prediction(replica)
        if err.code != 0 {
            let msg = err.msg.flatMap { String(cString: $0) } ?? "unknown"
            sqlpipe_free_error(err)
            throw SqlpipeError.execFailed(msg)
        }
    }

    public func commitPrediction() throws {
        guard let replica else { throw SqlpipeError.closed }
        let err = sqlpipe_replica_commit_prediction(replica)
        if err.code != 0 {
            let msg = err.msg.flatMap { String(cString: $0) } ?? "unknown"
            sqlpipe_free_error(err)
            throw SqlpipeError.execFailed(msg)
        }
    }

    /// Ends prediction: rolls back savepoint and applies queued inbound.
    /// Returns opaque response bytes to forward to the master (acks).
    @discardableResult
    public func endPrediction() throws -> Data? {
        guard let replica else { throw SqlpipeError.closed }
        var buf = sqlpipe_buf()
        let err = sqlpipe_replica_end_prediction(replica, &buf)
        defer { sqlpipe_free_buf(buf) }
        if err.code != 0 {
            let msg = err.msg.flatMap { String(cString: $0) } ?? "unknown"
            sqlpipe_free_error(err)
            throw SqlpipeError.execFailed(msg)
        }
        guard buf.data != nil, buf.len > 0 else { return nil }
        return Data(bytes: buf.data, count: Int(buf.len))
    }

    public func rollbackPrediction() throws {
        guard let replica else { throw SqlpipeError.closed }
        let err = sqlpipe_replica_rollback_prediction(replica)
        if err.code != 0 {
            let msg = err.msg.flatMap { String(cString: $0) } ?? "unknown"
            sqlpipe_free_error(err)
            throw SqlpipeError.execFailed(msg)
        }
    }

    public func execute(_ sql: String) throws {
        guard let db else { throw SqlpipeError.closed }
        var errMsg: UnsafeMutablePointer<CChar>?
        let rc = sqlite3_exec(db, sql, nil, nil, &errMsg)
        if rc != SQLITE_OK {
            let msg = errMsg.flatMap { String(cString: $0) } ?? "unknown"
            sqlite3_free(errMsg)
            throw SqlpipeError.execFailed(msg)
        }
    }

    public func query(_ sql: String) -> [[String: Any]]? {
        guard let db else { return nil }
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return nil }
        defer { sqlite3_finalize(stmt) }
        var results: [[String: Any]] = []
        let colCount = sqlite3_column_count(stmt)
        while sqlite3_step(stmt) == SQLITE_ROW {
            var row: [String: Any] = [:]
            for i in 0..<colCount {
                let name = String(cString: sqlite3_column_name(stmt, i))
                switch sqlite3_column_type(stmt, i) {
                case SQLITE_INTEGER: row[name] = sqlite3_column_int64(stmt, i)
                case SQLITE_FLOAT: row[name] = sqlite3_column_double(stmt, i)
                case SQLITE_TEXT: row[name] = String(cString: sqlite3_column_text(stmt, i))
                case SQLITE_BLOB:
                    let len = sqlite3_column_bytes(stmt, i)
                    if let ptr = sqlite3_column_blob(stmt, i) {
                        row[name] = Data(bytes: ptr, count: Int(len))
                    }
                default: row[name] = NSNull()
                }
            }
            results.append(row)
        }
        return results
    }

    /// Hello wire bytes to send to the master (single message).
    public func hello() -> Data? {
        guard let replica else { return nil }
        var buf = sqlpipe_buf()
        let err = sqlpipe_replica_hello(replica, &buf)
        defer { sqlpipe_free_buf(buf) }
        if err.code != 0 { return nil }
        return Data(bytes: buf.data, count: Int(buf.len))
    }

    public func converge() -> Data? {
        guard let replica else { return nil }
        var buf = sqlpipe_buf()
        let err = sqlpipe_replica_converge(replica, &buf)
        defer { sqlpipe_free_buf(buf) }
        if err.code != 0 { return nil }
        return Data(bytes: buf.data, count: Int(buf.len))
    }

    /// Handle master wire message. Returns response bytes (acks) to send back.
    @discardableResult
    public func handleMessage(_ data: Data) -> Data? {
        guard let replica, !data.isEmpty else { return nil }
        return data.withUnsafeBytes { raw -> Data? in
            let bytes = raw.bindMemory(to: UInt8.self)
            var outBuf = sqlpipe_buf()
            let err = sqlpipe_replica_handle_message(
                replica, bytes.baseAddress, data.count, &outBuf
            )
            defer { sqlpipe_free_buf(outBuf) }
            if err.code != 0 { return nil }
            guard outBuf.data != nil, outBuf.len > 0 else { return nil }
            return Data(bytes: outBuf.data, count: Int(outBuf.len))
        }
    }

    public func subscribe(_ sql: String) throws -> UInt64 {
        guard let replica else { throw SqlpipeError.closed }
        var id: UInt64 = 0
        let err = sqlpipe_replica_subscribe(replica, sql, &id)
        if err.code != 0 {
            let msg = err.msg.flatMap { String(cString: $0) } ?? "unknown"
            sqlpipe_free_error(err)
            throw SqlpipeError.subscribeFailed(msg)
        }
        return id
    }
}
