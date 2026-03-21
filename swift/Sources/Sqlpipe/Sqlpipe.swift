// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

import Foundation
import CSqlpipe

// MARK: - Value types

/// A SQLite value decoded from sqlpipe's wire format.
public enum SQLValue: Sendable, Equatable {
    case null
    case integer(Int64)
    case real(Double)
    case text(String)
    case blob(Data)
}

/// A subscription query result decoded from sqlpipe's binary format.
public struct QueryResult: Sendable {
    public let id: UInt64
    public let columns: [String]
    public let rows: [[SQLValue]]
}

/// Result of handling an incoming message.
public struct HandleResult: Sendable {
    /// Response data to send back (serialized PeerMessages, no count prefix).
    public let response: Data?
    /// Whether any data changes were applied to the local replica.
    public let hasChanges: Bool
    /// Updated subscription query results.
    public let subscriptions: [QueryResult]
}

/// Peer connection state.
public enum PeerState: UInt8, Sendable {
    case `init` = 0
    case negotiating = 1
    case diffing = 2
    case live = 3
    case error = 4
}

// MARK: - Errors

public enum SqlpipeError: LocalizedError, Sendable {
    case openFailed(String)
    case peerCreateFailed(String)
    case execFailed(String)
    case subscribeFailed(String)
    case closed

    public var errorDescription: String? {
        switch self {
        case .openFailed(let msg): return "Failed to open database: \(msg)"
        case .peerCreateFailed(let msg): return "Failed to create peer: \(msg)"
        case .execFailed(let msg): return "SQL exec failed: \(msg)"
        case .subscribeFailed(let msg): return "Subscribe failed: \(msg)"
        case .closed: return "SyncPeer is closed"
        }
    }
}

// MARK: - Log callback

/// Log level matching sqlpipe::LogLevel.
public enum LogLevel: UInt8, Sendable {
    case debug = 0, info, warn, error
}

/// Callback for sqlpipe log output.
public typealias LogHandler = @Sendable (LogLevel, String) -> Void

// MARK: - SyncPeer

/// Swift wrapper around sqlpipe's Peer C API for bidirectional SQLite sync.
///
/// Owns a local SQLite database and synchronises it with a remote peer
/// using sqlpipe's changeset protocol. Transport is the caller's
/// responsibility — SyncPeer is message-in / message-out.
public final class SyncPeer: @unchecked Sendable {
    private var db: OpaquePointer?
    private var peer: OpaquePointer?

    /// Open a local SQLite database and create a sqlpipe Peer.
    ///
    /// - Parameters:
    ///   - dbPath: Path to the SQLite database file (or ":memory:").
    ///   - ownedTables: Tables owned by this (client) peer.
    ///   - logHandler: Optional log callback.
    public init(
        dbPath: String,
        ownedTables: [String],
        logHandler: LogHandler? = nil
    ) throws {
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

        var cfg = sqlpipe_peer_config()

        let cStrings = ownedTables.map { strdup($0) }
        defer { cStrings.forEach { free($0) } }

        var cStringPtrs = cStrings.map { UnsafePointer($0) }
        try cStringPtrs.withUnsafeMutableBufferPointer { buf in
            cfg.owned_tables = buf.baseAddress
            cfg.owned_table_count = ownedTables.count

            if logHandler != nil {
                cfg.on_log = { _, level, message in
                    guard let message else { return }
                    // Note: logHandler is captured via the cfg context, but
                    // sqlpipe's C API uses a void* context which we don't use
                    // here. For simplicity, the log handler is a file-level
                    // variable set before peer creation.
                    let msg = String(cString: message)
                    _currentLogHandler?(LogLevel(rawValue: level) ?? .info, msg)
                }
            }

            _currentLogHandler = logHandler

            var peerPtr: OpaquePointer?
            let err = sqlpipe_peer_new(db, cfg, &peerPtr)
            if err.code != 0 {
                let msg = err.msg.flatMap { String(cString: $0) } ?? "unknown"
                sqlpipe_free_error(err)
                throw SqlpipeError.peerCreateFailed(msg)
            }
            self.peer = peerPtr
        }
    }

    deinit {
        if let peer { sqlpipe_peer_free(peer) }
        if let db { sqlite3_close(db) }
    }

    // MARK: - Peer operations

    /// Start the peer handshake. Returns serialized messages to send.
    public func start() -> Data? {
        guard let peer else { return nil }
        var buf = sqlpipe_buf()
        let err = sqlpipe_peer_start(peer, &buf)
        defer { sqlpipe_free_buf(buf) }
        if err.code != 0 { logError(err, "start"); return nil }
        return stripCountPrefix(buf)
    }

    /// Handle an incoming binary message. Returns response + changes + subscriptions.
    public func handleMessage(_ data: Data) -> HandleResult {
        guard let peer else {
            return HandleResult(response: nil, hasChanges: false, subscriptions: [])
        }

        var allResponse = Data()
        var anyChanges = false
        var allSubscriptions: [QueryResult] = []

        data.withUnsafeBytes { rawBuf in
            let bytes = rawBuf.bindMemory(to: UInt8.self)
            var offset = 0

            while offset + 4 <= bytes.count {
                let msgLen = Int(bytes[offset])
                    | (Int(bytes[offset+1]) << 8)
                    | (Int(bytes[offset+2]) << 16)
                    | (Int(bytes[offset+3]) << 24)
                let total = 4 + msgLen
                guard offset + total <= bytes.count else { break }

                var outBuf = sqlpipe_buf()
                let ptr = bytes.baseAddress!.advanced(by: offset)
                let err = sqlpipe_peer_handle_message(peer, ptr, total, &outBuf)

                if err.code != 0 {
                    logError(err, "handleMessage")
                } else {
                    let decoded = decodePeerHandleResult(outBuf)
                    if let resp = decoded.messages { allResponse.append(resp) }
                    if decoded.changeCount > 0 { anyChanges = true }
                    allSubscriptions.append(contentsOf: decoded.subscriptions)
                }
                sqlpipe_free_buf(outBuf)
                offset += total
            }
        }

        return HandleResult(
            response: allResponse.isEmpty ? nil : allResponse,
            hasChanges: anyChanges,
            subscriptions: allSubscriptions
        )
    }

    /// Flush local changes. Returns serialized messages to send.
    public func flush() -> Data? {
        guard let peer else { return nil }
        var buf = sqlpipe_buf()
        let err = sqlpipe_peer_flush(peer, &buf)
        defer { sqlpipe_free_buf(buf) }
        if err.code != 0 { logError(err, "flush"); return nil }
        return stripCountPrefix(buf)
    }

    /// Subscribe to a SQL query. Returns the subscription ID.
    /// Results arrive via HandleResult.subscriptions.
    public func subscribe(_ sql: String) throws -> UInt64 {
        guard let peer else { throw SqlpipeError.closed }
        var subID: UInt64 = 0
        let err = sqlpipe_peer_subscribe(peer, sql, &subID)
        if err.code != 0 {
            let msg = err.msg.flatMap { String(cString: $0) } ?? "unknown"
            sqlpipe_free_error(err)
            throw SqlpipeError.subscribeFailed(msg)
        }
        return subID
    }

    /// Unsubscribe from a subscription.
    public func unsubscribe(_ id: UInt64) {
        guard let peer else { return }
        let err = sqlpipe_peer_unsubscribe(peer, id)
        if err.code != 0 { logError(err, "unsubscribe") }
    }

    /// Execute SQL on the local database (for client-owned tables).
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

    /// One-shot query. Accepts sqldeep syntax.
    public func query(_ sql: String) -> [[String: Any]]? {
        guard let db else { return nil }
        let transpiled = transpile(sql)
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, transpiled, -1, &stmt, nil) == SQLITE_OK else {
            return nil
        }
        defer { sqlite3_finalize(stmt) }

        var results: [[String: Any]] = []
        let colCount = sqlite3_column_count(stmt)

        while sqlite3_step(stmt) == SQLITE_ROW {
            var row: [String: Any] = [:]
            for i in 0..<colCount {
                let name = String(cString: sqlite3_column_name(stmt, i))
                switch sqlite3_column_type(stmt, i) {
                case SQLITE_INTEGER: row[name] = sqlite3_column_int64(stmt, i)
                case SQLITE_FLOAT:   row[name] = sqlite3_column_double(stmt, i)
                case SQLITE_TEXT:    row[name] = String(cString: sqlite3_column_text(stmt, i))
                case SQLITE_BLOB:
                    let len = sqlite3_column_bytes(stmt, i)
                    if let ptr = sqlite3_column_blob(stmt, i) {
                        row[name] = Data(bytes: ptr, count: Int(len))
                    } else {
                        row[name] = NSNull()
                    }
                default: row[name] = NSNull()
                }
            }
            results.append(row)
        }
        return results
    }

    /// Current peer state.
    public var state: PeerState {
        guard let peer else { return .`init` }
        return PeerState(rawValue: sqlpipe_peer_state(peer)) ?? .`init`
    }

    /// Whether the peer is in Live state.
    public var isLive: Bool { state == .live }

    /// Reset the peer for reconnection.
    public func reset() {
        guard let peer else { return }
        sqlpipe_peer_reset(peer)
    }

    /// Close the peer and database.
    public func close() {
        if let peer { sqlpipe_peer_free(peer); self.peer = nil }
        if let db { sqlite3_close(db); self.db = nil }
    }

    // MARK: - Binary decoding

    private struct DecodedPeerHandleResult {
        let messages: Data?
        let changeCount: Int
        let subscriptions: [QueryResult]
    }

    private func decodePeerHandleResult(_ buf: sqlpipe_buf) -> DecodedPeerHandleResult {
        guard let data = buf.data, buf.len > 0 else {
            return DecodedPeerHandleResult(messages: nil, changeCount: 0, subscriptions: [])
        }
        let bytes = UnsafeBufferPointer(start: data, count: buf.len)
        var offset = 0

        let msgCount = readU32(bytes, offset: &offset)
        let msgStart = offset
        for _ in 0..<msgCount {
            guard offset + 4 <= bytes.count else { break }
            let msgLen = readU32(bytes, offset: &offset)
            offset += Int(msgLen)
        }
        let msgEnd = offset

        var responseData: Data?
        if msgCount > 0 {
            responseData = Data(bytes: bytes.baseAddress!.advanced(by: msgStart),
                                count: msgEnd - msgStart)
        }

        let changeCount = readU32(bytes, offset: &offset)
        for _ in 0..<changeCount { skipChangeEvent(bytes, offset: &offset) }

        let subCount = readU32(bytes, offset: &offset)
        var subs: [QueryResult] = []
        for _ in 0..<subCount {
            if let qr = decodeQueryResult(bytes, offset: &offset) {
                subs.append(qr)
            }
        }

        return DecodedPeerHandleResult(
            messages: responseData, changeCount: Int(changeCount), subscriptions: subs)
    }

    private func decodeQueryResult(
        _ bytes: UnsafeBufferPointer<UInt8>, offset: inout Int
    ) -> QueryResult? {
        guard offset + 12 <= bytes.count else { return nil }
        let id = readU64(bytes, offset: &offset)
        let colCount = readU32(bytes, offset: &offset)
        var columns: [String] = []
        for _ in 0..<colCount { columns.append(readString(bytes, offset: &offset)) }
        let rowCount = readU32(bytes, offset: &offset)
        var rows: [[SQLValue]] = []
        for _ in 0..<rowCount {
            var row: [SQLValue] = []
            for _ in 0..<colCount { row.append(readValue(bytes, offset: &offset)) }
            rows.append(row)
        }
        return QueryResult(id: id, columns: columns, rows: rows)
    }

    private func readValue(
        _ bytes: UnsafeBufferPointer<UInt8>, offset: inout Int
    ) -> SQLValue {
        guard offset < bytes.count else { return .null }
        let tag = bytes[offset]; offset += 1
        switch tag {
        case 0x01: return .integer(readI64(bytes, offset: &offset))
        case 0x02: return .real(Double(bitPattern: readU64(bytes, offset: &offset)))
        case 0x03: return .text(readString(bytes, offset: &offset))
        case 0x04:
            let len = readU32(bytes, offset: &offset)
            guard offset + Int(len) <= bytes.count else { return .null }
            let data = Data(bytes: bytes.baseAddress!.advanced(by: offset), count: Int(len))
            offset += Int(len)
            return .blob(data)
        default: return .null
        }
    }

    private func skipChangeEvent(
        _ bytes: UnsafeBufferPointer<UInt8>, offset: inout Int
    ) {
        _ = readString(bytes, offset: &offset)
        offset += 1
        let pkCount = readU32(bytes, offset: &offset)
        offset += Int(pkCount)
        let oldCount = readU32(bytes, offset: &offset)
        for _ in 0..<oldCount { _ = readValue(bytes, offset: &offset) }
        let newCount = readU32(bytes, offset: &offset)
        for _ in 0..<newCount { _ = readValue(bytes, offset: &offset) }
    }

    // MARK: - Primitive readers (little-endian)

    private func readU32(_ b: UnsafeBufferPointer<UInt8>, offset: inout Int) -> UInt32 {
        guard offset + 4 <= b.count else { return 0 }
        let v = UInt32(b[offset]) | (UInt32(b[offset+1]) << 8)
            | (UInt32(b[offset+2]) << 16) | (UInt32(b[offset+3]) << 24)
        offset += 4; return v
    }

    private func readU64(_ b: UnsafeBufferPointer<UInt8>, offset: inout Int) -> UInt64 {
        guard offset + 8 <= b.count else { return 0 }
        var v: UInt64 = 0
        for i in 0..<8 { v |= UInt64(b[offset + i]) << (i * 8) }
        offset += 8; return v
    }

    private func readI64(_ b: UnsafeBufferPointer<UInt8>, offset: inout Int) -> Int64 {
        Int64(bitPattern: readU64(b, offset: &offset))
    }

    private func readString(_ b: UnsafeBufferPointer<UInt8>, offset: inout Int) -> String {
        let len = readU32(b, offset: &offset)
        guard offset + Int(len) <= b.count else { return "" }
        let str = String(bytes: UnsafeBufferPointer(
            start: b.baseAddress!.advanced(by: offset), count: Int(len)),
            encoding: .utf8) ?? ""
        offset += Int(len); return str
    }

    // MARK: - Helpers

    private func stripCountPrefix(_ buf: sqlpipe_buf) -> Data? {
        guard let data = buf.data, buf.len > 4 else { return nil }
        return Data(bytes: data.advanced(by: 4), count: buf.len - 4)
    }

    private func logError(_ err: sqlpipe_error, _ ctx: String) {
        let msg = err.msg.flatMap { String(cString: $0) } ?? "code \(err.code)"
        _currentLogHandler?(.error, "SyncPeer.\(ctx) failed: \(msg)")
        sqlpipe_free_error(err)
    }

    private func transpile(_ input: String) -> String {
        var error: UnsafeMutablePointer<CChar>?
        var errLine: Int32 = 0
        var errCol: Int32 = 0
        guard let result = sqldeep_transpile(input, &error, &errLine, &errCol) else {
            if let error { sqldeep_free(error) }
            return input
        }
        defer { sqldeep_free(result) }
        return String(cString: result)
    }
}

// File-level log handler (workaround for C callback context limitations).
private nonisolated(unsafe) var _currentLogHandler: LogHandler?
