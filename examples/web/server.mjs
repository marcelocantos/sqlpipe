// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0
//
// Demo server: shared pixel grid with sqlpipe replication.
// One authoritative SQLite database with a Master. Each connected
// browser is a Replica. User actions arrive as JSON over WebSocket;
// state flows back via sqlpipe changeset replication.

import { createServer } from 'http';
import { readFileSync, existsSync } from 'fs';
import { join, extname } from 'path';
import { fileURLToPath } from 'url';
import { WebSocketServer } from 'ws';
import { createSqlpipe, ReplicaState } from '../../web/dist/index.js';

const __dirname = fileURLToPath(new URL('.', import.meta.url));
const PORT = 3000;
const GRID_SIZE = 16;

// ── Initialise sqlpipe ──────────────────────────────────────────

const sp = await createSqlpipe(async () => {
  const { default: createModule } = await import('../../build/wasm/sqlpipe.js');
  return createModule();
});
console.log(`sqlpipe ${sp.version}, protocol v${sp.protocolVersion}`);

// ── Authoritative database ──────────────────────────────────────

const db = sp.openDatabase(':memory:');
db.exec(`
  CREATE TABLE pixels (
    x INTEGER NOT NULL,
    y INTEGER NOT NULL,
    color TEXT NOT NULL,
    player TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (x, y)
  );
`);

const master = sp.createMaster(db);

// ── Per-connection replica state ────────────────────────────────

const COLORS = [
  '#e74c3c', '#3498db', '#2ecc71', '#f39c12', '#9b59b6',
  '#1abc9c', '#e67e22', '#e91e63', '#00bcd4', '#8bc34a',
];
let nextColor = 0;
let nextId = 1;

class Connection {
  constructor(ws, id, color) {
    this.ws = ws;
    this.id = id;
    this.color = color;
    this.handshakeDone = false;
  }
}

const connections = new Map(); // id → Connection

// ── Handle a user action ────────────────────────────────────────

function applyAction(conn, action) {
  if (action.type !== 'paint') return;
  const { x, y } = action;
  if (x < 0 || x >= GRID_SIZE || y < 0 || y >= GRID_SIZE) return;

  // Write to the authoritative database.
  db.exec(
    `INSERT OR REPLACE INTO pixels (x, y, color, player)
     VALUES (${x}, ${y}, '${conn.color}', '${conn.id}')`
  );
}

// ── Flush master and broadcast to all replicas ──────────────────

function broadcast() {
  const msgs = master.flush();
  if (msgs.length === 0) return;

  for (const conn of connections.values()) {
    if (!conn.handshakeDone) continue;
    for (const msg of msgs) {
      if (conn.ws.readyState === 1) {
        conn.ws.send(msg);
      }
    }
  }
}

// ── Handle replica handshake messages ───────────────────────────

function handleReplicaMessage(conn, data) {
  const msg = new Uint8Array(data);
  try {
    const responses = master.handleMessage(msg);
    for (const resp of responses) {
      conn.ws.send(resp);
    }

    // After handshake completes (master sends no more responses and
    // the last message wasn't an error), mark as done.
    // A simple heuristic: if we've processed a HelloMsg and replied,
    // the handshake will progress. We mark done after a few exchanges.
    // Actually, we can detect completion by checking if the response
    // includes a DiffReadyMsg or if the changeset flow has started.
    // For simplicity, mark done after any successful handle.
    conn.handshakeDone = true;

    // After handshake, send any pending changesets.
    const pending = master.flush();
    for (const m of pending) {
      conn.ws.send(m);
    }
  } catch (e) {
    console.error(`handshake error for user ${conn.id}:`, e.message);
  }
}

// ── HTTP server (static files) ──────────────────────────────────

const MIME = {
  '.html': 'text/html',
  '.js': 'application/javascript',
  '.mjs': 'application/javascript',
  '.wasm': 'application/wasm',
  '.css': 'text/css',
};

const STATIC_ROOTS = [
  join(__dirname, 'public'),
  join(__dirname, '../../build/wasm'),
];

const httpServer = createServer((req, res) => {
  let url = req.url === '/' ? '/index.html' : req.url;

  for (const root of STATIC_ROOTS) {
    const filePath = join(root, url);
    if (existsSync(filePath)) {
      const ext = extname(filePath);
      res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
      res.end(readFileSync(filePath));
      return;
    }
  }

  res.writeHead(404);
  res.end('Not found');
});

// ── WebSocket server ────────────────────────────────────────────

const wss = new WebSocketServer({ server: httpServer });

wss.on('connection', (ws) => {
  const id = nextId++;
  const color = COLORS[nextColor++ % COLORS.length];
  const conn = new Connection(ws, id, color);
  connections.set(id, conn);
  console.log(`user ${id} connected (${color})`);

  // Send init (JSON) with user info.
  ws.send(JSON.stringify({ type: 'init', id, color, gridSize: GRID_SIZE }));

  ws.on('message', (data, isBinary) => {
    if (!isBinary) {
      // Text frame = JSON action from the user.
      try {
        const action = JSON.parse(data.toString());
        applyAction(conn, action);
        broadcast();
      } catch (e) {
        console.error(`action error for user ${id}:`, e.message);
      }
    } else {
      // Binary frame = sqlpipe replica message (handshake).
      handleReplicaMessage(conn, data);
    }
  });

  ws.on('close', () => {
    console.log(`user ${id} disconnected`);
    connections.delete(id);
  });

  ws.on('error', (e) => {
    console.error(`ws error for user ${id}:`, e.message);
  });
});

httpServer.listen(PORT, () => {
  console.log(`\nPixel Grid demo: http://localhost:${PORT}`);
  console.log(`Open in multiple browser tabs to play!\n`);
});
