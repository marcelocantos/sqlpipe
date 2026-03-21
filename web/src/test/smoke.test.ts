// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

import { createSqlpipe, ReplicaState, LogLevel } from '../index.js';

function assert(cond: boolean, msg: string): asserts cond {
  if (!cond) throw new Error(`assertion failed: ${msg}`);
}

const sp = await createSqlpipe();
console.log(`sqlpipe ${sp.version}, protocol v${sp.protocolVersion}`);
console.log(`sqldeep ${sp.sqldeepVersion}`);

// ── Database + schema ───────────────────────────────────────────

const masterDb = sp.openDatabase(':memory:');
const replicaDb = sp.openDatabase(':memory:');

const schema = 'CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT, value REAL)';
masterDb.exec(schema);
replicaDb.exec(schema);
console.log('databases created');

// ── Master + Replica ────────────────────────────────────────────

const logs: string[] = [];
const master = sp.createMaster(masterDb, {
  onLog: (level, msg) => logs.push(`[master ${LogLevel[level]}] ${msg}`),
});
const replica = sp.createReplica(replicaDb, {
  onLog: (level, msg) => logs.push(`[replica ${LogLevel[level]}] ${msg}`),
});

// ── Handshake ───────────────────────────────────────────────────

sp.syncHandshake(master, replica);
assert(replica.state === ReplicaState.Live, `expected Live, got ${ReplicaState[replica.state]}`);
console.log('handshake complete — replica is Live');

// ── Insert + replicate ──────────────────────────────────────────

masterDb.exec("INSERT INTO items VALUES (1, 'hello', 3.14)");
masterDb.exec("INSERT INTO items VALUES (2, 'world', 2.72)");

const msgs = master.flush();
assert(msgs.length === 1, `expected 1 flush message, got ${msgs.length}`);

const result = replica.handleMessage(msgs[0]);
assert(result.changes.length === 2, `expected 2 changes, got ${result.changes.length}`);
assert(result.messages.length === 1, `expected 1 ack, got ${result.messages.length}`);
console.log(`replicated ${result.changes.length} changes`);

// ── Seq check ───────────────────────────────────────────────────

assert(master.currentSeq === 1n, `master seq ${master.currentSeq}`);
assert(replica.currentSeq === 1n, `replica seq ${replica.currentSeq}`);
console.log(`seq: master=${master.currentSeq}, replica=${replica.currentSeq}`);

// ── QueryWatch ──────────────────────────────────────────────────

const watch = sp.createQueryWatch(replicaDb);
const subId1 = watch.subscribe('SELECT count(*) as cnt FROM items');
const subId2 = watch.subscribe('SELECT id, name, value FROM items ORDER BY id');
assert(typeof subId1 === 'bigint', `expected bigint, got ${typeof subId1}`);
assert(typeof subId2 === 'bigint', `expected bigint, got ${typeof subId2}`);

// First notify delivers initial results for both subscriptions.
const initial = watch.notify(['items']);
assert(initial.length === 2, `expected 2 initial results, got ${initial.length}`);
const countResult = initial.find(r => r.id === subId1);
assert(countResult !== undefined, 'count subscription not found in initial results');
assert(countResult.rows[0][0] === 2n, `expected count=2, got ${countResult.rows[0][0]}`);
console.log(`QueryWatch: count=${countResult!.rows[0][0]}`);

// Insert another row on master and replicate.
masterDb.exec("INSERT INTO items VALUES (3, 'sqlpipe', 1.0)");
const msgs2 = master.flush();
const result2 = replica.handleMessage(msgs2[0]);
assert(result2.changes.length === 1, `expected 1 change`);

// Notify the watch — both subscriptions should fire (data changed).
const changed = watch.notify(['items']);
assert(changed.length === 2, `expected 2 changed subscriptions, got ${changed.length}`);
console.log('QueryWatch notified after replication');

watch.unsubscribe(subId1);
watch.unsubscribe(subId2);
assert(watch.empty, 'watch should be empty after unsubscribe');

// ── Serialize / Deserialize ──────────────────────────────────────

// Serialize the replica database, open a new one, deserialize into it,
// and verify the data survived the round-trip.
const snapshot = replicaDb.serialize();
assert(snapshot.length > 0, 'serialize produced empty buffer');
console.log(`serialized replica: ${snapshot.length} bytes`);

const restoredDb = sp.openDatabase(':memory:');
restoredDb.deserialize(snapshot);

// Verify data via QueryWatch on the restored database.
const rWatch = sp.createQueryWatch(restoredDb);
const rSubId = rWatch.subscribe('SELECT count(*) FROM items');
// notify to get the initial result
const rInitial = rWatch.notify(['items']);
assert(rInitial.length === 1, `expected 1 result, got ${rInitial.length}`);
assert(rInitial[0].rows[0][0] === 3n, `expected 3 rows after restore, got ${rInitial[0].rows[0][0]}`);
rWatch.unsubscribe(rSubId);
rWatch.close();
restoredDb.close();
console.log('serialize/deserialize round-trip OK');

// ── sqldeep ─────────────────────────────────────────────────────

const transpiled = sp.transpile('SELECT {name, value} FROM items');
assert(
  transpiled.includes('json_object'),
  `expected json_object in output, got: ${transpiled}`
);
console.log(`sqldeep: "${transpiled}"`);

// ── Cleanup ─────────────────────────────────────────────────────

watch.close();
master.close();
replica.close();
masterDb.close();
replicaDb.close();

if (logs.length > 0) {
  console.log(`\nLog output (${logs.length} entries):`);
  for (const l of logs.slice(0, 5)) console.log(`  ${l}`);
  if (logs.length > 5) console.log(`  ... and ${logs.length - 5} more`);
}

console.log('\n✓ All TypeScript smoke tests passed');
