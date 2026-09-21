import assert from "node:assert/strict";
import test from "node:test";
import { ConversationTreeSnapshotReceiver } from "../src/snapshot-stream.js";

function packet(revision, index, count, payload) {
  return new TextEncoder().encode(JSON.stringify({ version: 1, revision, index, count, payload })).buffer;
}

test("reassembles a chunked Host snapshot in order", () => {
  const snapshot = { version: 1, session: { session_id: "session-1", messages: [] } };
  const source = JSON.stringify(snapshot);
  const receiver = new ConversationTreeSnapshotReceiver();
  assert.equal(receiver.accept(packet(3, 1, 2, source.slice(24))), undefined);
  assert.deepEqual(receiver.accept(packet(3, 0, 2, source.slice(0, 24))), snapshot);
});

test("drops stale snapshots after a newer revision completes", () => {
  const receiver = new ConversationTreeSnapshotReceiver();
  const current = JSON.stringify({ version: 1, session: null });
  assert.deepEqual(receiver.accept(packet(2, 0, 1, current)), { version: 1, session: null });
  assert.equal(receiver.accept(packet(1, 0, 1, current)), undefined);
});

test("rejects malformed snapshot packets", () => {
  const receiver = new ConversationTreeSnapshotReceiver();
  assert.throws(() => receiver.accept(new TextEncoder().encode("not json").buffer), /invalid_snapshot_packet/);
  assert.throws(() => receiver.accept(packet(1, 0, 1, "{}")), /invalid_snapshot/);
});
