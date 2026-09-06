import assert from "node:assert/strict";
import { test } from "node:test";
import { TrafficPayloadCollector } from "../src/api/traffic-payload";

function packet(value: Record<string, unknown>): ArrayBuffer {
  const bytes = new TextEncoder().encode(JSON.stringify(value));
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

test("traffic payload stream reassembles a matching flow and ignores another flow", () => {
  const collector = new TrafficPayloadCollector("flow-1");
  assert.equal(collector.accept(packet({ version: 1, revision: 1, index: 0, count: 1, flowId: "flow-2", payload: "{}" })), undefined);
  const serialized = JSON.stringify({ payload: { response: { body: "large" } } });
  const split = Math.floor(serialized.length / 2);
  assert.equal(collector.accept(packet({ version: 1, revision: 1, index: 0, count: 2, flowId: "flow-1", payload: serialized.slice(0, split) })), undefined);
  assert.deepEqual(collector.accept(packet({ version: 1, revision: 1, index: 1, count: 2, flowId: "flow-1", payload: serialized.slice(split) })), { payload: { response: { body: "large" } } });
});

test("traffic payload stream rejects conflicting, incomplete, and malformed packets", () => {
  const collector = new TrafficPayloadCollector("flow-1");
  collector.accept(packet({ version: 1, revision: 1, index: 0, count: 2, flowId: "flow-1", payload: "{\"payload\":" }));
  assert.throws(
    () => collector.accept(packet({ version: 1, revision: 1, index: 0, count: 2, flowId: "flow-1", payload: "{\"payload\":" })),
    /分片重复/u,
  );
  assert.throws(() => collector.accept(packet({ version: 1, revision: 1, index: 1, count: 3, flowId: "flow-1", payload: "}" })), /数量不一致/u);
  assert.throws(() => collector.complete(), /不完整/u);
  assert.throws(() => collector.accept(packet({ version: 2, revision: 1, index: 1, count: 2, flowId: "flow-1", payload: "}" })), /版本无效/u);
  assert.throws(() => collector.accept(packet({ version: 1, revision: 2, index: 1, count: 2, flowId: "flow-1", payload: "}" })), /版本不一致/u);
  const malformed = new TrafficPayloadCollector("flow-1");
  assert.throws(() => malformed.accept(packet({ version: 1, revision: 1, index: 0, count: 1, flowId: "flow-1", payload: "not-json" })), /不是 JSON/u);
});
