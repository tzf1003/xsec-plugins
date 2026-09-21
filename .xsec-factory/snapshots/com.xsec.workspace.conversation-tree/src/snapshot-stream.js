const SNAPSHOT_VERSION = 1;
const MAX_PACKET_BYTES = 48 * 1024;
const MAX_PACKET_COUNT = 16_384;
const decoder = new TextDecoder();

function record(value, name) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`conversation_tree_invalid_${name}`);
  }
  return value;
}

function integer(value, name, minimum, maximum) {
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new Error(`conversation_tree_invalid_${name}`);
  }
  return value;
}

function parsePacket(payload) {
  if (!(payload instanceof ArrayBuffer) || payload.byteLength > MAX_PACKET_BYTES) {
    throw new Error("conversation_tree_invalid_snapshot_packet");
  }
  let value;
  try {
    value = JSON.parse(decoder.decode(payload));
  } catch {
    throw new Error("conversation_tree_invalid_snapshot_packet");
  }
  const packet = record(value, "snapshot_packet");
  if (packet.version !== SNAPSHOT_VERSION || typeof packet.payload !== "string") {
    throw new Error("conversation_tree_invalid_snapshot_packet");
  }
  const count = integer(packet.count, "snapshot_count", 1, MAX_PACKET_COUNT);
  return {
    revision: integer(packet.revision, "snapshot_revision", 1, Number.MAX_SAFE_INTEGER),
    index: integer(packet.index, "snapshot_index", 0, count - 1),
    count,
    payload: packet.payload,
  };
}

function parseSnapshot(value) {
  const snapshot = record(value, "snapshot");
  if (snapshot.version !== SNAPSHOT_VERSION || (snapshot.session !== null && !record(snapshot.session, "session"))) {
    throw new Error("conversation_tree_invalid_snapshot");
  }
  return snapshot;
}

/** Reassembles latest-only Host snapshots sent through the binary data bridge. */
export class ConversationTreeSnapshotReceiver {
  constructor() {
    this.completedRevision = 0;
    this.current = null;
  }

  accept(payload) {
    const packet = parsePacket(payload);
    if (packet.revision <= this.completedRevision) return undefined;
    if (!this.current || packet.revision > this.current.revision) {
      this.current = { revision: packet.revision, count: packet.count, chunks: new Array(packet.count) };
    }
    if (packet.revision !== this.current.revision || packet.count !== this.current.count) return undefined;
    this.current.chunks[packet.index] = packet.payload;
    if (this.current.chunks.includes(undefined)) return undefined;
    const completed = this.current;
    this.current = null;
    let snapshot;
    try {
      snapshot = parseSnapshot(JSON.parse(completed.chunks.join("")));
    } catch {
      throw new Error("conversation_tree_invalid_snapshot");
    }
    this.completedRevision = completed.revision;
    return snapshot;
  }
}
