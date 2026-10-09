import { EventEmitter } from 'node:events';

/** In-process pub/sub for scan progress, consumed by the SSE endpoint. */
const bus = new EventEmitter();
bus.setMaxListeners(0);
const snapshots = new Map(); // scanId -> latest progress (for late subscribers)
const finals = new Map(); // scanId -> 'done' payload (for subscribers that raced the finish)

export function publish(scanId, type, data) {
  if (type === 'progress') snapshots.set(scanId, data);
  if (type === 'done') finals.set(scanId, data);
  bus.emit(scanId, { type, data });
  if (type === 'done') setTimeout(() => { snapshots.delete(scanId); finals.delete(scanId); }, 60_000).unref();
}

export function subscribe(scanId, fn) {
  bus.on(scanId, fn);
  return () => bus.off(scanId, fn);
}

export const snapshot = (scanId) => snapshots.get(scanId) || null;
export const finalState = (scanId) => finals.get(scanId) || null;
