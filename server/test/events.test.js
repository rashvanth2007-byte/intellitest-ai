import { test } from 'node:test';
import assert from 'node:assert/strict';
import { publish, subscribe, finalState } from '../src/scan/events.js';

test('done state is retained for subscribers that raced the finish', () => {
  const seen = [];
  publish('race-scan', 'done', { status: 'completed' }); // published before anyone subscribed
  const unsub = subscribe('race-scan', (e) => seen.push(e));
  assert.equal(seen.length, 0);
  assert.deepEqual(finalState('race-scan'), { status: 'completed' });
  assert.equal(finalState('other-scan'), null);
  unsub();
});
