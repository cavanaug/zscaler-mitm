import assert from 'node:assert/strict';
import test from 'node:test';
import { probeFetch } from '../probe.js';

test('probeFetch abandons a hung fetch', async () => {
  const fetchFn = (_url, init) =>
    new Promise((_resolve, reject) => {
      init.signal.addEventListener('abort', () => reject(init.signal.reason));
    });
  const t0 = Date.now();
  await probeFetch('https://example.com/dashboard', fetchFn, 50);
  assert.ok(Date.now() - t0 < 500);
});

test('probeFetch tries HEAD then GET on failure', async () => {
  const methods = [];
  const fetchFn = async (_url, init) => {
    methods.push(init.method);
    throw new Error('net');
  };
  await probeFetch('https://example.com/path', fetchFn, 1000);
  assert.deepEqual(methods, ['HEAD', 'GET']);
});
