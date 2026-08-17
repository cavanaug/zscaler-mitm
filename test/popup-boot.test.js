import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

test('popup.html shows Loading before JS and loads popup.js as a module', () => {
  const html = readFileSync(join(root, 'popup.html'), 'utf8');
  assert.match(html, /id="status">Loading…/);
  assert.match(html, /id="debug">starting…/);
  assert.match(html, /script type="module" src="popup\.js"/);
  assert.match(html, /popup\.js did not start/);
});
