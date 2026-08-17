import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const icons = join(dirname(fileURLToPath(import.meta.url)), '..', 'icons');

function pngColorType(file) {
  const buf = readFileSync(join(icons, file));
  return buf[25];
}

test('toolbar icons used by setIcon are RGBA PNG', () => {
  for (const file of ['green-16.png', 'green-32.png', 'blue-16.png', 'blue-32.png', 'red-16.png', 'yellow-16.png']) {
    assert.equal(pngColorType(file), 6, file);
  }
});
