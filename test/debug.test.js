import assert from 'node:assert/strict';
import test from 'node:test';
import { applyDebugVisibility, formatCaptureDebug } from '../debug.js';

test('formatCaptureDebug: tab mismatch and last URL', () => {
  const text = formatCaptureDebug({
    tab: { id: 7, url: 'https://hp-jira.external.hp.com/browse/ARCH-3378' },
    record: { error: 'reload', verdict: null, url: '', pageUrl: '' },
    meta: {
      lastTabId: 99,
      resolvedTabId: 7,
      attachedSpec: 'securityInfoRawDer',
      hasSi: true,
      derKind: 'object',
      lastError: null,
      lastUrl: 'https://cdn.amplitude.com/script.js',
      lastAt: Date.now() - 4000,
      canaryAt: Date.now() - 5000,
      canaryType: 'script',
    },
    hasHttps: true,
    source: 'none',
  });
  assert.match(text, /tab 7 last 99 resolved 7 \(mismatch\)/);
  assert.match(text, /si yes/);
  assert.match(text, /cdn\.amplitude\.com/);
  assert.match(text, /src=none/);
  assert.match(text, /httpsAccess yes/);
});

test('applyDebugVisibility toggles hidden and link label', () => {
  const debugEl = { hidden: false };
  const linkEl = { textContent: '' };
  applyDebugVisibility(false, debugEl, linkEl);
  assert.equal(debugEl.hidden, true);
  assert.equal(linkEl.textContent, 'Debug');
  applyDebugVisibility(true, debugEl, linkEl);
  assert.equal(debugEl.hidden, false);
  assert.equal(linkEl.textContent, 'Hide debug');
});
