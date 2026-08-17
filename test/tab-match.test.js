import assert from 'node:assert/strict';
import test from 'node:test';
import { certFitsTab } from '../cert.js';
import {
  documentUrl,
  isOwnWebRequest,
  pickTabId,
  requestIsPageCert,
  shouldSkipCapture,
  storageOriginKey,
  storageOriginKeys,
} from '../tab-match.js';

test('pickTabId: prefers details.tabId when set', () => {
  assert.equal(pickTabId({ tabId: 7, url: 'https://a.example/' }, [], null), 7);
});

test('pickTabId: exact URL among queried tabs', () => {
  assert.equal(
    pickTabId(
      { tabId: -1, url: 'https://a.example/path' },
      [
        { id: 1, url: 'https://other.example/' },
        { id: 2, url: 'https://a.example/path' },
      ],
      null,
    ),
    2,
  );
});

test('pickTabId: unique same origin when URL differs', () => {
  assert.equal(
    pickTabId(
      { tabId: -1, url: 'https://a.example/redir' },
      [{ id: 3, url: 'https://a.example/' }],
      null,
    ),
    3,
  );
});

test('pickTabId: active tab of same origin when several tabs match', () => {
  assert.equal(
    pickTabId(
      { tabId: -1, url: 'https://a.example/x' },
      [
        { id: 4, url: 'https://a.example/one' },
        { id: 5, url: 'https://a.example/two' },
      ],
      { id: 5, url: 'https://a.example/two' },
    ),
    5,
  );
});

test('pickTabId: tabId -1 still uses active tab when origins differ', () => {
  assert.equal(
    pickTabId(
      { tabId: -1, url: 'https://cdn.example/', type: 'xmlhttprequest' },
      [{ id: 1, url: 'https://github.azc.ext.hp.com/x' }],
      { id: 1, url: 'https://github.azc.ext.hp.com/x' },
    ),
    1,
  );
});

test('certFitsTab: related hp enterprise hosts', () => {
  assert.equal(
    certFitsTab(
      'https://github.azc.ext.hp.com/stratus/hpdevbox/issues',
      'https://github.azc.ext.hp.com/stratus/hpdevbox/issues',
    ),
    true,
  );
  assert.equal(
    certFitsTab('https://static.azc.ext.hp.com/x', 'https://github.azc.ext.hp.com/x'),
    true,
  );
  assert.equal(certFitsTab('https://evil.example/', 'https://github.azc.ext.hp.com/x'), false);
});

test('pickTabId: main_frame with tabId -1 uses active tab', () => {
  assert.equal(
    pickTabId(
      { tabId: -1, url: 'https://a.example/', type: 'main_frame' },
      [{ id: 1, url: 'https://b.example/' }],
      { id: 1, url: 'https://b.example/' },
    ),
    1,
  );
});

test('storageOriginKey keys HTTPS origins', () => {
  assert.equal(
    storageOriginKey('https://hp-jira.external.hp.com/browse/ARCH-3378'),
    'okOrigin:https://hp-jira.external.hp.com',
  );
  assert.equal(storageOriginKey('http://hp-jira.external.hp.com/'), null);
  assert.deepEqual(
    storageOriginKeys(
      'https://hp-jira.external.hp.com/browse/ARCH-3378',
      'https://static.cdn.atlassian.com/x.js',
    ),
    ['okOrigin:https://hp-jira.external.hp.com', 'okOrigin:https://static.cdn.atlassian.com'],
  );
});

test('documentUrl: subresource uses initiator, not the CDN URL', () => {
  assert.equal(
    documentUrl(
      {
        type: 'script',
        url: 'https://static.azc.ext.hp.com/asset.js',
        initiator: 'https://github-partner.azc.ext.hp.com',
      },
      '',
    ),
    'https://github-partner.azc.ext.hp.com',
  );
  assert.equal(
    documentUrl({ type: 'main_frame', url: 'https://github-partner.azc.ext.hp.com/x' }, 'https://other.example/'),
    'https://github-partner.azc.ext.hp.com/x',
  );
});

test('requestIsPageCert: first-party Jira vs Amplitude tracker', () => {
  const tab = 'https://hp-jira.external.hp.com/browse/ARCH-3378';
  assert.equal(requestIsPageCert({ type: 'main_frame', url: tab }, tab), true);
  assert.equal(
    requestIsPageCert(
      {
        type: 'xmlhttprequest',
        url: 'https://hp-jira.external.hp.com/rest/api/2/issue/ARCH-3378',
        initiator: 'https://hp-jira.external.hp.com',
      },
      tab,
    ),
    true,
  );
  assert.equal(
    requestIsPageCert(
      {
        type: 'script',
        url: 'https://cdn.amplitude.com/script.js',
        initiator: 'https://hp-jira.external.hp.com',
      },
      tab,
    ),
    false,
  );
});

test('shouldSkipCapture: keep document cert; recapture after origin change', () => {
  const rec = {
    url: 'https://static.azc.ext.hp.com/x',
    pageUrl: 'https://github.azc.ext.hp.com/issues',
    error: null,
  };
  assert.equal(
    shouldSkipCapture(rec, { type: 'xmlhttprequest', url: 'https://static.azc.ext.hp.com/y' }, rec.pageUrl),
    true,
  );
  assert.equal(shouldSkipCapture(rec, { type: 'main_frame', url: 'https://gitlab.azc.ext.hp.com/' }, rec.pageUrl), false);
  assert.equal(
    shouldSkipCapture(rec, { type: 'xmlhttprequest', url: 'https://gitlab.azc.ext.hp.com/api' }, 'https://gitlab.azc.ext.hp.com/'),
    false,
  );
});

test('isOwnWebRequest: packed list URL only, not extension fetches of the tab', () => {
  const prefix = 'https://raw.githubusercontent.com/cavanaug/zscaler-mitm/';
  assert.equal(
    isOwnWebRequest({ initiator: 'chrome-extension://abc', url: 'https://content.int.hp.com/' }, prefix),
    false,
  );
  assert.equal(isOwnWebRequest({ tabId: -1, url: prefix + 'master/public-cas.json' }, prefix), true);
  assert.equal(isOwnWebRequest({ tabId: -1, url: 'https://example.com/' }, prefix), false);
});
