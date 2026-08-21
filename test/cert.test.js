import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  classify,
  certFitsTab,
  EMPTY_PUBLIC_CAS,
  hostMatchesDns,
  iconKind,
  mergeOverlay,
  overlayDnsHasHost,
  removeOverlayHost,
  parsePublicCas,
  pickPublicCas,
  resolveNavRecord,
  shouldKeepOnComplete,
  shouldKeepRecord,
  statusLine,
} from '../cert.js';

const pub = {
  version: 1,
  generatedAt: 't',
  source: 'test',
  organizations: ['DigiCert Inc', 'Google Trust Services'],
  issuerCNs: ['WE2'],
  rootSpkis: ['aabbcc'],
};

test('parsePublicCas rejects junk and empty lists stay empty', () => {
  assert.equal(parsePublicCas(null), null);
  assert.equal(parsePublicCas('nope'), null);
  assert.equal(parsePublicCas({}), null);
  const emptyValid = {
    version: 1,
    generatedAt: '',
    source: '',
    organizations: [],
    issuerCNs: [],
    rootSpkis: [],
  };
  assert.equal(parsePublicCas(emptyValid), null);
  assert.equal(parsePublicCas(JSON.stringify(emptyValid)), null);
  assert.deepEqual(pickPublicCas('bad', null, null), EMPTY_PUBLIC_CAS);
  assert.deepEqual(pickPublicCas(emptyValid, emptyValid, emptyValid), EMPTY_PUBLIC_CAS);
  const packed = parsePublicCas(readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'public-cas.json'), 'utf8'));
  assert.ok(packed);
  assert.ok(packed.organizations.length >= 50);
  assert.ok(packed.organizations.includes("Let's Encrypt"));
  assert.equal(pickPublicCas('bad', pub, packed).organizations[0], packed.organizations[0]);
  assert.equal(pickPublicCas(emptyValid, null, packed).organizations.length, packed.organizations.length);
  const stale = {
    ...packed,
    generatedAt: '2020-01-01T00:00:00.000Z',
    organizations: packed.organizations.filter((o) => o !== "Let's Encrypt"),
  };
  assert.ok(stale.organizations.length >= 50);
  assert.equal(stale.organizations.includes("Let's Encrypt"), false);
  assert.ok(pickPublicCas(stale, null, packed).organizations.includes("Let's Encrypt"));
});

test('classify: short issuer CN alone does not match public list', () => {
  const cas = { ...pub, issuerCNs: ['WE2', 'DigiCert Global CA'] };
  assert.equal(
    classify({
      issuer: { CN: 'WE2', O: 'Zscaler Inc.', OU: '' },
      hostname: 'example.com',
      publicCas: cas,
      overlays: [],
      chainSpkis: [],
      certNc: null,
    }),
    'intercept',
  );
  assert.equal(
    classify({
      issuer: { CN: 'DigiCert Global CA', O: 'Not A Real CA', OU: '' },
      hostname: 'example.com',
      publicCas: cas,
      overlays: [],
      chainSpkis: [],
      certNc: null,
    }),
    'public',
  );
});

test('classify: packed list treats Let\'s Encrypt leaf as public', () => {
  const packed = parsePublicCas(readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'public-cas.json'), 'utf8'));
  assert.equal(
    classify({
      issuer: { CN: 'R10', O: "Let's Encrypt", OU: '' },
      hostname: 'example.com',
      publicCas: packed,
      overlays: [],
      chainSpkis: [],
      certNc: null,
    }),
    'public',
  );
});

test('classify: public O / CN / SPKI', () => {
  assert.equal(
    classify({
      issuer: { CN: 'DigiCert Global CA', O: 'DigiCert Inc', OU: '' },
      hostname: 'example.com',
      publicCas: pub,
      overlays: [],
      chainSpkis: [],
      certNc: null,
    }),
    'public',
  );
  assert.equal(
    classify({
      issuer: { CN: 'WE2', O: 'Google Trust Services', OU: '' },
      hostname: 'mail.google.com',
      publicCas: pub,
      overlays: [],
      chainSpkis: [],
      certNc: null,
    }),
    'public',
  );
  const llc = { ...pub, organizations: ['Google Trust Services LLC'] };
  assert.equal(
    classify({
      issuer: { CN: 'WE2', O: 'Google Trust Services', OU: '' },
      hostname: 'www.google.com',
      publicCas: llc,
      overlays: [],
      chainSpkis: [],
      certNc: null,
    }),
    'public',
  );
  assert.equal(
    classify({
      issuer: { CN: 'Unknown Inter', O: 'Unknown Org', OU: '' },
      hostname: 'example.com',
      publicCas: pub,
      overlays: [],
      chainSpkis: ['aabbcc'],
      certNc: null,
    }),
    'public',
  );
});

test('classify: unconstrained alternate is intercept even with empty public list', () => {
  const z = { CN: 'Zscaler Intermediate Root CA (zscalerthree.net) (t)', O: 'Zscaler Inc.', OU: 'Zscaler Inc.' };
  assert.equal(
    classify({
      issuer: z,
      hostname: 'mail.google.com',
      publicCas: EMPTY_PUBLIC_CAS,
      overlays: [],
      chainSpkis: [],
      certNc: null,
    }),
    'intercept',
  );
});

test('classify: HP DigitalBadge overlay for content.int.hp.com', () => {
  const issuer = {
    CN: 'HP Inc Private SSL Intermediate CA',
    O: 'HP Global PKI Services',
    OU: 'HP DigitalBadge PKI',
  };
  const overlays = mergeOverlay([], issuer, 'content.int.hp.com');
  assert.equal(
    classify({
      issuer,
      hostname: 'content.int.hp.com',
      publicCas: EMPTY_PUBLIC_CAS,
      overlays,
      chainSpkis: [],
      certNc: null,
    }),
    'in-scope',
  );
});

test('classify: overlay in-scope vs off-scope', () => {
  const hp = { CN: 'HP Inc Private SSL', O: 'HP Inc', OU: '' };
  const overlays = [{ O: 'HP Inc', CN: null, dns: ['hp.com'] }];
  assert.equal(
    classify({
      issuer: hp,
      hostname: 'www.hp.com',
      publicCas: pub,
      overlays,
      chainSpkis: [],
      certNc: null,
    }),
    'in-scope',
  );
  assert.equal(
    classify({
      issuer: hp,
      hostname: 'mail.google.com',
      publicCas: pub,
      overlays,
      chainSpkis: [],
      certNc: null,
    }),
    'intercept',
  );
});

test('classify: cert permitted DNS without overlay', () => {
  const hp = { CN: 'HP Inc Private SSL', O: 'HP Inc', OU: '' };
  assert.equal(
    classify({
      issuer: hp,
      hostname: 'hp.com',
      publicCas: pub,
      overlays: [],
      chainSpkis: [],
      certNc: { permitted: ['.hp.com'], excluded: [] },
    }),
    'in-scope',
  );
});

test('hostMatchesDns', () => {
  assert.equal(hostMatchesDns('www.hp.com', 'hp.com'), true);
  assert.equal(hostMatchesDns('hp.com', 'hp.com'), true);
  assert.equal(hostMatchesDns('hp.com', '.hp.com'), true);
  assert.equal(hostMatchesDns('not-hp.com', 'hp.com'), false);
});

test('mergeOverlay adds host', () => {
  const issuer = { CN: 'HP', O: 'HP Inc', OU: '' };
  const next = mergeOverlay([], issuer, 'www.hp.com');
  assert.equal(next.length, 1);
  assert.equal(next[0].O, 'HP Inc');
  assert.deepEqual(next[0].dns, ['www.hp.com']);
  assert.equal(overlayDnsHasHost(next[0], 'www.hp.com'), true);
  assert.equal(overlayDnsHasHost(next[0], 'other.hp.com'), false);
});

test('removeOverlayHost drops exact host and empty overlay', () => {
  const issuer = { CN: 'HP', O: 'HP Inc', OU: '' };
  const added = mergeOverlay([], issuer, 'content.int.hp.com');
  const gone = removeOverlayHost(added, issuer, 'content.int.hp.com');
  assert.equal(gone.length, 0);
  const two = mergeOverlay(mergeOverlay([], issuer, 'a.hp.com'), issuer, 'b.hp.com');
  const one = removeOverlayHost(two, issuer, 'a.hp.com');
  assert.deepEqual(one[0].dns, ['b.hp.com']);
});

test('iconKind + statusLine table', () => {
  assert.equal(iconKind(null), 'yellow');
  assert.equal(statusLine(null), 'Reload the tab to inspect the certificate');

  const reload = { url: '', subject: null, issuer: null, verdict: null, error: 'reload' };
  assert.equal(iconKind(reload), 'yellow');

  const http = { url: 'http://example.com/', subject: null, issuer: null, verdict: null, error: 'not-https' };
  assert.equal(iconKind(http), 'default');
  assert.equal(statusLine(http), 'Not HTTPS — no certificate');

  const old = { url: '', subject: null, issuer: null, verdict: null, error: 'no-security-info' };
  assert.equal(iconKind(old), 'yellow');
  assert.equal(statusLine(old), 'Needs Chromium 144+');

  const parse = { url: '', subject: null, issuer: null, verdict: null, error: 'parse' };
  assert.equal(iconKind(parse), 'yellow');
  assert.equal(statusLine(parse), 'Couldn’t parse certificate');

  const hit = {
    url: 'https://mail.google.com/',
    subject: { CN: 'mail.google.com', O: '', OU: '' },
    issuer: { CN: 'Zscaler Intermediate Root CA (zscalerthree.net) (t)', O: 'Zscaler Inc.', OU: 'Zscaler Inc.' },
    verdict: 'intercept',
    error: null,
  };
  assert.equal(iconKind(hit), 'red');
  assert.equal(statusLine(hit), 'Unconstrained or off-scope intercepting CA');

  const clean = {
    url: 'https://example.com/',
    subject: { CN: 'example.com', O: 'Zscaler Inc.', OU: '' },
    issuer: { CN: 'DigiCert Global CA', O: 'DigiCert Inc', OU: '' },
    verdict: 'public',
    error: null,
  };
  assert.equal(iconKind(clean), 'green');
  assert.equal(statusLine(clean), 'Public CA');

  const scoped = {
    url: 'https://www.hp.com/',
    subject: { CN: 'www.hp.com', O: '', OU: '' },
    issuer: { CN: 'HP', O: 'HP Inc', OU: '' },
    verdict: 'in-scope',
    error: null,
  };
  assert.equal(iconKind(scoped), 'blue');
  assert.equal(statusLine(scoped), 'Private CA, in-scope');
});

test('certFitsTab: sibling HP enterprise hosts share a 3-label suffix', () => {
  assert.equal(
    certFitsTab('https://static.azc.ext.hp.com/x', 'https://github.azc.ext.hp.com/x'),
    true,
  );
  assert.equal(certFitsTab('https://github.githubassets.com/x', 'https://github.com/settings/copilot/features'), false);
});

test('shouldKeepRecord: keep parsed cert on same origin URL change', () => {
  const rec = {
    url: 'https://example.com/',
    subject: { CN: 'example.com', O: '', OU: '' },
    issuer: { CN: 'DigiCert', O: 'DigiCert Inc', OU: '' },
    verdict: 'public',
    error: null,
  };
  assert.equal(shouldKeepRecord(rec, 'https://example.com/'), true);
  assert.equal(shouldKeepRecord(rec, 'https://example.com/index.html'), true);
  assert.equal(shouldKeepRecord(rec, 'https://other.example/'), false);
  const cdn = {
    ...rec,
    url: 'https://static.azc.ext.hp.com/asset.js',
    pageUrl: 'https://github.azc.ext.hp.com/stratus/hpdevbox/issues',
  };
  assert.equal(shouldKeepRecord(cdn, 'https://github.azc.ext.hp.com/stratus/hpdevbox/issues'), true);
  assert.equal(shouldKeepRecord(cdn, 'https://gitlab.azc.ext.hp.com/other'), false);
  assert.equal(
    shouldKeepOnComplete(
      { ...cdn, pageUrl: cdn.url },
      'https://github-partner.azc.ext.hp.com/jedi/harvester_crawler/pull/2844',
    ),
    true,
  );
  assert.equal(shouldKeepRecord(null, 'https://example.com/'), false);
  const reload = { url: 'https://example.com/a', subject: null, issuer: null, verdict: null, error: 'reload' };
  assert.equal(shouldKeepRecord(reload, 'https://example.com/b'), false);
  assert.equal(shouldKeepRecord(reload, 'https://example.com/a'), false);
  const missing = {
    url: 'https://example.com/',
    subject: null,
    issuer: null,
    verdict: null,
    error: 'no-security-info',
  };
  assert.equal(shouldKeepRecord(missing, 'https://example.com/index.html'), true);
  assert.equal(shouldKeepRecord(missing, 'https://other.example/'), false);
});

test('resolveNavRecord: do not keep prior-origin public cert after navigate to MITM host', () => {
  const priorPublic = {
    url: 'https://example.com/',
    pageUrl: 'https://example.com/',
    subject: { CN: 'example.com', O: '', OU: '' },
    issuer: { CN: 'DigiCert', O: 'DigiCert Inc', OU: '' },
    verdict: 'public',
    error: null,
  };
  const intercept = {
    url: 'https://bitwarden.com/',
    pageUrl: 'https://bitwarden.com/',
    subject: { CN: 'bitwarden.com', O: 'Zscaler Inc.', OU: 'Zscaler Inc.' },
    issuer: {
      CN: 'Zscaler Intermediate Root CA (zscalerthree.net) (t)',
      O: 'Zscaler Inc.',
      OU: 'Zscaler Inc.',
    },
    verdict: 'intercept',
    error: null,
  };
  // Stale onUpdated snapshot alone must not win — that painted green over red.
  assert.equal(resolveNavRecord(priorPublic, priorPublic, 'https://bitwarden.com/'), null);
  // Capture won the race: second load sees intercept.
  assert.equal(resolveNavRecord(priorPublic, intercept, 'https://bitwarden.com/'), intercept);
  assert.equal(resolveNavRecord(intercept, intercept, 'https://bitwarden.com/'), intercept);
});

