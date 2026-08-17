import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  classify,
  EMPTY_PUBLIC_CAS,
  hostMatchesDns,
  iconKind,
  mergeOverlay,
  parsePublicCas,
  parseX509Names,
  pickPublicCas,
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
  assert.deepEqual(pickPublicCas('bad', null, null), EMPTY_PUBLIC_CAS);
  assert.equal(pickPublicCas('bad', pub, EMPTY_PUBLIC_CAS).organizations[0], 'DigiCert Inc');
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
  assert.equal(shouldKeepRecord(null, 'https://example.com/'), false);
  const reload = { url: 'https://example.com/a', subject: null, issuer: null, verdict: null, error: 'reload' };
  assert.equal(shouldKeepRecord(reload, 'https://example.com/b'), false);
  assert.equal(shouldKeepRecord(reload, 'https://example.com/a'), true);
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

const fixtures = join(dirname(fileURLToPath(import.meta.url)), 'fixtures');

function loadDer(name) {
  return new Uint8Array(readFileSync(join(fixtures, name)));
}

test('parseX509Names: issuer O = Zscaler Inc.', () => {
  const { issuer, subject } = parseX509Names(loadDer('issuer-o-zscaler.der'));
  assert.equal(issuer.O, 'Zscaler Inc.');
  assert.equal(
    classify({
      issuer,
      hostname: 'example.com',
      publicCas: EMPTY_PUBLIC_CAS,
      overlays: [],
      chainSpkis: [],
      certNc: null,
    }),
    'intercept',
  );
  assert.equal(subject.CN, 'example.com');
});

test('parseX509Names: issuer OU = Zscaler Inc.', () => {
  const { issuer } = parseX509Names(loadDer('issuer-ou-zscaler.der'));
  assert.equal(issuer.OU, 'Zscaler Inc.');
});

test('parseX509Names: issuer CN zscalerthree.net', () => {
  const { issuer } = parseX509Names(loadDer('issuer-cn-zscalerthree.der'));
  assert.equal(issuer.CN, 'Zscaler Intermediate Root CA (zscalerthree.net) (t)');
});

test('parseX509Names: issuer CN zscalerone.net', () => {
  const { issuer } = parseX509Names(loadDer('issuer-cn-zscalerone.der'));
  assert.ok(issuer.CN.startsWith('Zscaler Intermediate Root CA'));
});

test('parseX509Names: subject O = Zscaler Inc. with DigiCert issuer does not match', () => {
  const { subject, issuer } = parseX509Names(loadDer('subject-zscaler-issuer-digicert.der'));
  assert.equal(subject.O, 'Zscaler Inc.');
  assert.equal(issuer.O, 'DigiCert Inc');
  assert.equal(
    classify({
      issuer,
      hostname: 'example.com',
      publicCas: pub,
      overlays: [],
      chainSpkis: [],
      certNc: null,
    }),
    'public',
  );
});

test('parseX509Names: garbage throws', () => {
  assert.throws(() => parseX509Names(Uint8Array.of(0xff, 0x00, 0x01)));
  assert.throws(() => parseX509Names(new Uint8Array(0)));
});

test('parseX509Names: ArrayBuffer and JSON-cloned bytes', () => {
  const der = loadDer('issuer-o-zscaler.der');
  const fromAb = parseX509Names(der.buffer.slice(der.byteOffset, der.byteOffset + der.byteLength));
  assert.equal(fromAb.issuer.O, 'Zscaler Inc.');
  const cloned = JSON.parse(JSON.stringify(der));
  const fromObj = parseX509Names(cloned);
  assert.equal(fromObj.issuer.O, 'Zscaler Inc.');
  const fromArr = parseX509Names(Array.from(der));
  assert.equal(fromArr.issuer.O, 'Zscaler Inc.');
});
