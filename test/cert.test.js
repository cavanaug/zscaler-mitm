import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
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
  parseNameConstraints,
  parsePublicCas,
  parseSpkiDer,
  parseX509Names,
  pickPublicCas,
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
  assert.equal(pickPublicCas('bad', pub, packed).organizations[0], packed.organizations[0]);
  assert.equal(pickPublicCas(emptyValid, null, packed).organizations.length, packed.organizations.length);
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

/** Patch issuer-nc-hp.der: permitted NC has foo.com, unknown rfc822Name, bar.com */
function ncFixtureWithUnknownTag() {
  const base = loadDer('issuer-nc-hp.der');
  let oidOff = 0;
  while (oidOff < base.length - 4) {
    if (
      base[oidOff] === 0x06 &&
      base[oidOff + 1] === 0x03 &&
      base[oidOff + 2] === 0x55 &&
      base[oidOff + 3] === 0x1d &&
      base[oidOff + 4] === 0x1e
    ) {
      break;
    }
    oidOff++;
  }
  const octetOff = oidOff + 5;
  const ncOff = octetOff + 2;
  const oldNcLen = base[octetOff + 1];
  const ncInner = Uint8Array.from([
    0x30, 0x1a, 0xa0, 0x18, 0x30, 0x16, 0x82, 0x07, 0x66, 0x6f, 0x6f, 0x2e, 0x63, 0x6f, 0x6d, 0x81, 0x04,
    0x74, 0x65, 0x73, 0x74, 0x82, 0x07, 0x62, 0x61, 0x72, 0x2e, 0x63, 0x6f, 0x6d,
  ]);
  const delta = ncInner.length - oldNcLen;
  const out = new Uint8Array(base.length + delta);
  out.set(base.subarray(0, ncOff), 0);
  out.set(ncInner, ncOff);
  out.set(base.subarray(ncOff + oldNcLen), ncOff + ncInner.length);
  out[3] += delta;
  out[7] += delta;
  out[oidOff - 1] += delta;
  out[octetOff + 1] = ncInner.length;
  const a3Off = base.indexOf(0xa3, 400);
  out[a3Off + 1] += delta;
  out[a3Off + 3] += delta;
  return out;
}

test('parseNameConstraints: skips unknown TLV and collects later DNS names', () => {
  const nc = parseNameConstraints(ncFixtureWithUnknownTag());
  assert.ok(nc);
  assert.ok(nc.permitted.includes('foo.com'));
  assert.ok(nc.permitted.includes('bar.com'));
});

test('parseNameConstraints: permitted .hp.com', () => {
  const nc = parseNameConstraints(loadDer('issuer-nc-hp.der'));
  assert.ok(nc);
  assert.ok(nc.permitted.some((d) => d.replace(/^\./, '') === 'hp.com' || d === '.hp.com' || d === 'hp.com'));
  assert.equal(
    classify({
      issuer: { CN: 'HP Test CA', O: 'HP Inc', OU: '' },
      hostname: 'hp.com',
      publicCas: EMPTY_PUBLIC_CAS,
      overlays: [],
      chainSpkis: [],
      certNc: nc,
    }),
    'in-scope',
  );
});

test('parseSpkiDer: non-empty and hashes stably', () => {
  const spki = parseSpkiDer(loadDer('issuer-nc-hp.der'));
  assert.ok(spki.byteLength > 16);
  const hex = createHash('sha256').update(spki).digest('hex');
  assert.equal(hex.length, 64);
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
