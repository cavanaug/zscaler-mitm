import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { parseNameConstraints, parseSpkiDer, parseX509Names } from '../asn1.js';
import { classify, EMPTY_PUBLIC_CAS } from '../cert.js';

const pub = {
  version: 1,
  generatedAt: 't',
  source: 'test',
  organizations: ['DigiCert Inc', 'Google Trust Services'],
  issuerCNs: ['WE2'],
  rootSpkis: ['aabbcc'],
};

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
