import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { iconKind, isZscalerIssuer, parseX509Names, shouldKeepRecord, statusLine } from '../cert.js';

test('isZscalerIssuer: issuer O', () => {
  assert.equal(isZscalerIssuer({ CN: '', O: 'Zscaler Inc.', OU: '' }), true);
});

test('isZscalerIssuer: issuer OU', () => {
  assert.equal(isZscalerIssuer({ CN: '', O: '', OU: 'Zscaler Inc.' }), true);
});

test('isZscalerIssuer: issuer CN zscalerthree.net', () => {
  assert.equal(
    isZscalerIssuer({
      CN: 'Zscaler Intermediate Root CA (zscalerthree.net) (t)',
      O: '',
      OU: '',
    }),
    true,
  );
});

test('isZscalerIssuer: issuer CN other Zscaler clouds', () => {
  assert.equal(
    isZscalerIssuer({ CN: 'Zscaler Intermediate Root CA (zscalerone.net) (t)', O: '', OU: '' }),
    true,
  );
  assert.equal(
    isZscalerIssuer({ CN: 'Zscaler Intermediate Root CA (zscalertwo.net) (t)', O: '', OU: '' }),
    true,
  );
});

test('isZscalerIssuer: subject-like O on a DigiCert issuer does not match', () => {
  assert.equal(isZscalerIssuer({ CN: 'DigiCert Global CA', O: 'DigiCert Inc', OU: '' }), false);
});

test('isZscalerIssuer: missing issuer is false', () => {
  assert.equal(isZscalerIssuer(null), false);
  assert.equal(isZscalerIssuer(undefined), false);
});

test('iconKind + statusLine table', () => {
  assert.equal(iconKind(null), 'yellow');
  assert.equal(statusLine(null), 'Reload the tab to inspect the certificate');

  const reload = { url: '', subject: null, issuer: null, zscaler: false, error: 'reload' };
  assert.equal(iconKind(reload), 'yellow');
  assert.equal(statusLine(reload), 'Reload the tab to inspect the certificate');

  const http = { url: 'http://example.com/', subject: null, issuer: null, zscaler: false, error: 'not-https' };
  assert.equal(iconKind(http), 'default');
  assert.equal(statusLine(http), 'Not HTTPS — no certificate');

  const old = { url: '', subject: null, issuer: null, zscaler: false, error: 'no-security-info' };
  assert.equal(iconKind(old), 'yellow');
  assert.equal(statusLine(old), 'Needs Chrome/Brave 144+');

  const parse = { url: '', subject: null, issuer: null, zscaler: false, error: 'parse' };
  assert.equal(iconKind(parse), 'yellow');
  assert.equal(statusLine(parse), 'Couldn’t parse certificate');

  const hit = {
    url: 'https://example.com/',
    subject: { CN: 'example.com', O: '', OU: '' },
    issuer: { CN: 'Zscaler Intermediate Root CA (zscalerthree.net) (t)', O: 'Zscaler Inc.', OU: 'Zscaler Inc.' },
    zscaler: true,
    error: null,
  };
  assert.equal(iconKind(hit), 'red');
  assert.equal(statusLine(hit), 'Zscaler interception detected');

  const clean = {
    url: 'https://example.com/',
    subject: { CN: 'example.com', O: 'Zscaler Inc.', OU: '' },
    issuer: { CN: 'DigiCert Global CA', O: 'DigiCert Inc', OU: '' },
    zscaler: false,
    error: null,
  };
  assert.equal(iconKind(clean), 'default');
  assert.equal(statusLine(clean), 'Issuer is not Zscaler');
});

test('shouldKeepRecord: keep parsed cert on same origin URL change', () => {
  const rec = {
    url: 'https://example.com/',
    subject: { CN: 'example.com', O: '', OU: '' },
    issuer: { CN: 'DigiCert', O: 'DigiCert Inc', OU: '' },
    zscaler: false,
    error: null,
  };
  assert.equal(shouldKeepRecord(rec, 'https://example.com/'), true);
  assert.equal(shouldKeepRecord(rec, 'https://example.com/index.html'), true);
  assert.equal(shouldKeepRecord(rec, 'https://other.example/'), false);
  assert.equal(shouldKeepRecord(null, 'https://example.com/'), false);
  const reload = { url: 'https://example.com/a', subject: null, issuer: null, zscaler: false, error: 'reload' };
  assert.equal(shouldKeepRecord(reload, 'https://example.com/b'), false);
  assert.equal(shouldKeepRecord(reload, 'https://example.com/a'), true);
  const missing = {
    url: 'https://example.com/',
    subject: null,
    issuer: null,
    zscaler: false,
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
  assert.equal(isZscalerIssuer(issuer), true);
  assert.equal(subject.CN, 'example.com');
});

test('parseX509Names: issuer OU = Zscaler Inc.', () => {
  const { issuer } = parseX509Names(loadDer('issuer-ou-zscaler.der'));
  assert.equal(issuer.OU, 'Zscaler Inc.');
  assert.equal(isZscalerIssuer(issuer), true);
});

test('parseX509Names: issuer CN zscalerthree.net', () => {
  const { issuer } = parseX509Names(loadDer('issuer-cn-zscalerthree.der'));
  assert.equal(issuer.CN, 'Zscaler Intermediate Root CA (zscalerthree.net) (t)');
  assert.equal(isZscalerIssuer(issuer), true);
});

test('parseX509Names: issuer CN zscalerone.net', () => {
  const { issuer } = parseX509Names(loadDer('issuer-cn-zscalerone.der'));
  assert.ok(issuer.CN.startsWith('Zscaler Intermediate Root CA'));
  assert.equal(isZscalerIssuer(issuer), true);
});

test('parseX509Names: subject O = Zscaler Inc. with DigiCert issuer does not match', () => {
  const { subject, issuer } = parseX509Names(loadDer('subject-zscaler-issuer-digicert.der'));
  assert.equal(subject.O, 'Zscaler Inc.');
  assert.equal(issuer.O, 'DigiCert Inc');
  assert.equal(isZscalerIssuer(issuer), false);
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
