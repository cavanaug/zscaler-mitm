# Zscaler MITM Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a tiny MV3 extension whose toolbar spy icon turns red when the active tab’s HTTPS leaf cert is issued by Zscaler, yellow when the extension cannot tell, and default otherwise, with a popup showing subject and issuer CN/O/OU.

**Architecture:** Service worker listens to `webRequest.onHeadersReceived` (`main_frame` + `securityInfoRawDer`), parses the leaf DER in `cert.js`, stores a per-tab record in `chrome.storage.session`, and calls `chrome.action.setIcon` with the 16/32 spy PNGs. Popup reads that record. No content scripts, no debugger, no origin cache.

**Tech Stack:** Vanilla JS Chrome extension MV3 (ES modules), `chrome.webRequest` SecurityInfo (Chromium 144+), Node.js `node:test` (no npm packages).

**Spec:** `zscaler-mitm/docs/superpowers/specs/2026-08-14-zscaler-mitm-design.md`

**Working directory:** `/home/cavanaug/wip_other/projects/brave-extensions/zscaler-mitm`

## Global Constraints

- Manifest V3 only; load unpacked in Brave/Chrome; no Web Store, no options page, no content scripts, no `chrome.debugger`, no native messaging, no ZeroOmega fork.
- Chromium 144+ `webRequest` extraInfoSpec `securityInfoRawDer`.
- Match **issuer** only: O exactly `Zscaler Inc.` OR OU exactly `Zscaler Inc.` OR CN starts with `Zscaler Intermediate Root CA`.
- Do **not** match subject (a real `zscaler.com` cert issued by DigiCert must stay default).
- Icon files already on disk: `{default,yellow,red}-{16,32,48,128}.png` plus `source-spy.png`.
- No new npm dependencies. One Node test file. No Playwright.
- Toolbar icon only (not the tab strip). Per-tab `chrome.storage.session` only — no hostname cache.
- Popup copy is the spec table: “Not HTTPS — no certificate”, “Needs Chrome/Brave 144+”, “Reload the tab to inspect the certificate”, “Couldn’t parse certificate”.
- Never throw out of the service worker.
- `tabs` permission is required (not listed in the spec’s permission sketch) so HTTP/`chrome://`/`file://` can be classified without a webRequest event.

---

## File map

| Path | Responsibility |
|------|----------------|
| `manifest.json` | MV3, action icons + popup, service worker module, permissions |
| `cert.js` | DER → names, `isZscalerIssuer`, `iconKind`, `statusLine` |
| `background.js` | webRequest + tab events → session storage + `setIcon` |
| `popup.html` / `popup.js` | Render current tab’s record |
| `icons/*.png` | Spy silhouette (already generated) |
| `package.json` | `"type": "module"`, `"test": "node --test"` |
| `test/cert.test.js` | Node asserts |
| `test/fixtures/*.der` | Real X.509 leaves for the parser |
| `README.md` | Load unpacked + manual Brave checklist |

---

### Task 1: Package.json and commit icons

**Files:**
- Create: `package.json`
- Existing (do not regenerate): `icons/source-spy.png`, `icons/{default,yellow,red}-{16,32,48,128}.png`

**Interfaces:**
- Consumes: nothing
- Produces: ESM package so later tasks can `import` from `cert.js`; icons available at the paths `background.js` will pass to `setIcon`

- [ ] **Step 1: Verify icon files exist**

```bash
cd /home/cavanaug/wip_other/projects/brave-extensions/zscaler-mitm
ls icons/source-spy.png \
  icons/default-16.png icons/default-32.png icons/default-48.png icons/default-128.png \
  icons/yellow-16.png icons/yellow-32.png icons/yellow-48.png icons/yellow-128.png \
  icons/red-16.png icons/red-32.png icons/red-48.png icons/red-128.png
```

Expected: all 13 paths listed, no error.

- [ ] **Step 2: Write `package.json`**

```json
{
  "name": "zscaler-mitm",
  "private": true,
  "type": "module",
  "scripts": {
    "test": "node --test"
  }
}
```

- [ ] **Step 3: Commit**

```bash
git add zscaler-mitm/package.json zscaler-mitm/icons
git commit -m "$(cat <<'EOF'
chore(zscaler-mitm): add spy toolbar icons and ESM package.json

EOF
)"
```

---

### Task 2: `isZscalerIssuer` + `iconKind` + `statusLine`

**Files:**
- Create: `cert.js`
- Create: `test/cert.test.js`

**Interfaces:**
- Consumes: nothing
- Produces:

```js
/** @typedef {{ CN: string, O: string, OU: string }} CertName */
/** @typedef {{ url: string, subject: CertName | null, issuer: CertName | null, zscaler: boolean, error: null | 'not-https' | 'no-security-info' | 'parse' | 'reload' }} TabRecord */

export function isZscalerIssuer(issuer /*: CertName | null | undefined */) /*: boolean */
export function iconKind(record /*: TabRecord | null | undefined */) /*: 'default' | 'yellow' | 'red' */
export function statusLine(record /*: TabRecord | null | undefined */) /*: string */
```

`parseX509Names` is **not** in this task. Do not add a stub export for it.

- [ ] **Step 1: Write the failing tests**

Create `test/cert.test.js`:

```js
import assert from 'node:assert/strict';
import test from 'node:test';
import { iconKind, isZscalerIssuer, statusLine } from '../cert.js';

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
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /home/cavanaug/wip_other/projects/brave-extensions/zscaler-mitm
npm test
```

Expected: FAIL with `Cannot find module` / `ERR_MODULE_NOT_FOUND` for `../cert.js`.

- [ ] **Step 3: Write minimal `cert.js`**

```js
export function isZscalerIssuer(issuer) {
  if (!issuer) return false;
  if (issuer.O === 'Zscaler Inc.') return true;
  if (issuer.OU === 'Zscaler Inc.') return true;
  if (typeof issuer.CN === 'string' && issuer.CN.startsWith('Zscaler Intermediate Root CA')) {
    return true;
  }
  return false;
}

export function iconKind(record) {
  if (!record) return 'yellow';
  if (record.error === 'not-https') return 'default';
  if (record.error) return 'yellow';
  if (record.zscaler) return 'red';
  return 'default';
}

export function statusLine(record) {
  if (!record || record.error === 'reload') return 'Reload the tab to inspect the certificate';
  if (record.error === 'not-https') return 'Not HTTPS — no certificate';
  if (record.error === 'no-security-info') return 'Needs Chrome/Brave 144+';
  if (record.error === 'parse') return 'Couldn’t parse certificate';
  if (record.zscaler) return 'Zscaler interception detected';
  return 'Issuer is not Zscaler';
}
```

Use a real apostrophe `’` (U+2019) in `Couldn’t parse certificate` so it matches the spec and the test string exactly.

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /home/cavanaug/wip_other/projects/brave-extensions/zscaler-mitm
npm test
```

Expected: PASS, all tests in `test/cert.test.js`.

- [ ] **Step 5: Commit**

```bash
git add zscaler-mitm/cert.js zscaler-mitm/test/cert.test.js
git commit -m "$(cat <<'EOF'
feat(zscaler-mitm): add Zscaler issuer match and icon state helpers

EOF
)"
```

---

### Task 3: X.509 leaf parser

**Files:**
- Modify: `cert.js` (add `parseX509Names`)
- Modify: `test/cert.test.js` (parser cases)
- Create: `test/fixtures/issuer-o-zscaler.der`
- Create: `test/fixtures/issuer-ou-zscaler.der`
- Create: `test/fixtures/issuer-cn-zscalerthree.der`
- Create: `test/fixtures/issuer-cn-zscalerone.der`
- Create: `test/fixtures/subject-zscaler-issuer-digicert.der`

**Interfaces:**
- Consumes: `isZscalerIssuer` from Task 2
- Produces:

```js
export function parseX509Names(der /*: Uint8Array | ArrayBuffer */) /*: { subject: CertName, issuer: CertName } */
```

Throws `Error` on garbage / truncated DER. Callers in the service worker catch that and set `error: 'parse'`. Empty CN/O/OU fields are `''`, never `undefined`.

- [ ] **Step 1: Generate DER fixtures with openssl**

```bash
cd /home/cavanaug/wip_other/projects/brave-extensions/zscaler-mitm
mkdir -p test/fixtures
TMP=$(mktemp -d)

openssl req -x509 -newkey ed25519 -keyout "$TMP/k.pem" -out "$TMP/c.pem" -days 1 -nodes \
  -subj "/O=Zscaler Inc./CN=example.com"
openssl x509 -in "$TMP/c.pem" -outform DER -out test/fixtures/issuer-o-zscaler.der

openssl req -x509 -newkey ed25519 -keyout "$TMP/k.pem" -out "$TMP/c.pem" -days 1 -nodes \
  -subj "/OU=Zscaler Inc./CN=example.com"
openssl x509 -in "$TMP/c.pem" -outform DER -out test/fixtures/issuer-ou-zscaler.der

openssl req -x509 -newkey ed25519 -keyout "$TMP/k.pem" -out "$TMP/c.pem" -days 1 -nodes \
  -subj "/CN=Zscaler Intermediate Root CA (zscalerthree.net) (t)"
openssl x509 -in "$TMP/c.pem" -outform DER -out test/fixtures/issuer-cn-zscalerthree.der

openssl req -x509 -newkey ed25519 -keyout "$TMP/k.pem" -out "$TMP/c.pem" -days 1 -nodes \
  -subj "/CN=Zscaler Intermediate Root CA (zscalerone.net) (t)"
openssl x509 -in "$TMP/c.pem" -outform DER -out test/fixtures/issuer-cn-zscalerone.der

openssl req -x509 -newkey ed25519 -keyout "$TMP/ca.key" -out "$TMP/ca.pem" -days 1 -nodes \
  -subj "/O=DigiCert Inc/CN=DigiCert Test CA"
openssl req -new -newkey ed25519 -keyout "$TMP/leaf.key" -out "$TMP/leaf.csr" -nodes \
  -subj "/O=Zscaler Inc./CN=zscaler.com"
openssl x509 -req -in "$TMP/leaf.csr" -CA "$TMP/ca.pem" -CAkey "$TMP/ca.key" -CAcreateserial \
  -out "$TMP/leaf.pem" -days 1
openssl x509 -in "$TMP/leaf.pem" -outform DER -out test/fixtures/subject-zscaler-issuer-digicert.der

python3 -c "from pathlib import Path
p=Path('test/fixtures')
for f in p.glob('*.der'):
  b=f.read_bytes()
  assert b[0]==0x30 and len(b)>50, f
  print(f.name, len(b))"
```

Expected: five `.der` files printed with sizes > 50. If `ed25519` is unsupported, retry the same commands with `-newkey rsa:2048` instead of `-newkey ed25519`.

Self-signed fixtures have issuer == subject, which is enough to exercise issuer O / OU / CN. The CA-signed fixture is the false-positive case (subject O = Zscaler, issuer O = DigiCert).

- [ ] **Step 2: Append failing parser tests to `test/cert.test.js`**

Change the `cert.js` import line to:

```js
import { iconKind, isZscalerIssuer, parseX509Names, statusLine } from '../cert.js';
```

Add these imports at the top (keep the existing `assert` / `test` imports):

```js
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
```

Add at the bottom:

```js
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
```

- [ ] **Step 3: Run tests to verify parser cases fail**

```bash
cd /home/cavanaug/wip_other/projects/brave-extensions/zscaler-mitm
npm test
```

Expected: FAIL with `parseX509Names is not a function` or `does not provide an export named 'parseX509Names'`.

- [ ] **Step 4: Implement `parseX509Names` in `cert.js`**

Append (do not remove Task 2 exports):

```js
function readLen(buf, i) {
  if (i >= buf.length) throw new Error('truncated');
  const b = buf[i];
  if (b === 0x80) throw new Error('indefinite length');
  if (b < 0x80) return { len: b, i: i + 1 };
  const n = b & 0x7f;
  if (n === 0 || n > 4) throw new Error('bad length');
  let len = 0;
  for (let k = 0; k < n; k++) {
    if (i + 1 + k >= buf.length) throw new Error('truncated');
    len = (len << 8) | buf[i + 1 + k];
  }
  return { len, i: i + 1 + n };
}

function take(buf, i, tag) {
  if (i >= buf.length) throw new Error('truncated');
  if (buf[i] !== tag) {
    throw new Error('expected 0x' + tag.toString(16) + ', got 0x' + buf[i].toString(16));
  }
  const { len, i: v } = readLen(buf, i + 1);
  const start = v;
  const end = v + len;
  if (end > buf.length) throw new Error('truncated');
  return { start, end, i: end };
}

function decodeOid(bytes) {
  if (bytes.length === 0) throw new Error('empty oid');
  const first = bytes[0];
  const parts = [Math.floor(first / 40), first % 40];
  let acc = 0;
  for (let i = 1; i < bytes.length; i++) {
    acc = (acc << 7) | (bytes[i] & 0x7f);
    if ((bytes[i] & 0x80) === 0) {
      parts.push(acc);
      acc = 0;
    }
  }
  return parts.join('.');
}

function decodeDirString(tag, value) {
  if (tag === 0x1e) return new TextDecoder('utf-16be').decode(value);
  return new TextDecoder('utf-8').decode(value);
}

function parseName(buf, seq) {
  const out = { CN: '', O: '', OU: '' };
  let i = seq.start;
  while (i < seq.end) {
    const rdn = take(buf, i, 0x31);
    i = rdn.i;
    let j = rdn.start;
    while (j < rdn.end) {
      const atv = take(buf, j, 0x30);
      j = atv.i;
      const oid = take(buf, atv.start, 0x06);
      if (oid.i >= atv.end) throw new Error('missing value');
      const vTag = buf[oid.i];
      const val = take(buf, oid.i, vTag);
      const id = decodeOid(buf.subarray(oid.start, oid.end));
      const str = decodeDirString(vTag, buf.subarray(val.start, val.end));
      if (id === '2.5.4.3') out.CN = str;
      if (id === '2.5.4.10') out.O = str;
      if (id === '2.5.4.11') out.OU = str;
    }
  }
  return out;
}

export function parseX509Names(der) {
  const buf = der instanceof Uint8Array ? der : new Uint8Array(der);
  const cert = take(buf, 0, 0x30);
  const tbs = take(buf, cert.start, 0x30);
  let i = tbs.start;
  if (buf[i] === 0xa0) i = take(buf, i, 0xa0).i;
  i = take(buf, i, 0x02).i;
  i = take(buf, i, 0x30).i;
  const issuer = take(buf, i, 0x30);
  i = issuer.i;
  i = take(buf, i, 0x30).i;
  const subject = take(buf, i, 0x30);
  return { issuer: parseName(buf, issuer), subject: parseName(buf, subject) };
}
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd /home/cavanaug/wip_other/projects/brave-extensions/zscaler-mitm
npm test
```

Expected: PASS, including all `parseX509Names` tests. If an openssl-generated CN/O string differs by a trailing space or PrintableString quirk, fix the test assertion to the actual parsed value **only after** logging `parseX509Names(...)` once — do not weaken `isZscalerIssuer`.

- [ ] **Step 6: Commit**

```bash
git add zscaler-mitm/cert.js zscaler-mitm/test/cert.test.js zscaler-mitm/test/fixtures
git commit -m "$(cat <<'EOF'
feat(zscaler-mitm): parse leaf cert issuer and subject CN/O/OU from DER

EOF
)"
```

---

### Task 4: Manifest + service worker

**Files:**
- Create: `manifest.json`
- Create: `background.js`

**Interfaces:**
- Consumes: `parseX509Names`, `isZscalerIssuer`, `iconKind` from `cert.js`
- Produces: per-tab `chrome.storage.session` key `tab:${tabId}` whose value is a `TabRecord`; per-tab `chrome.action.setIcon` using `icons/{default,yellow,red}-{16,32}.png`

Session key format is exactly `` `tab:${tabId}` `` (no space). Popup in Task 5 must use the same key.

- [ ] **Step 1: Write `manifest.json`**

```json
{
  "manifest_version": 3,
  "name": "Zscaler MITM",
  "version": "1.0.0",
  "description": "Toolbar warning when the current tab’s TLS cert is issued by Zscaler.",
  "icons": {
    "16": "icons/default-16.png",
    "48": "icons/default-48.png",
    "128": "icons/default-128.png"
  },
  "action": {
    "default_title": "Zscaler MITM",
    "default_popup": "popup.html",
    "default_icon": {
      "16": "icons/default-16.png",
      "32": "icons/default-32.png"
    }
  },
  "background": {
    "service_worker": "background.js",
    "type": "module"
  },
  "permissions": ["webRequest", "storage", "tabs"],
  "host_permissions": ["https://*/*"]
}
```

- [ ] **Step 2: Write `background.js`**

```js
import { iconKind, isZscalerIssuer, parseX509Names } from './cert.js';

const ICONS = {
  default: { 16: 'icons/default-16.png', 32: 'icons/default-32.png' },
  yellow: { 16: 'icons/yellow-16.png', 32: 'icons/yellow-32.png' },
  red: { 16: 'icons/red-16.png', 32: 'icons/red-32.png' },
};

function tabKey(tabId) {
  return 'tab:' + tabId;
}

async function save(tabId, record) {
  await chrome.storage.session.set({ [tabKey(tabId)]: record });
}

async function load(tabId) {
  const key = tabKey(tabId);
  const got = await chrome.storage.session.get(key);
  return got[key] ?? null;
}

async function applyIcon(tabId) {
  const record = await load(tabId);
  try {
    await chrome.action.setIcon({ tabId, path: ICONS[iconKind(record)] });
  } catch {
    // tab closed
  }
}

function classifyUrl(url) {
  if (!url) return 'reload';
  try {
    const u = new URL(url);
    if (u.protocol === 'https:') return 'https';
    return 'not-https';
  } catch {
    return 'not-https';
  }
}

function blank(url, error) {
  return { url: url || '', subject: null, issuer: null, zscaler: false, error };
}

async function ensureRecord(tabId, url) {
  const existing = await load(tabId);
  if (existing) return existing;
  const kind = classifyUrl(url);
  const record = kind === 'not-https' ? blank(url, 'not-https') : blank(url, 'reload');
  await save(tabId, record);
  return record;
}

try {
  chrome.webRequest.onHeadersReceived.addListener(
    (details) => {
      if (details.tabId < 0) return;
      const run = async () => {
        try {
          const si = details.securityInfo;
          if (!si) {
            await save(details.tabId, blank(details.url, 'no-security-info'));
            await applyIcon(details.tabId);
            return;
          }
          const leaf = si.certificates && si.certificates[0];
          if (!leaf || !leaf.rawDER) {
            await save(details.tabId, blank(details.url, 'parse'));
            await applyIcon(details.tabId);
            return;
          }
          const names = parseX509Names(leaf.rawDER);
          const zscaler = isZscalerIssuer(names.issuer);
          await save(details.tabId, {
            url: details.url,
            subject: names.subject,
            issuer: names.issuer,
            zscaler,
            error: null,
          });
          await applyIcon(details.tabId);
        } catch {
          await save(details.tabId, blank(details.url, 'parse'));
          await applyIcon(details.tabId);
        }
      };
      run();
    },
    { urls: ['https://*/*'], types: ['main_frame'] },
    ['securityInfoRawDer'],
  );
} catch {
  // extraInfoSpec unsupported — HTTPS tabs stay yellow via ensureRecord
}

chrome.tabs.onUpdated.addListener(async (tabId, info, tab) => {
  if (tabId < 0) return;
  if (!info.url && info.status !== 'complete') return;
  const url = tab.url || info.url;
  if (classifyUrl(url) === 'not-https') {
    await save(tabId, blank(url, 'not-https'));
    await applyIcon(tabId);
    return;
  }
  await ensureRecord(tabId, url);
  await applyIcon(tabId);
});

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  if (tabId < 0) return;
  let url = '';
  try {
    const tab = await chrome.tabs.get(tabId);
    url = tab.url || '';
  } catch {
    return;
  }
  await ensureRecord(tabId, url);
  await applyIcon(tabId);
});

chrome.tabs.onRemoved.addListener(async (tabId) => {
  await chrome.storage.session.remove(tabKey(tabId));
});
```

Do not use a blocking webRequest listener. The async `run()` must be fire-and-forget.

- [ ] **Step 3: Syntax-check**

```bash
cd /home/cavanaug/wip_other/projects/brave-extensions/zscaler-mitm
node --check background.js
node --check cert.js
python3 -c "import json; json.load(open('manifest.json'))"
npm test
```

Expected: no output from `--check`; JSON loads; tests still PASS.

- [ ] **Step 4: Commit**

```bash
git add zscaler-mitm/manifest.json zscaler-mitm/background.js
git commit -m "$(cat <<'EOF'
feat(zscaler-mitm): set toolbar icon from the active tab’s leaf cert

EOF
)"
```

---

### Task 5: Popup

**Files:**
- Create: `popup.html`
- Create: `popup.js`

**Interfaces:**
- Consumes: `iconKind`, `statusLine` from `cert.js`; session key `'tab:' + tabId` and `TabRecord` from Task 4
- Produces: popup UI listing subject and issuer CN/O/OU plus the status line

Build the field list with `createElement` / `textContent` only. Do not assign HTML strings into the document.

- [ ] **Step 1: Write `popup.html`**

```html
<!DOCTYPE html>
<meta charset="utf-8">
<title>Zscaler MITM</title>
<style>
  body { font: 13px/1.4 system-ui, sans-serif; margin: 12px; min-width: 280px; color: #111; }
  h1 { font-size: 14px; margin: 0 0 8px; }
  #status { font-weight: 600; margin-bottom: 10px; }
  #status.red { color: #c62828; }
  #status.yellow { color: #b8860b; }
  h2 { font-size: 12px; margin: 10px 0 4px; }
  dl { display: grid; grid-template-columns: 2.5em 1fr; gap: 2px 10px; margin: 0; }
  dt { color: #666; }
  dd { margin: 0; word-break: break-all; }
</style>
<h1>Certificate</h1>
<div id="status"></div>
<div id="fields"></div>
<script type="module" src="popup.js"></script>
```

- [ ] **Step 2: Write `popup.js`**

```js
import { iconKind, statusLine } from './cert.js';

function nameBlock(title, name) {
  const wrap = document.createElement('div');
  const h = document.createElement('h2');
  h.textContent = title;
  wrap.append(h);
  if (!name) {
    const p = document.createElement('p');
    p.textContent = 'None.';
    wrap.append(p);
    return wrap;
  }
  const dl = document.createElement('dl');
  for (const key of ['CN', 'O', 'OU']) {
    const dt = document.createElement('dt');
    dt.textContent = key;
    const dd = document.createElement('dd');
    dd.textContent = name[key] || '—';
    dl.append(dt, dd);
  }
  wrap.append(dl);
  return wrap;
}

const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
const key = 'tab:' + tab.id;
const got = await chrome.storage.session.get(key);
const record = got[key] ?? null;

const status = document.getElementById('status');
status.textContent = statusLine(record);
status.className = iconKind(record);

const fields = document.getElementById('fields');
fields.replaceChildren();
if (record && record.error === null) {
  fields.append(nameBlock('Subject', record.subject), nameBlock('Issuer', record.issuer));
}
```

- [ ] **Step 3: Syntax-check**

```bash
cd /home/cavanaug/wip_other/projects/brave-extensions/zscaler-mitm
node --check popup.js
npm test
```

Expected: no `--check` output; tests PASS.

- [ ] **Step 4: Commit**

```bash
git add zscaler-mitm/popup.html zscaler-mitm/popup.js
git commit -m "$(cat <<'EOF'
feat(zscaler-mitm): show subject and issuer CN/O/OU in the toolbar popup

EOF
)"
```

---

### Task 6: README

**Files:**
- Create: `README.md`

**Interfaces:**
- Consumes: load-unpacked flow from `xml-tree/README.md` (Brave `brave://extensions`)
- Produces: install + manual checklist matching the spec success criteria

- [ ] **Step 1: Write `README.md`**

~~~~markdown
# Zscaler MITM

Toolbar icon that turns **red** when the active tab’s TLS certificate is issued by Zscaler, **yellow** when the extension cannot tell, and stays the default spy icon otherwise. Click the icon to see subject and issuer CN / O / OU.

Requires Chrome or Brave with Chromium **144+** (`webRequest` `securityInfoRawDer`).

## Load unpacked in Brave

1. Open `brave://extensions` (or `chrome://extensions`)
2. Enable **Developer mode**
3. Click **Load unpacked** and select this folder (`zscaler-mitm`)
4. Pin **Zscaler MITM** to the toolbar

## Test

    npm test

No extra packages. Parser + match tests only; they do not launch a browser.

## Manual Brave smoke checklist

- [ ] Pin the icon. Open `https://example.com` — default spy icon; popup shows a non-Zscaler issuer
- [ ] On a Zscaler-intercepted HTTPS tab — red spy icon; popup issuer O/OU/CN matches Zscaler
- [ ] Open `chrome://extensions` or an `http://` page — default spy icon; popup says “Not HTTPS — no certificate”
- [ ] Load the extension, then click an already-open HTTPS tab without reloading — yellow; popup says “Reload the tab to inspect the certificate”; reload — icon updates
- [ ] Brave shows no Manifest V2 / “no longer supported” warning

## Out of scope (v1)

- ZeroOmega / proxy switching
- Coloring the tab itself
- Chrome Web Store
~~~~

- [ ] **Step 2: Run unit tests once more**

```bash
cd /home/cavanaug/wip_other/projects/brave-extensions/zscaler-mitm
npm test
```

Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add zscaler-mitm/README.md
git commit -m "$(cat <<'EOF'
docs(zscaler-mitm): add load-unpacked README and Brave smoke checklist

EOF
)"
```

---
