# Public CA Classify Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Generalize the Zscaler MITM toolbar so public CAs show dark green, constrained private CAs show blue, and unconstrained/off-scope intercepting CAs show red, using a repo-backed public list plus cert/user Name Constraints.

**Architecture:** Keep the MV3 `webRequest` + leaf DER flow. Replace `isZscalerIssuer` with `classify()` in `cert.js`. Pack `public-cas.json` (generated offline from CCADB) and refresh it from GitHub raw. User overlays live in `chrome.storage.sync`. Parse RFC 5280 Name Constraints from the issuer cert when Chromium includes the chain.

**Tech Stack:** Vanilla JS MV3 (ES modules), Chromium 144+ `securityInfoRawDer`, Node `node:test`, no new npm packages. OpenSSL only in the optional list-update script path if used; SPKI hashing for the packed list uses Node `crypto` in `scripts/update-public-cas.mjs`.

**Spec:** `docs/superpowers/specs/2026-08-16-public-ca-classify-design.md`

**Working directory:** `/home/cavanaug/wip_other/projects/zscaler-mitm`

## Global Constraints

- Manifest V3; Chromium 144+ `securityInfoRawDer`; no new npm dependencies; `node --test` only (no Playwright).
- Never throw out of the service worker.
- Do not fetch CCADB or Chrome Root Store at runtime; runtime fetch is GitHub raw of `public-cas.json` only.
- Do not use the live OS/browser trust store.
- Public issuers skip Name Constraint logic.
- Combined permitted DNS empty on a non-public issuer → `intercept` (red), never fail open to public/green.
- `rootSpkis` are lowercase hex SHA-256 of the SubjectPublicKeyInfo DER (not the cert fingerprint).
- GitHub raw URL: `https://raw.githubusercontent.com/cavanaug/zscaler-mitm/master/public-cas.json`
- Icon palette: grey `default` (no TLS), `yellow` (cannot tell), `green` (public), `blue` (in-scope private), `red` (unconstrained/off-scope).
- Popup “Allow this issuer for `<host>`” uses the tab hostname as-is (no eTLD truncation).
- `isZscalerIssuer` is removed from product logic.

---

## File map

| Path | Responsibility |
|------|----------------|
| `cert.js` | DER names, NC parse, SPKI bytes, public-list parse/pick, overlay helpers, `classify`, `iconKind`, `statusLine` |
| `public-cas.json` | Committed public baseline |
| `scripts/update-public-cas.mjs` | Rebuild `public-cas.json` from CCADB (offline, human-run) |
| `background.js` | webRequest, classify with list+overlays+chain, GitHub refresh, icons |
| `popup.html` / `popup.js` | Verdict + allow-issuer |
| `options.html` / `options.js` | Overlay CRUD + list freshness |
| `manifest.json` | options page, GitHub host permission, copy |
| `icons/green-*.png` `icons/blue-*.png` | New tints |
| `test/cert.test.js` | Parser + classify table |
| `Makefile` | Package new files |
| `README.md` `store/listing.md` `store/privacy.md` | Copy |

---

### Task 1: Classify, public-list pick, overlay host match

**Files:**
- Modify: `cert.js`
- Modify: `test/cert.test.js`

**Interfaces:**
- Consumes: existing `parseX509Names`, `shouldKeepRecord`, DER walker in `cert.js`
- Produces:
  - `EMPTY_PUBLIC_CAS` `{ version: 1, generatedAt: '', source: '', organizations: [], issuerCNs: [], rootSpkis: [] }`
  - `parsePublicCas(input) → object|null`
  - `pickPublicCas(fetched, cached, packed) → object` (never null; empty on total failure)
  - `hostnameFromUrl(url) → string` (lowercase, no trailing dot; `''` on failure)
  - `hostMatchesDns(host, dnsEntry) → boolean`
  - `isPublicIssuer(issuer, publicCas, chainSpkis) → boolean`
  - `overlayForIssuer(issuer, overlays) → overlay|null`
  - `mergeOverlay(overlays, issuer, host) → Overlay[]`
  - `hostInConstraints(hostname, certNc, overlay) → boolean`
  - `classify({ issuer, hostname, publicCas, overlays, chainSpkis, certNc }) → 'public'|'in-scope'|'intercept'`
  - `iconKind(record)` / `statusLine(record)` use `record.verdict` not `record.zscaler`
  - Overlay shape: `{ O: string, CN: string|null, dns: string[] }`
  - `certNc` shape: `{ permitted: string[], excluded: string[] }` or `null`

- [ ] **Step 1: Rewrite tests that used `isZscalerIssuer` / `zscaler`**

In `test/cert.test.js` remove imports of `isZscalerIssuer`. Import `classify`, `iconKind`, `statusLine`, `parsePublicCas`, `pickPublicCas`, `EMPTY_PUBLIC_CAS`, `hostMatchesDns`, `mergeOverlay`, `parseX509Names`, `shouldKeepRecord`.

Replace the `isZscalerIssuer:*` tests and the `iconKind + statusLine` table with:

```js
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
```

Keep `shouldKeepRecord` tests but change `zscaler: false` to `verdict: 'public'` (or `null` on error records). Keep DER parse tests; drop `isZscalerIssuer` asserts. After `parseX509Names` of the DigiCert fixture, add:

```js
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
```

After Zscaler O fixture parse, classify with `EMPTY_PUBLIC_CAS` expects `'intercept'`.

- [ ] **Step 2: Run tests — expect FAIL**

```bash
cd /home/cavanaug/wip_other/projects/zscaler-mitm && npm test
```

Expected: FAIL (`classify` / `parsePublicCas` not exported, or `isZscalerIssuer` still imported).

- [ ] **Step 3: Implement in `cert.js`**

Delete `isZscalerIssuer`. Replace `iconKind` / `statusLine`. Add:

```js
export const EMPTY_PUBLIC_CAS = {
  version: 1,
  generatedAt: '',
  source: '',
  organizations: [],
  issuerCNs: [],
  rootSpkis: [],
};

function asStringArray(v) {
  if (!Array.isArray(v)) return null;
  const out = [];
  for (const x of v) {
    if (typeof x !== 'string') return null;
    out.push(x);
  }
  return out;
}

export function parsePublicCas(input) {
  let obj = input;
  if (typeof input === 'string') {
    try {
      obj = JSON.parse(input);
    } catch {
      return null;
    }
  }
  if (!obj || typeof obj !== 'object') return null;
  const organizations = asStringArray(obj.organizations);
  const issuerCNs = asStringArray(obj.issuerCNs);
  const rootSpkis = asStringArray(obj.rootSpkis);
  if (!organizations || !issuerCNs || !rootSpkis) return null;
  return {
    version: Number(obj.version) || 1,
    generatedAt: typeof obj.generatedAt === 'string' ? obj.generatedAt : '',
    source: typeof obj.source === 'string' ? obj.source : '',
    organizations,
    issuerCNs,
    rootSpkis: rootSpkis.map((h) => h.toLowerCase()),
  };
}

export function pickPublicCas(fetched, cached, packed) {
  for (const x of [fetched, cached, packed]) {
    const p = parsePublicCas(x);
    if (p) return p;
  }
  return EMPTY_PUBLIC_CAS;
}

export function hostnameFromUrl(url) {
  try {
    return new URL(url).hostname.replace(/\.$/, '').toLowerCase();
  } catch {
    return '';
  }
}

export function hostMatchesDns(host, dnsEntry) {
  if (!host || !dnsEntry) return false;
  const h = String(host).replace(/\.$/, '').toLowerCase();
  const p = String(dnsEntry).replace(/^\.+/, '').replace(/\.$/, '').toLowerCase();
  if (!p) return false;
  return h === p || h.endsWith('.' + p);
}

export function isPublicIssuer(issuer, publicCas, chainSpkis) {
  if (!issuer || !publicCas) return false;
  if (issuer.O && publicCas.organizations.includes(issuer.O)) return true;
  if (issuer.CN && publicCas.issuerCNs.includes(issuer.CN)) return true;
  const roots = new Set(publicCas.rootSpkis);
  for (const s of chainSpkis || []) {
    if (roots.has(String(s).toLowerCase())) return true;
  }
  return false;
}

export function overlayForIssuer(issuer, overlays) {
  if (!issuer || !Array.isArray(overlays)) return null;
  for (const o of overlays) {
    if (!o || o.O !== issuer.O) continue;
    if (o.CN != null && o.CN !== issuer.CN) continue;
    return o;
  }
  return null;
}

export function mergeOverlay(overlays, issuer, host) {
  const list = Array.isArray(overlays) ? overlays.map((o) => ({ ...o, dns: [...(o.dns || [])] })) : [];
  let hit = overlayForIssuer(issuer, list);
  if (!hit) {
    hit = { O: issuer.O, CN: null, dns: [] };
    list.push(hit);
  }
  if (host && !hit.dns.some((d) => hostMatchesDns(host, d) && d.replace(/^\.+/, '') === host)) {
    if (!hit.dns.includes(host)) hit.dns.push(host);
  }
  return list;
}

export function hostInConstraints(hostname, certNc, overlay) {
  const permitted = [...(certNc && certNc.permitted ? certNc.permitted : []), ...(overlay && overlay.dns ? overlay.dns : [])];
  const excluded = certNc && certNc.excluded ? certNc.excluded : [];
  if (!permitted.length) return false;
  if (excluded.some((d) => hostMatchesDns(hostname, d))) return false;
  return permitted.some((d) => hostMatchesDns(hostname, d));
}

export function classify({ issuer, hostname, publicCas, overlays, chainSpkis, certNc }) {
  if (isPublicIssuer(issuer, publicCas, chainSpkis)) return 'public';
  const overlay = overlayForIssuer(issuer, overlays);
  if (hostInConstraints(hostname, certNc, overlay)) return 'in-scope';
  return 'intercept';
}

export function iconKind(record) {
  if (!record) return 'yellow';
  if (record.error === 'not-https') return 'default';
  if (record.error) return 'yellow';
  if (record.verdict === 'public') return 'green';
  if (record.verdict === 'in-scope') return 'blue';
  if (record.verdict === 'intercept') return 'red';
  return 'yellow';
}

export function statusLine(record) {
  if (!record || record.error === 'reload') return 'Reload the tab to inspect the certificate';
  if (record.error === 'not-https') return 'Not HTTPS — no certificate';
  if (record.error === 'no-security-info') return 'Needs Chromium 144+';
  if (record.error === 'parse') return 'Couldn’t parse certificate';
  if (record.verdict === 'public') return 'Public CA';
  if (record.verdict === 'in-scope') return 'Private CA, in-scope';
  if (record.verdict === 'intercept') return 'Unconstrained or off-scope intercepting CA';
  return 'Reload the tab to inspect the certificate';
}
```

- [ ] **Step 4: Run tests — expect PASS**

```bash
cd /home/cavanaug/wip_other/projects/zscaler-mitm && npm test
```

Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add cert.js test/cert.test.js
git commit -m "$(cat <<'EOF'
Replace Zscaler-only match with public-CA classify rules.

EOF
)"
```

---

### Task 2: Parse Name Constraints and SPKI from cert DER

**Files:**
- Modify: `cert.js`
- Modify: `test/cert.test.js`
- Create: `test/fixtures/issuer-nc-hp.der` (generated in the step)

**Interfaces:**
- Consumes: existing `take` / `readLen` / `derBytes` in `cert.js`
- Produces:
  - `parseNameConstraints(der) → { permitted: string[], excluded: string[] } | null`
  - `parseSpkiDer(der) → Uint8Array` (SubjectPublicKeyInfo bytes)

- [ ] **Step 1: Failing tests + fixture**

Generate a CA cert with Name Constraints permitted DNS `.hp.com`:

```bash
cd /home/cavanaug/wip_other/projects/zscaler-mitm
TMP=$(mktemp -d)
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$TMP/k.pem" -out "$TMP/c.pem" \
  -subj '/CN=HP Test CA/O=HP Inc' -days 1 \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'nameConstraints=permitted;DNS:.hp.com'
openssl x509 -in "$TMP/c.pem" -outform DER -out test/fixtures/issuer-nc-hp.der
rm -rf "$TMP"
```

Add to `test/cert.test.js`:

```js
import { parseNameConstraints, parseSpkiDer } from '../cert.js';
import { createHash } from 'node:crypto';

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
```

- [ ] **Step 2: Run tests — expect FAIL**

```bash
npm test
```

Expected: FAIL (`parseNameConstraints` not exported).

- [ ] **Step 3: Implement parsers in `cert.js`**

Add after the existing walker (`decodeOid`, `take`, `parseName`). Walk TBS: skip version/serial/sig/issuer/validity/subject, next SEQUENCE is SPKI (return that slice as `parseSpkiDer`). Then skip issuerUniqueID `[1]` / subjectUniqueID `[2]` if present; if `[3]` extensions, find OID `2.5.29.30`, parse NameConstraints:

- `permittedSubtrees` context `[0]`, `excludedSubtrees` `[1]`
- each `GeneralSubtree` SEQUENCE, `dNSName` is context-specific tag `0x82` (IA5String)

Return `null` if the extension is absent. Empty arrays if present but no DNS names.

Export:

```js
export function parseSpkiDer(der) { /* ... */ }
export function parseNameConstraints(der) { /* ... */ }
```

Keep `parseX509Names` working; do not break existing fixtures.

- [ ] **Step 4: Run tests — expect PASS**

```bash
npm test
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add cert.js test/cert.test.js test/fixtures/issuer-nc-hp.der
git commit -m "$(cat <<'EOF'
Parse certificate Name Constraints and SPKI from DER.

EOF
)"
```

---

### Task 3: Generate and pack `public-cas.json`

**Files:**
- Create: `scripts/update-public-cas.mjs`
- Create: `public-cas.json`
- Modify: `package.json` (script `"update-public-cas": "node scripts/update-public-cas.mjs"`)

**Interfaces:**
- Consumes: CCADB CSVs (human/CI network, not the extension)
- Produces: `public-cas.json` with `version`, `generatedAt` (ISO), `source: "ccadb-intermediates+roots"`, `organizations`, `issuerCNs`, `rootSpkis` (lowercase hex SHA-256 of root SPKI)

- [ ] **Step 1: Write `scripts/update-public-cas.mjs`**

The script must:

1. Fetch `https://ccadb.my.salesforce-sites.com/mozilla/IncludedCACertificateReportPEMCSV`
2. Fetch `https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatV4a`
3. Parse CSV (quoted fields, including multiline PEM).
4. From Mozilla PEM rows where `Trust Bits` includes `Websites`: add `Owner`, `Certificate Issuer Organization` to `organizations`; add `Common Name or Certificate Name` to `issuerCNs`; parse `PEM Info` into DER; SHA-256 the SPKI (reuse the same TBS walk as `parseSpkiDer` — duplicate a tiny copy in the script so it can run without Chrome; or `import { parseSpkiDer } from '../cert.js'` and `createHash('sha256')`).
5. From V4a rows: skip `Revocation Status === 'Revoked'`. Include if `Chrome Status === 'Included'` OR `Mozilla Status === 'Included'` OR `Status of Root Cert` contains `Google Chrome: Included` or `Mozilla: Included`. Add `CA Owner` to organizations; add `Certificate Name` to `issuerCNs`.
6. Sort unique strings. Write `public-cas.json` (pretty-printed, trailing newline).

Include a small CSV parser in the file (no npm). Abort with a non-zero exit if either fetch fails or `organizations.length < 50`.

- [ ] **Step 2: Run the generator**

```bash
cd /home/cavanaug/wip_other/projects/zscaler-mitm && node scripts/update-public-cas.mjs
```

Expected: writes `public-cas.json`; file contains `DigiCert Inc` and `Google Trust Services` (or `Google Trust Services LLC`) in `organizations`.

- [ ] **Step 3: Sanity-check against classify**

```bash
node --input-type=module -e "
import { readFileSync } from 'node:fs';
import { classify, parsePublicCas } from './cert.js';
const publicCas = parsePublicCas(readFileSync('public-cas.json','utf8'));
console.log(classify({ issuer:{CN:'WE2',O:'Google Trust Services',OU:''}, hostname:'mail.google.com', publicCas, overlays:[], chainSpkis:[], certNc:null }));
console.log(classify({ issuer:{CN:'x',O:'Zscaler Inc.',OU:''}, hostname:'mail.google.com', publicCas, overlays:[], chainSpkis:[], certNc:null }));
"
```

Expected: first line `public` (if GTS `O` in file; if the file has `Google Trust Services LLC` only, use that string). Second line `intercept`.

- [ ] **Step 4: Commit**

```bash
git add scripts/update-public-cas.mjs public-cas.json package.json
git commit -m "$(cat <<'EOF'
Add CCADB-derived public-cas.json and the update script.

EOF
)"
```

---

### Task 4: Green and blue toolbar icons

**Files:**
- Create: `icons/green-{16,32,48,128}.png`
- Create: `icons/blue-{16,32,48,128}.png`
- Modify: `Makefile` (optional `icons` target)

**Interfaces:**
- Consumes: `icons/source-spy.png`
- Produces: PNG paths `background.js` will pass to `setIcon`

- [ ] **Step 1: Generate tints from the source silhouette**

Dark green `#1b5e20`, blue `#1565c0`. Use ImageMagick so the alpha mask of `source-spy.png` is preserved:

```bash
cd /home/cavanaug/wip_other/projects/zscaler-mitm
for color in green:'#1b5e20' blue:'#1565c0'; do
  name=${color%%:*}
  fill=${color#*:}
  for size in 16 32 48 128; do
    convert icons/source-spy.png -resize ${size}x${size} \
      -alpha extract -background "$fill" -alpha shape \
      icons/${name}-${size}.png
  done
done
ls icons/green-16.png icons/blue-32.png
```

Expected: files exist. If `convert` is missing, use `python3` + Pillow only if already installed; otherwise install `imagemagick` via the distro package (do not add an npm dep).

- [ ] **Step 2: Commit**

```bash
git add icons/green-*.png icons/blue-*.png Makefile
git commit -m "$(cat <<'EOF'
Add green and blue spy icon tints for public vs scoped private CAs.

EOF
)"
```

---

### Task 5: Wire background.js (list, overlays, chain, icons)

**Files:**
- Modify: `background.js`

**Interfaces:**
- Consumes: `classify`, `hostnameFromUrl`, `iconKind`, `parseX509Names`, `parseNameConstraints`, `parseSpkiDer`, `parsePublicCas`, `pickPublicCas`, `shouldKeepRecord` from `cert.js`; packed `./public-cas.json`
- Produces: session records `{ url, subject, issuer, verdict, certNc, error, detail? }` (no `zscaler`); GitHub refresh into `chrome.storage.local` keys `publicCas` and `publicCasFetchedAt`; overlays from `chrome.storage.sync` key `overlays` with `local` fallback

- [ ] **Step 1: Add a packed JSON import and icon map**

At top of `background.js`:

```js
import publicCasPacked from './public-cas.json' with { type: 'json' };
import {
  classify,
  hostnameFromUrl,
  iconKind,
  parseNameConstraints,
  parseSpkiDer,
  parsePublicCas,
  pickPublicCas,
  parseX509Names,
  shouldKeepRecord,
} from './cert.js';

const PUBLIC_CAS_URL = 'https://raw.githubusercontent.com/cavanaug/zscaler-mitm/master/public-cas.json';
const DAY_MS = 24 * 60 * 60 * 1000;

const ICONS = {
  default: { 16: 'icons/default-16.png', 32: 'icons/default-32.png' },
  yellow: { 16: 'icons/yellow-16.png', 32: 'icons/yellow-32.png' },
  green: { 16: 'icons/green-16.png', 32: 'icons/green-32.png' },
  blue: { 16: 'icons/blue-16.png', 32: 'icons/blue-32.png' },
  red: { 16: 'icons/red-16.png', 32: 'icons/red-32.png' },
};
```

If Chromium rejects `with { type: 'json' }`, switch to `fetch(chrome.runtime.getURL('public-cas.json'))` cached in a module-level promise. Add `public-cas.json` to `web_accessible_resources` only if that fetch is used; `getURL` works without it.

- [ ] **Step 2: List + overlay loaders and refresh**

```js
async function sha256Hex(bytes) {
  const hash = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function loadOverlays() {
  try {
    const got = await chrome.storage.sync.get('overlays');
    if (Array.isArray(got.overlays)) return got.overlays;
  } catch {
    // sync unavailable
  }
  const got = await chrome.storage.local.get('overlays');
  return Array.isArray(got.overlays) ? got.overlays : [];
}

export async function saveOverlays(overlays) {
  try {
    await chrome.storage.sync.set({ overlays });
  } catch {
    await chrome.storage.local.set({ overlays });
  }
}

async function currentPublicCas() {
  const got = await chrome.storage.local.get(['publicCas', 'publicCasFetchedAt']);
  return pickPublicCas(got.publicCas, null, publicCasPacked);
}

async function refreshPublicCas(force) {
  try {
    const got = await chrome.storage.local.get('publicCasFetchedAt');
    if (!force && typeof got.publicCasFetchedAt === 'number' && Date.now() - got.publicCasFetchedAt < DAY_MS) {
      return;
    }
    const res = await fetch(PUBLIC_CAS_URL, { cache: 'no-store' });
    if (!res.ok) return;
    const text = await res.text();
    const parsed = parsePublicCas(text);
    if (!parsed) return;
    await chrome.storage.local.set({ publicCas: parsed, publicCasFetchedAt: Date.now() });
  } catch {
    // keep last good / packed
  }
}

void refreshPublicCas(false);
```

- [ ] **Step 3: Replace `blank` and `recordFromDetails`**

`recordFromDetails` must be async. Walk `si.certificates` for SPKI hashes (skip failures). Parse NC from `certificates[1]` when present.

```js
function blank(url, error) {
  return { url: url || '', subject: null, issuer: null, verdict: null, certNc: null, error };
}

async function recordFromDetails(details) {
  const si = details.securityInfo;
  if (!si) return blank(details.url, 'no-security-info');
  const { der, why } = leafRawDer(si);
  if (!der) {
    const rec = blank(details.url, 'parse');
    rec.detail = why;
    return rec;
  }
  const names = parseX509Names(der);
  const certs = Array.isArray(si.certificates) ? si.certificates : [];
  const chainSpkis = [];
  for (const c of certs) {
    const raw = c && (c.rawDER ?? c.rawDer ?? c.raw_der);
    if (raw == null) continue;
    try {
      chainSpkis.push(await sha256Hex(parseSpkiDer(raw)));
    } catch {
      // skip
    }
  }
  let certNc = null;
  const issuerCert = certs[1];
  const issuerDer = issuerCert && (issuerCert.rawDER ?? issuerCert.rawDer ?? issuerCert.raw_der);
  if (issuerDer != null) {
    try {
      certNc = parseNameConstraints(issuerDer);
    } catch {
      certNc = null;
    }
  }
  const publicCas = await currentPublicCas();
  const overlays = await loadOverlays();
  const verdict = classify({
    issuer: names.issuer,
    hostname: hostnameFromUrl(details.url),
    publicCas,
    overlays,
    chainSpkis,
    certNc,
  });
  return {
    url: details.url,
    subject: names.subject,
    issuer: names.issuer,
    verdict,
    certNc,
    error: null,
  };
}
```

In `onHeadersReceived`, `await recordFromDetails(details)`. Keep the existing tabId / main_frame / shouldKeepRecord logic.

Add `reclassifyRecord(record)` that re-runs `classify` with stored `issuer`, `url`, `certNc` and current list/overlays (no DER). Use it after overlay changes (Task 6 will message the worker).

```js
async function reclassifyRecord(record) {
  if (!record || record.error !== null || !record.issuer) return record;
  const verdict = classify({
    issuer: record.issuer,
    hostname: hostnameFromUrl(record.url),
    publicCas: await currentPublicCas(),
    overlays: await loadOverlays(),
    chainSpkis: [],
    certNc: record.certNc,
  });
  return { ...record, verdict };
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  const run = async () => {
    if (msg && msg.type === 'overlays-changed') {
      const tabs = await chrome.tabs.query({});
      for (const tab of tabs) {
        if (tab.id < 0) continue;
        const rec = await load(tab.id);
        if (!rec) continue;
        await save(tab.id, await reclassifyRecord(rec));
        await applyIcon(tab.id);
      }
    }
    sendResponse({ ok: true });
  };
  void run();
  return true;
});
```

- [ ] **Step 4: `npm test` still passes** (background is not unit-tested)

```bash
npm test
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add background.js
git commit -m "$(cat <<'EOF'
Classify tabs with the public list, overlays, and chain Name Constraints.

EOF
)"
```

---

### Task 6: Popup allow-issuer + green/blue status colors

**Files:**
- Modify: `popup.html`
- Modify: `popup.js`

**Interfaces:**
- Consumes: `iconKind`, `statusLine`, `hostnameFromUrl`, `mergeOverlay` from `cert.js`; session record `verdict`; `chrome.runtime.sendMessage({ type: 'overlays-changed' })`
- Produces: “Allow this issuer for `<host>`” button when `error === null` and `verdict !== 'public'`

- [ ] **Step 1: Update `popup.html` CSS and add a button**

Add `#status.green { color: #1b5e20; }`, `#status.blue { color: #1565c0; }`, keep red/yellow. Add `<button id="allow" type="button" hidden></button>` under `#fields`.

- [ ] **Step 2: Update `popup.js`**

After rendering fields, if `record.error === null && record.verdict !== 'public' && record.issuer`:

```js
import { hostnameFromUrl, iconKind, mergeOverlay, statusLine } from './cert.js';

const allow = document.getElementById('allow');
const host = hostnameFromUrl(record.url);
allow.hidden = false;
allow.textContent = 'Allow this issuer for ' + host;
allow.addEventListener('click', async () => {
  let overlays = [];
  try {
    overlays = (await chrome.storage.sync.get('overlays')).overlays || [];
  } catch {
    overlays = (await chrome.storage.local.get('overlays')).overlays || [];
  }
  const next = mergeOverlay(overlays, record.issuer, host);
  try {
    await chrome.storage.sync.set({ overlays: next });
  } catch {
    await chrome.storage.local.set({ overlays: next });
  }
  await chrome.runtime.sendMessage({ type: 'overlays-changed' });
  location.reload();
});
```

- [ ] **Step 3: Commit**

```bash
git add popup.html popup.js
git commit -m "$(cat <<'EOF'
Let the popup allow the current issuer for this hostname.

EOF
)"
```

---

### Task 7: Options page and manifest

**Files:**
- Create: `options.html`
- Create: `options.js`
- Modify: `manifest.json`
- Modify: `Makefile`

**Interfaces:**
- Consumes: `overlays` storage, `publicCas` / `publicCasFetchedAt` / packed list via the same keys as background
- Produces: CRUD for `{ O, CN, dns[] }`; shows `generatedAt` and last refresh time

- [ ] **Step 1: `options.html` + `options.js`**

Single-page list: each overlay shows O, optional CN, comma-separated DNS, Delete. Form: O, CN (optional), DNS (comma-separated), Add. Footer: `Public list generatedAt: …` and `Last GitHub refresh: …` (or `packed snapshot` if `publicCasFetchedAt` missing). On save, `chrome.runtime.sendMessage({ type: 'overlays-changed' })`.

Keep the page boring: system font, no framework.

- [ ] **Step 2: Manifest**

```json
{
  "manifest_version": 3,
  "name": "Zscaler MITM",
  "version": "1.1.0",
  "description": "Toolbar signal when the tab’s TLS issuer is a public CA, a constrained private CA, or an unconstrained intercepting CA.",
  "icons": {
    "16": "icons/default-16.png",
    "48": "icons/default-48.png",
    "128": "icons/default-128.png"
  },
  "action": {
    "default_title": "TLS issuer",
    "default_popup": "popup.html",
    "default_icon": {
      "16": "icons/default-16.png",
      "32": "icons/default-32.png"
    }
  },
  "options_page": "options.html",
  "background": {
    "service_worker": "background.js",
    "type": "module"
  },
  "permissions": ["webRequest", "storage", "tabs"],
  "host_permissions": [
    "https://*/*",
    "https://raw.githubusercontent.com/cavanaug/zscaler-mitm/*"
  ]
}
```

If JSON import needs the file in the package, `Makefile` already copies listed files — add `public-cas.json options.html options.js`.

```make
$(ZIP): manifest.json background.js cert.js popup.html popup.js options.html options.js public-cas.json $(wildcard icons/*.png)
	rm -rf $(STAGE) $(ZIP)
	mkdir -p $(STAGE)
	cp manifest.json background.js cert.js popup.html popup.js options.html options.js public-cas.json $(STAGE)/
	cp -r icons $(STAGE)/icons
	cd $(DIST) && zip -r $(NAME).zip $(NAME)
```

- [ ] **Step 3: Commit**

```bash
git add options.html options.js manifest.json Makefile
git commit -m "$(cat <<'EOF'
Add options page for issuer DNS overlays and pack the public list.

EOF
)"
```

---

### Task 8: README and store/privacy copy

**Files:**
- Modify: `README.md`
- Modify: `store/listing.md`
- Modify: `store/privacy.md`

**Interfaces:**
- Consumes: behavior from Tasks 1–7
- Produces: accurate load/test/privacy text (GitHub JSON fetch is data, not remote code)

- [ ] **Step 1: README manual checklist**

Replace Zscaler-only bullets with:

- [ ] Public HTTPS site (example.com) — dark green spy; popup “Public CA”
- [ ] Zscaler-intercepted HTTPS — red; “Unconstrained or off-scope intercepting CA”
- [ ] After Allow on an HP (or other private) host — blue on that host; red on Gmail with that issuer
- [ ] `chrome://` or `http://` — grey; “Not HTTPS — no certificate”
- [ ] Already-open HTTPS tab without reload — yellow; reload updates
- [ ] Options page shows overlays and public-list `generatedAt`

Keep Chromium 144+ / WebRequestSecurityInfo instructions.

- [ ] **Step 2: Privacy + listing**

State: overlays in `storage.sync` (fallback local); public list cache in `storage.local`; GET of GitHub raw `public-cas.json` (certificate-issuer metadata only, no browsing history). Remote code: still **No**. Host permission for `raw.githubusercontent.com` is for that JSON file.

- [ ] **Step 3: `npm test` + `make package`**

```bash
npm test && make package
```

Expected: tests pass; `dist/zscaler-mitm.zip` contains `public-cas.json`, `options.html`, green/blue icons.

- [ ] **Step 4: Commit**

```bash
git add README.md store/listing.md store/privacy.md
git commit -m "$(cat <<'EOF'
Document public-CA classify, overlays, and the GitHub list refresh.

EOF
)"
```

---

## Self-review

**Spec coverage:** classify table → Task 1; cert NC + SPKI → Task 2; CCADB file in git → Task 3; green/blue icons → Task 4; background classify/refresh/chain → Task 5; popup allow → Task 6; options + manifest host permission → Task 7; README/store → Task 8. Success criteria 1–8 map to Tasks 1, 3, 5, 8.

**Placeholders:** GitHub URL is concrete (`cavanaug/zscaler-mitm`). `rootSpkis` encoding is lowercase hex.

**Types:** `verdict` is `'public'|'in-scope'|'intercept'`; overlays `{ O, CN, dns }`; storage keys `overlays`, `publicCas`, `publicCasFetchedAt`; message `overlays-changed`.
