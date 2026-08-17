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

export function shouldKeepRecord(existing, url) {
  if (!existing) return false;
  if (existing.url === url) return true;
  // ponytail: keep parse/no-si/success across same-origin slash/redirect; only 'reload' is a placeholder
  if (existing.error === 'reload') return false;
  try {
    const a = new URL(existing.url);
    const b = new URL(url);
    return a.protocol === 'https:' && b.protocol === 'https:' && a.origin === b.origin;
  } catch {
    return false;
  }
}

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

export function derBytes(der) {
  if (der instanceof ArrayBuffer) return new Uint8Array(der);
  if (ArrayBuffer.isView(der)) {
    return new Uint8Array(der.buffer, der.byteOffset, der.byteLength);
  }
  if (typeof der === 'string') {
    const b64 = der.replace(/-----[^-]+-----/g, '').replace(/\s/g, '');
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  if (Array.isArray(der)) return Uint8Array.from(der, (n) => Number(n));
  if (der && typeof der === 'object') {
    const len = Number(der.byteLength ?? der.length);
    if (len > 0 && der[0] !== undefined) {
      const out = new Uint8Array(len);
      for (let i = 0; i < len; i++) out[i] = der[i];
      return out;
    }
    const keys = Object.keys(der)
      .filter((k) => /^\d+$/.test(k))
      .map(Number)
      .sort((a, b) => a - b);
    if (keys.length) {
      const out = new Uint8Array(keys[keys.length - 1] + 1);
      for (const k of keys) out[k] = der[k];
      return out;
    }
  }
  throw new Error('unsupported der type');
}

export function parseX509Names(der) {
  const buf = derBytes(der);
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
