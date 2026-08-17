/** Minimal DER/ASN.1 reader for X.509: names, SPKI, name constraints. */

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

function skipTbsThroughSubject(buf, tbs) {
  let i = tbs.start;
  if (buf[i] === 0xa0) i = take(buf, i, 0xa0).i;
  i = take(buf, i, 0x02).i;
  i = take(buf, i, 0x30).i;
  i = take(buf, i, 0x30).i;
  i = take(buf, i, 0x30).i;
  i = take(buf, i, 0x30).i;
  return i;
}

function collectDnsNames(buf, subtreesWrapper, out) {
  const seq = take(buf, subtreesWrapper.start, 0x30);
  let i = seq.start;
  while (i < seq.end) {
    if (buf[i] === 0x82) {
      const dns = take(buf, i, 0x82);
      out.push(new TextDecoder('ascii').decode(buf.subarray(dns.start, dns.end)));
      i = dns.i;
    } else if (buf[i] === 0x30) {
      const subtree = take(buf, i, 0x30);
      i = subtree.i;
      if (subtree.start < subtree.end && buf[subtree.start] === 0x82) {
        const dns = take(buf, subtree.start, 0x82);
        out.push(new TextDecoder('ascii').decode(buf.subarray(dns.start, dns.end)));
      }
    } else {
      const { len, i: next } = readLen(buf, i + 1);
      i = next + len;
    }
  }
}

function parseNameConstraintsValue(buf) {
  const root = take(buf, 0, 0x30);
  const permitted = [];
  const excluded = [];
  let i = root.start;
  if (i < root.end && buf[i] === 0xa0) {
    const subtrees = take(buf, i, 0xa0);
    collectDnsNames(buf, subtrees, permitted);
    i = subtrees.i;
  }
  if (i < root.end && buf[i] === 0xa1) {
    const subtrees = take(buf, i, 0xa1);
    collectDnsNames(buf, subtrees, excluded);
  }
  return { permitted, excluded };
}

function parseNameConstraintsFromExtensions(buf, extWrapper) {
  const extensions = take(buf, extWrapper.start, 0x30);
  let j = extensions.start;
  while (j < extensions.end) {
    const ext = take(buf, j, 0x30);
    j = ext.i;
    const oidEl = take(buf, ext.start, 0x06);
    if (decodeOid(buf.subarray(oidEl.start, oidEl.end)) !== '2.5.29.30') continue;
    let k = oidEl.i;
    if (k < ext.end && buf[k] === 0x01) k = take(buf, k, 0x01).i;
    const extValue = take(buf, k, 0x04);
    return parseNameConstraintsValue(buf.subarray(extValue.start, extValue.end));
  }
  return null;
}

export function parseSpkiDer(der) {
  const buf = derBytes(der);
  const cert = take(buf, 0, 0x30);
  const tbs = take(buf, cert.start, 0x30);
  const i = skipTbsThroughSubject(buf, tbs);
  const spki = take(buf, i, 0x30);
  return buf.subarray(i, spki.i);
}

export function parseNameConstraints(der) {
  const buf = derBytes(der);
  const cert = take(buf, 0, 0x30);
  const tbs = take(buf, cert.start, 0x30);
  let i = skipTbsThroughSubject(buf, tbs);
  i = take(buf, i, 0x30).i;
  if (i < tbs.end && buf[i] === 0x81) i = take(buf, i, 0x81).i;
  if (i < tbs.end && buf[i] === 0x82) i = take(buf, i, 0x82).i;
  if (i >= tbs.end || buf[i] !== 0xa3) return null;
  return parseNameConstraintsFromExtensions(buf, take(buf, i, 0xa3));
}
