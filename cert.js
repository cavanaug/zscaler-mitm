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
  if (organizations.length < 50) return null;
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
  let best = null;
  for (const x of [fetched, cached, packed]) {
    const p = parsePublicCas(x);
    if (!p) continue;
    if (!best || p.generatedAt > best.generatedAt) best = p;
  }
  return best || EMPTY_PUBLIC_CAS;
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
  if (issuer.O && orgInList(issuer.O, publicCas.organizations)) return true;
  if (issuer.CN && issuer.CN.length >= 8 && publicCas.issuerCNs.includes(issuer.CN)) return true;
  const roots = new Set(publicCas.rootSpkis);
  for (const s of chainSpkis || []) {
    if (roots.has(String(s).toLowerCase())) return true;
  }
  return false;
}

function normOrg(s) {
  return String(s || '')
    .toLowerCase()
    .replace(/[.,]/g, ' ')
    .replace(/\b(llc|inc|ltd|corp|corporation|incorporated|limited|gmbh|co)\b/g, '')
    .replace(/\s+/g, ' ')
    .trim();
}

function orgInList(o, organizations) {
  if (!o || !Array.isArray(organizations)) return false;
  if (organizations.includes(o)) return true;
  const n = normOrg(o);
  if (!n) return false;
  return organizations.some((x) => normOrg(x) === n);
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

function normHost(h) {
  return String(h || '').replace(/^\.+/, '').replace(/\.$/, '').toLowerCase();
}

export function overlayDnsHasHost(overlay, host) {
  if (!overlay || !host) return false;
  const h = normHost(host);
  return (overlay.dns || []).some((d) => normHost(d) === h);
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

export function removeOverlayHost(overlays, issuer, host) {
  const list = Array.isArray(overlays) ? overlays.map((o) => ({ ...o, dns: [...(o.dns || [])] })) : [];
  const hit = overlayForIssuer(issuer, list);
  if (!hit || !host) return list;
  const h = normHost(host);
  hit.dns = hit.dns.filter((d) => normHost(d) !== h);
  if (!hit.dns.length) return list.filter((o) => o !== hit);
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

export function relatedHost(a, b) {
  if (!a || !b) return false;
  if (a === b) return true;
  if (a.endsWith('.' + b) || b.endsWith('.' + a)) return true;
  const as = a.split('.');
  const bs = b.split('.');
  // ponytail: 3-label suffix (azc.ext.hp.com), not a PSL
  if (as.length >= 3 && bs.length >= 3) {
    return as.slice(-3).join('.') === bs.slice(-3).join('.');
  }
  return false;
}

export function certFitsTab(certUrl, tabUrl) {
  if (!certUrl) return false;
  if (!tabUrl) return true;
  try {
    const c = new URL(certUrl);
    const t = new URL(tabUrl);
    if (c.protocol !== t.protocol) return false;
    if (c.origin === t.origin) return true;
    return relatedHost(c.hostname, t.hostname);
  } catch {
    return false;
  }
}

export function sameHttpsOrigin(a, b) {
  try {
    const ua = new URL(a);
    const ub = new URL(b);
    return ua.protocol === 'https:' && ub.protocol === 'https:' && ua.origin === ub.origin;
  } catch {
    return false;
  }
}

export function shouldKeepRecord(existing, url) {
  if (!existing) return false;
  // never keep the reload placeholder — it trapped tabs when tabId was -1
  if (existing.error === 'reload') return false;
  if (existing.error === 'not-https') return false;
  // pageUrl is the tab document; record.url may be a CDN hop
  return sameHttpsOrigin(existing.pageUrl || existing.url, url);
}

export function shouldKeepOnComplete(existing, url) {
  if (!existing || existing.error !== null) return false;
  if (shouldKeepRecord(existing, url)) return true;
  // CDN hop: don't wipe a parsed cert when status=complete reports the document URL
  return certFitsTab(existing.url, url);
}

/** Pick cert after tab URL change. `latest` is a re-read so a concurrent capture wins. */
export function resolveNavRecord(existing, latest, url) {
  if (shouldKeepOnComplete(existing, url)) return existing;
  if (latest && latest !== existing && shouldKeepOnComplete(latest, url)) return latest;
  return null;
}

