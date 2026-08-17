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

const META = 'meta:wr';
let attachedSpec = null;
let attachError = '';

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
  return { url: url || '', subject: null, issuer: null, verdict: null, certNc: null, error };
}

async function writeMeta(extra) {
  const prev = (await chrome.storage.session.get(META))[META] || {};
  await chrome.storage.session.set({
    [META]: {
      ...prev,
      attachedSpec,
      attachError,
      ...extra,
    },
  });
}

async function ensureRecord(tabId, url) {
  const existing = await load(tabId);
  if (shouldKeepRecord(existing, url)) return existing;
  const kind = classifyUrl(url);
  const error =
    kind === 'not-https' ? 'not-https' : attachedSpec ? 'reload' : 'no-security-info';
  const record = blank(url, error);
  await save(tabId, record);
  return record;
}

async function resolveTabId(details) {
  if (details.tabId >= 0) return details.tabId;
  try {
    const matches = await chrome.tabs.query({ url: details.url });
    if (matches.length === 1) return matches[0].id;
  } catch {
    // no matching tab
  }
  return -1;
}

function leafRawDer(si) {
  const certs = si.certificates;
  const leaf = Array.isArray(certs) ? certs[0] : certs;
  if (!leaf) return { der: null, why: 'no certificates' };
  const der = leaf.rawDER ?? leaf.rawDer ?? leaf.raw_der ?? null;
  if (der == null) {
    return { der: null, why: 'no rawDER; keys=' + Object.keys(leaf).join(',') };
  }
  return { der, why: null };
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

function onHeadersReceived(details) {
  const run = async () => {
    let record;
    try {
      record = await recordFromDetails(details);
    } catch (e) {
      record = blank(details.url, 'parse');
      record.detail = String(e && e.message ? e.message : e);
    }
    const tabId = await resolveTabId(details);
    const leaf = details.securityInfo && (details.securityInfo.certificates || [])[0];
    await writeMeta({
      lastTabId: details.tabId,
      resolvedTabId: tabId,
      lastUrl: details.url,
      lastError: record.error,
      lastDetail: record.detail || null,
      hasSi: Boolean(details.securityInfo),
      derKind: leaf && leaf.rawDER != null ? typeof leaf.rawDER : 'missing',
      lastAt: Date.now(),
    });
    if (tabId < 0) return;
    // ponytail: subresource cert if main_frame was missed; a CDN hop can differ
    if (details.type !== 'main_frame') {
      const existing = await load(tabId);
      if (existing && existing.error === null) return;
    }
    const existing = await load(tabId);
    if (
      existing &&
      existing.error === null &&
      record.error !== null &&
      shouldKeepRecord(existing, record.url)
    ) {
      return;
    }
    await save(tabId, record);
    await applyIcon(tabId);
  };
  void run().catch(() => {});
}

const filter = { urls: ['https://*/*'] };
const extraSpecs = [
  ['extraHeaders', 'securityInfoRawDer'],
  ['securityInfoRawDer'],
];
const attached = [];
for (const spec of extraSpecs) {
  try {
    chrome.webRequest.onHeadersReceived.addListener(onHeadersReceived, filter, spec);
    attached.push(spec.join('+'));
    attachedSpec = spec;
  } catch (e) {
    attachError = String(e && e.message ? e.message : e);
  }
}
try {
  chrome.webRequest.onBeforeRequest.addListener((details) => {
    void writeMeta({
      canaryAt: Date.now(),
      canaryType: details.type,
      canaryTabId: details.tabId,
      canaryUrl: details.url,
    }).catch(() => {});
  }, filter);
} catch (e) {
  attachError = (attachError ? attachError + '; ' : '') + String(e && e.message ? e.message : e);
}
if (attached.length) attachedSpec = attached.join(',');
void chrome.webRequest.handlerBehaviorChanged?.().catch(() => {});
void writeMeta({}).catch(() => {});

chrome.permissions.onAdded.addListener((p) => {
  if (p.origins && p.origins.length) chrome.runtime.reload();
});

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

chrome.tabs.onUpdated.addListener(async (tabId, info, tab) => {
  try {
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
  } catch {
    // ponytail: swallow — never throw out of service worker
  }
});

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  try {
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
  } catch {
    // ponytail: swallow — never throw out of service worker
  }
});

chrome.tabs.onRemoved.addListener(async (tabId) => {
  try {
    await chrome.storage.session.remove(tabKey(tabId));
  } catch {
    // ponytail: swallow — never throw out of service worker
  }
});
