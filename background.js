import publicCasPacked from './public-cas.json' with { type: 'json' };
import {
  classify,
  hostnameFromUrl,
  iconKind,
  isPublicIssuer,
  parsePublicCas,
  pickPublicCas,
  shouldKeepOnComplete,
  shouldKeepRecord,
  resolveNavRecord,
} from './cert.js';
import { parseNameConstraints, parseSpkiDer, parseX509Names } from './asn1.js';
import { documentUrl, isOwnWebRequest, pickTabId, requestIsPageCert, shouldSkipCapture, storageOriginKey, storageOriginKeys } from './tab-match.js';
import { loadOverlays } from './overlay-store.js';
import { probeFetch } from './probe.js';

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
const tabHint = new Map();
// tabId → origins with a known-good record (over-approximation; lets
// subresource captures skip a storage read once the tab has its cert)
const goodOrigins = new Map();
let attachedSpec = null;
let attachError = '';
let activeTabId = null;
let overlaysCache = null;
let metaState; // mirror of META in session storage; undefined until first read

async function sha256Hex(bytes) {
  const hash = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

let publicCasCache = null;

async function currentPublicCas() {
  if (!publicCasCache) {
    const got = await chrome.storage.local.get(['publicCas', 'publicCasFetchedAt']);
    publicCasCache = pickPublicCas(got.publicCas, null, publicCasPacked);
  }
  return publicCasCache;
}

async function currentOverlays() {
  if (!overlaysCache) overlaysCache = await loadOverlays();
  return overlaysCache;
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
    publicCasCache = parsed;
  } catch {
    // keep last good / packed
  }
}

void refreshPublicCas(false);

function tabKey(tabId) {
  return 'tab:' + tabId;
}

function originOf(url) {
  try {
    const u = new URL(url);
    return u.protocol === 'https:' ? u.origin : null;
  } catch {
    return null;
  }
}

async function save(tabId, record) {
  const payload = {};
  if (tabId >= 0) payload[tabKey(tabId)] = record;
  if (record && record.error === null) {
    if (tabId >= 0) payload['ok:' + tabId] = record;
    for (const k of storageOriginKeys(record.pageUrl, record.url)) payload[k] = record;
    const o = originOf(record.pageUrl || record.url);
    if (tabId >= 0 && o) {
      let set = goodOrigins.get(tabId);
      if (!set) goodOrigins.set(tabId, (set = new Set()));
      set.add(o);
    }
  }
  if (Object.keys(payload).length) await chrome.storage.session.set(payload);
}

async function persistSuccess(record) {
  if (!record || record.error !== null) return;
  const payload = {};
  for (const k of storageOriginKeys(record.pageUrl, record.url)) payload[k] = record;
  if (Object.keys(payload).length) await chrome.storage.session.set(payload);
}

async function load(tabId) {
  const keys = [tabKey(tabId), 'ok:' + tabId];
  let tabUrl = tabHint.get(tabId) || '';
  if (!tabUrl) {
    try {
      tabUrl = (await chrome.tabs.get(tabId)).url || '';
    } catch {
      // tab gone
    }
  }
  const originK = storageOriginKey(tabUrl);
  if (originK) keys.push(originK);
  const got = await chrome.storage.session.get(keys);
  const rec = got[tabKey(tabId)];
  const ok = got['ok:' + tabId];
  const byOrigin = originK ? got[originK] : null;
  if (rec && rec.error === null) return rec;
  if (ok && ok.error === null) return ok;
  if (byOrigin && byOrigin.error === null) return byOrigin;
  return rec ?? null;
}

async function applyIcon(tabId, record) {
  if (record === undefined) record = await load(tabId);
  const path = ICONS[iconKind(record)];
  try {
    await chrome.action.setIcon({ tabId, path });
  } catch {
    // tab closed
  }
  if (activeTabId === null) {
    try {
      activeTabId = (await resolveActiveTab())?.id ?? -1;
    } catch {
      activeTabId = -1;
    }
  }
  if (activeTabId === tabId) {
    try {
      await chrome.action.setIcon({ path });
    } catch {
      // no focused window
    }
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
  return { url: url || '', pageUrl: url || '', subject: null, issuer: null, verdict: null, certNc: null, error };
}

async function writeMeta(extra) {
  if (metaState === undefined) {
    metaState = (await chrome.storage.session.get(META))[META] || {};
  }
  const next = {
    ...metaState,
    attachedSpec,
    attachError,
    ...extra,
  };
  // only lastAt ticked → nothing observable changed, skip the write
  const unchanged =
    JSON.stringify({ ...metaState, lastAt: 0 }) === JSON.stringify({ ...next, lastAt: 0 });
  metaState = next;
  if (unchanged) return;
  await chrome.storage.session.set({ [META]: next });
}

async function ensureRecord(tabId, url) {
  const existing = await load(tabId);
  if (classifyUrl(url) === 'not-https') {
    const record = blank(url, 'not-https');
    await save(tabId, record);
    return record;
  }
  // Re-read when the first snapshot does not fit — a concurrent capture may have landed
  // (stale prior-origin + late applyIcon was painting green over intercept).
  if (shouldKeepOnComplete(existing, url)) return existing;
  const latest = await load(tabId);
  const kept = resolveNavRecord(existing, latest, url);
  if (kept) return kept;
  const error = attachedSpec ? 'reload' : 'no-security-info';
  const record = blank(url, error);
  await save(tabId, record);
  return record;
}

const OWN_LIST_PREFIX = 'https://raw.githubusercontent.com/cavanaug/zscaler-mitm/';

async function tabUrlFromChrome(tabId) {
  const hinted = tabHint.get(tabId);
  if (hinted) return hinted;
  try {
    const t = await chrome.tabs.get(tabId);
    return t.url || '';
  } catch {
    return '';
  }
}

async function resolveActiveTab() {
  const tryQuery = async (q) => {
    try {
      const [t] = await chrome.tabs.query(q);
      if (t && t.id >= 0) return t;
    } catch {
      // query failed
    }
    return null;
  };
  const focused = await tryQuery({ active: true, lastFocusedWindow: true });
  if (focused) return focused;
  const anyActive = await tryQuery({ active: true });
  if (anyActive) return anyActive;
  try {
    const win = await chrome.windows.getLastFocused({ populate: true });
    const t = (win.tabs || []).find((x) => x.active);
    if (t && t.id >= 0) return t;
  } catch {
    // no window
  }
  return null;
}

async function resolveTabId(details) {
  if (details.tabId >= 0) return details.tabId;
  if (isOwnWebRequest(details, OWN_LIST_PREFIX)) return -1;
  let tabs = [];
  try {
    tabs = await chrome.tabs.query({});
  } catch {
    // no tabs
  }
  const active = await resolveActiveTab();
  return pickTabId(details, tabs, active);
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
  const chainDers = [];
  for (const c of certs) {
    const raw = c && (c.rawDER ?? c.rawDer ?? c.raw_der);
    if (raw != null) chainDers.push(raw);
  }
  // verdict is computed once in onHeadersReceived, after pageUrl is known;
  // chain SPKIs stay raw — hashing is deferred until O/CN miss the public list
  return {
    url: details.url,
    subject: names.subject,
    issuer: names.issuer,
    certNc,
    chainDers,
    error: null,
  };
}

async function hashChainSpkis(ders) {
  const out = [];
  for (const raw of ders) {
    try {
      out.push(await sha256Hex(parseSpkiDer(raw)));
    } catch {
      // skip
    }
  }
  return out;
}

async function classifyRecord(record) {
  const publicCas = await currentPublicCas();
  // ~46µs per cert — only worth hashing when issuer O and CN both miss
  const chainSpkis = isPublicIssuer(record.issuer, publicCas, [])
    ? []
    : await hashChainSpkis(record.chainDers || []);
  const verdict = classify({
    issuer: record.issuer,
    hostname: hostnameFromUrl(record.pageUrl || record.url),
    publicCas,
    overlays: await currentOverlays(),
    chainSpkis,
    certNc: record.certNc,
  });
  return { ...record, verdict };
}

async function reclassifyRecord(record) {
  if (!record || record.error !== null || !record.issuer) return record;
  // stored records have no chainDers; a public verdict may rest on SPKI match
  if (record.verdict === 'public') return record;
  return classifyRecord(record);
}

function onHeadersReceived(details) {
  const run = async () => {
    if (isOwnWebRequest(details, OWN_LIST_PREFIX)) return;
    const isMainFrame = details.type === 'main_frame';
    const tabId = await resolveTabId(details);
    if (tabId >= 0 && isMainFrame && details.url) tabHint.set(tabId, details.url);
    const tabUrl = tabId >= 0 ? await tabUrlFromChrome(tabId) : '';
    const pageCert = requestIsPageCert(details, tabUrl);

    // filter before parsing — a subresource cert that would never be saved
    // still costs a full parse + classify otherwise
    let existing;
    if (!isMainFrame) {
      if (tabId < 0 || !pageCert) return;
      const origins = goodOrigins.get(tabId);
      const tabOrigin = originOf(tabUrl);
      if (origins && tabOrigin && origins.has(tabOrigin)) return;
      existing = await load(tabId);
      if (shouldSkipCapture(existing, details, tabUrl)) return;
    }

    let record;
    try {
      record = await recordFromDetails(details);
    } catch (e) {
      record = blank(details.url, 'parse');
      record.detail = String(e && e.message ? e.message : e);
    }
    record = {
      ...record,
      pageUrl: documentUrl(details, tabUrl),
    };
    if (record.error === null) {
      record = await classifyRecord(record);
      const { chainDers, ...rest } = record;
      record = rest;
    }
    const leaf = details.securityInfo && (details.securityInfo.certificates || [])[0];
    const extra = {
      lastTabId: details.tabId,
      resolvedTabId: tabId,
      lastUrl: details.url,
      lastError: record.error,
      lastDetail: record.detail || null,
      hasSi: Boolean(details.securityInfo),
      derKind: leaf && leaf.rawDER != null ? typeof leaf.rawDER : 'missing',
      lastAt: Date.now(),
    };
    if (record.error === null) {
      extra.lastSuccess = record;
      if (pageCert) await persistSuccess(record);
    }
    await writeMeta(extra);
    if (tabId < 0) return;
    if (existing === undefined) existing = await load(tabId);
    if (shouldSkipCapture(existing, details, tabUrl)) return;
    if (record.error !== null && !isMainFrame) return;
    if (
      existing &&
      existing.error === null &&
      record.error !== null &&
      shouldKeepRecord(existing, tabUrl || record.url)
    ) {
      return;
    }
    await save(tabId, record);
    await applyIcon(tabId, record);
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
// one-shot: proves webRequest events flow, then stops costing IPCs per request
function canary(details) {
  chrome.webRequest.onBeforeRequest.removeListener(canary);
  void writeMeta({
    canaryAt: Date.now(),
    canaryType: details.type,
    canaryTabId: details.tabId,
    canaryUrl: details.url,
  }).catch(() => {});
}
try {
  chrome.webRequest.onBeforeRequest.addListener(canary, filter);
} catch (e) {
  attachError = (attachError ? attachError + '; ' : '') + String(e && e.message ? e.message : e);
}
if (attached.length) attachedSpec = attached.join(',');
void chrome.webRequest.handlerBehaviorChanged?.().catch(() => {});
void writeMeta({}).catch(() => {});

chrome.permissions.onAdded.addListener((p) => {
  if (p.origins && p.origins.length) chrome.runtime.reload();
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && 'overlays' in changes) overlaysCache = null;
});

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  const run = async () => {
    try {
      if (msg && msg.type === 'overlays-changed') {
        if (typeof msg.tabId === 'number' && msg.tabId >= 0 && msg.record) {
          await save(msg.tabId, msg.record);
          await applyIcon(msg.tabId, msg.record);
        }
        const tabs = await chrome.tabs.query({});
        for (const tab of tabs) {
          if (tab.id < 0) continue;
          if (msg.tabId === tab.id && msg.record) continue;
          const rec = await load(tab.id);
          if (!rec) continue;
          const updated = await reclassifyRecord(rec);
          await save(tab.id, updated);
          await applyIcon(tab.id, updated);
        }
      } else if (msg && msg.type === 'apply-icon' && typeof msg.tabId === 'number') {
        await applyIcon(msg.tabId, msg.record);
      } else if (msg && msg.type === 'probe' && typeof msg.url === 'string') {
        await probeFetch(msg.url);
      }
    } finally {
      sendResponse({ ok: true });
    }
  };
  void run().catch(() => {});
  return true;
});

chrome.tabs.onUpdated.addListener(async (tabId, info, tab) => {
  try {
    if (tabId < 0) return;
    if (info.url) tabHint.set(tabId, info.url);
    if (info.url) {
      const url = info.url;
      if (classifyUrl(url) === 'not-https') {
        await save(tabId, blank(url, 'not-https'));
        await applyIcon(tabId);
        return;
      }
      await applyIcon(tabId, await ensureRecord(tabId, url));
      return;
    }
    if (info.status !== 'complete') return;
    const url = tab.url || tabHint.get(tabId);
    if (classifyUrl(url) === 'not-https') {
      await save(tabId, blank(url, 'not-https'));
      await applyIcon(tabId);
      return;
    }
    const existing = await load(tabId);
    if (shouldKeepOnComplete(existing, url)) {
      await applyIcon(tabId, existing);
      return;
    }
    await applyIcon(tabId, await ensureRecord(tabId, url));
  } catch {
    // ponytail: swallow — never throw out of service worker
  }
});

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  try {
    activeTabId = tabId;
    if (tabId < 0) return;
    let url = '';
    try {
      const tab = await chrome.tabs.get(tabId);
      url = tab.url || '';
    } catch {
      return;
    }
    const existing = await load(tabId);
    if (shouldKeepOnComplete(existing, url)) {
      await applyIcon(tabId, existing);
      return;
    }
    await applyIcon(tabId, await ensureRecord(tabId, url));
  } catch {
    // ponytail: swallow — never throw out of service worker
  }
});

chrome.tabs.onRemoved.addListener(async (tabId) => {
  try {
    tabHint.delete(tabId);
    goodOrigins.delete(tabId);
    await chrome.storage.session.remove([tabKey(tabId), 'ok:' + tabId]);
  } catch {
    // ponytail: swallow — never throw out of service worker
  }
});
