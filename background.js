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
  shouldKeepOnComplete,
  shouldKeepRecord,
} from './cert.js';
import { documentUrl, isOwnWebRequest, pickTabId, requestIsPageCert, shouldSkipCapture, storageOriginKey, storageOriginKeys } from './tab-match.js';
import { loadOverlays } from './overlay-store.js';

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
let attachedSpec = null;
let attachError = '';

async function sha256Hex(bytes) {
  const hash = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, '0')).join('');
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
  const payload = {};
  if (tabId >= 0) payload[tabKey(tabId)] = record;
  if (record && record.error === null) {
    if (tabId >= 0) payload['ok:' + tabId] = record;
    for (const k of storageOriginKeys(record.pageUrl, record.url)) payload[k] = record;
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

async function applyIcon(tabId) {
  const record = await load(tabId);
  const path = ICONS[iconKind(record)];
  try {
    await chrome.action.setIcon({ tabId, path });
  } catch {
    // tab closed
  }
  try {
    const active = await resolveActiveTab();
    if (active && active.id === tabId) await chrome.action.setIcon({ path });
  } catch {
    // no focused window
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
  if (classifyUrl(url) === 'not-https') {
    const record = blank(url, 'not-https');
    await save(tabId, record);
    return record;
  }
  // never clobber a parsed cert with the reload placeholder (CDN hops + onUpdated race)
  if (existing && existing.error === null) return existing;
  if (shouldKeepRecord(existing, url)) return existing;
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
  if (record.verdict === 'public') return record;
  const verdict = classify({
    issuer: record.issuer,
    hostname: hostnameFromUrl(record.pageUrl || record.url),
    publicCas: await currentPublicCas(),
    overlays: await loadOverlays(),
    chainSpkis: [],
    certNc: record.certNc,
  });
  return { ...record, verdict };
}

function onHeadersReceived(details) {
  const run = async () => {
    if (isOwnWebRequest(details, OWN_LIST_PREFIX)) return;
    let record;
    try {
      record = await recordFromDetails(details);
    } catch (e) {
      record = blank(details.url, 'parse');
      record.detail = String(e && e.message ? e.message : e);
    }
    const tabId = await resolveTabId(details);
    if (tabId >= 0 && details.type === 'main_frame' && details.url) tabHint.set(tabId, details.url);
    const tabUrl = tabId >= 0 ? await tabUrlFromChrome(tabId) : '';
    record = {
      ...record,
      pageUrl: documentUrl(details, tabUrl),
    };
    if (record.error === null) record = await reclassifyRecord(record);
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
      if (requestIsPageCert(details, tabUrl)) await persistSuccess(record);
    }
    await writeMeta(extra);
    if (tabId < 0) return;
    const existing = await load(tabId);
    if (record.error === null && !requestIsPageCert(details, tabUrl)) return;
    if (shouldSkipCapture(existing, details, tabUrl)) return;
    if (record.error !== null && details.type !== 'main_frame') return;
    if (
      existing &&
      existing.error === null &&
      record.error !== null &&
      shouldKeepRecord(existing, tabUrl || record.url)
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
    try {
      if (msg && msg.type === 'overlays-changed') {
        if (typeof msg.tabId === 'number' && msg.tabId >= 0 && msg.record) {
          await save(msg.tabId, msg.record);
          await applyIcon(msg.tabId);
        }
        const tabs = await chrome.tabs.query({});
        for (const tab of tabs) {
          if (tab.id < 0) continue;
          if (msg.tabId === tab.id && msg.record) continue;
          const rec = await load(tab.id);
          if (!rec) continue;
          await save(tab.id, await reclassifyRecord(rec));
          await applyIcon(tab.id);
        }
      } else if (msg && msg.type === 'apply-icon' && typeof msg.tabId === 'number') {
        await applyIcon(msg.tabId);
      } else if (msg && msg.type === 'probe' && typeof msg.url === 'string') {
        let target = msg.url;
        try {
          target = new URL(msg.url).origin + '/';
        } catch {
          // use as-is
        }
        try {
          await fetch(target, { method: 'HEAD', cache: 'no-store', redirect: 'follow' });
        } catch {
          try {
            await fetch(target, { method: 'GET', cache: 'no-store', redirect: 'follow' });
          } catch {
            // page may require cookies; user can reload
          }
        }
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
      await ensureRecord(tabId, url);
      await applyIcon(tabId);
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
    const existing = await load(tabId);
    if (shouldKeepOnComplete(existing, url)) {
      await applyIcon(tabId);
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
    tabHint.delete(tabId);
    await chrome.storage.session.remove([tabKey(tabId), 'ok:' + tabId]);
  } catch {
    // ponytail: swallow — never throw out of service worker
  }
});
