import { iconKind, isZscalerIssuer, parseX509Names, shouldKeepRecord } from './cert.js';

const ICONS = {
  default: { 16: 'icons/default-16.png', 32: 'icons/default-32.png' },
  yellow: { 16: 'icons/yellow-16.png', 32: 'icons/yellow-32.png' },
  red: { 16: 'icons/red-16.png', 32: 'icons/red-32.png' },
};

const META = 'meta:wr';
let attachedSpec = null;
let attachError = '';

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

function recordFromDetails(details) {
  const si = details.securityInfo;
  if (!si) return blank(details.url, 'no-security-info');
  const { der, why } = leafRawDer(si);
  if (!der) {
    const rec = blank(details.url, 'parse');
    rec.detail = why;
    return rec;
  }
  const names = parseX509Names(der);
  return {
    url: details.url,
    subject: names.subject,
    issuer: names.issuer,
    zscaler: isZscalerIssuer(names.issuer),
    error: null,
  };
}

function onHeadersReceived(details) {
  const run = async () => {
    let record;
    try {
      record = recordFromDetails(details);
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
