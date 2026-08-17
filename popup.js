import publicCasPacked from './public-cas.json' with { type: 'json' };
import { formatCaptureDebug } from './debug.js';
import { loadOverlays, saveOverlays } from './overlay-store.js';
import { storageOriginKey } from './tab-match.js';
import {
  certFitsTab,
  classify,
  hostnameFromUrl,
  iconKind,
  mergeOverlay,
  overlayDnsHasHost,
  overlayForIssuer,
  pickPublicCas,
  removeOverlayHost,
  sameHttpsOrigin,
  statusLine,
} from './cert.js';

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
const okKey = 'ok:' + tab.id;
const originKey = storageOriginKey(tab.url);
const got = await chrome.storage.session.get([key, okKey, originKey, 'meta:wr'].filter(Boolean));
let record = got[key] ?? null;
let meta = got['meta:wr'] ?? null;
const hasHttps = await chrome.permissions.contains({ origins: ['https://*/*'] });

const lastOk = meta?.lastSuccess && meta.lastSuccess.error === null;
const tabMatch = meta && (Number(meta.lastTabId) === tab.id || Number(meta.resolvedTabId) === tab.id);
const lastFits =
  lastOk &&
  (sameHttpsOrigin(meta.lastSuccess.pageUrl || meta.lastSuccess.url, tab.url) ||
    certFitsTab(meta.lastSuccess.url, tab.url) ||
    certFitsTab(meta.lastSuccess.pageUrl, tab.url) ||
    tabMatch);
const originHit = originKey && got[originKey] && got[originKey].error === null ? got[originKey] : null;
let source = record && record.error === null ? 'tab' : 'none';
if ((!record || record.error === 'reload') && got[okKey] && got[okKey].error === null) {
  record = got[okKey];
  source = 'ok';
  await chrome.storage.session.set({ [key]: record });
  await chrome.runtime.sendMessage({ type: 'apply-icon', tabId: tab.id });
} else if ((!record || record.error === 'reload') && originHit) {
  record = originHit;
  source = 'origin';
  await chrome.storage.session.set({ [key]: record });
  await chrome.runtime.sendMessage({ type: 'apply-icon', tabId: tab.id });
} else if ((!record || record.error === 'reload') && lastFits) {
  record = meta.lastSuccess;
  source = 'lastSuccess';
  await chrome.storage.session.set({ [key]: record });
  await chrome.runtime.sendMessage({ type: 'apply-icon', tabId: tab.id });
}

if (
  (!record || record.error === 'reload') &&
  hasHttps &&
  tab.url &&
  tab.url.startsWith('https:')
) {
  await chrome.runtime.sendMessage({ type: 'probe', url: tab.url, tabId: tab.id });
  for (let i = 0; i < 20; i++) {
    await new Promise((r) => setTimeout(r, 50));
    const again = await chrome.storage.session.get([key, okKey, originKey].filter(Boolean));
    const hit =
      (again[key] && again[key].error === null && again[key]) ||
      (again[okKey] && again[okKey].error === null && again[okKey]) ||
      (originKey && again[originKey] && again[originKey].error === null && again[originKey]);
    if (hit) {
      record = hit;
      source = 'probe';
      await chrome.storage.session.set({ [key]: record });
      await chrome.runtime.sendMessage({ type: 'apply-icon', tabId: tab.id });
      break;
    }
  }
  const metaGot = await chrome.storage.session.get('meta:wr');
  if (metaGot['meta:wr']) meta = metaGot['meta:wr'];
}

const status = document.getElementById('status');
status.textContent = statusLine(record);
status.className = iconKind(record);

const fields = document.getElementById('fields');
fields.replaceChildren();
const grant = document.getElementById('grant');
grant.addEventListener('click', async () => {
  const ok = await chrome.permissions.request({ origins: ['https://*/*'] });
  const hint = document.getElementById('hint');
  if (hint) {
    hint.textContent = ok ? 'Access granted. Reload this tab.' : 'Permission denied.';
  }
  grant.hidden = ok;
});

if (record && record.error === null) {
  fields.append(nameBlock('Subject', record.subject), nameBlock('Issuer', record.issuer));
  try {
    const shown = new URL(record.url).hostname;
    const tabHost = new URL(tab.url).hostname;
    if (shown !== tabHost) {
      const note = document.createElement('p');
      note.id = 'hint';
      note.textContent = 'Captured from ' + shown + ' (Chrome did not tag this tab).';
      fields.append(note);
    }
  } catch {
    // ignore
  }
} else if (record && record.error === 'parse') {
  const hint = document.createElement('p');
  hint.id = 'hint';
  hint.textContent = record.detail || meta?.lastDetail || meta?.derKind || '';
  fields.append(hint);
} else if (!record || record.error === 'reload') {
  const hint = document.createElement('p');
  hint.id = 'hint';
  if (!hasHttps) {
    hint.textContent =
      'Needs HTTPS site access to read certificates. Chrome → this extension → Site access → On all sites.';
    grant.hidden = false;
  } else if (!meta?.attachedSpec) {
    hint.textContent =
      'webRequest did not attach. Open chrome://extensions → Zscaler MITM → service worker errors.';
  } else if (!meta.lastAt && !meta.canaryAt) {
    hint.textContent = 'Reload this tab to capture the certificate.';
  } else if (!meta.lastAt && meta.canaryAt) {
    hint.textContent =
      'TLS cert API is disabled. Open chrome://flags, search WebRequestSecurityInfo, set Enabled, restart the browser. If that flag is missing, launch with --enable-features=WebRequestSecurityInfo';
  } else if (meta.lastTabId < 0 && meta.hasSi) {
    hint.textContent =
      'A certificate was read but Chrome did not attach it to this tab. Reload this page, or click the toolbar icon again after the page finishes loading.';
  } else if (meta.hasSi === false) {
    hint.textContent =
      'TLS cert API is disabled. Open chrome://flags, search WebRequestSecurityInfo, set Enabled, restart the browser. If that flag is missing, launch with --enable-features=WebRequestSecurityInfo';
  } else {
    hint.textContent =
      'Last capture tab=' +
      meta.lastTabId +
      ' si=' +
      (meta.hasSi ? 'yes' : 'no') +
      (meta.lastError ? ' err=' + meta.lastError : '') +
      (meta.lastUrl ? ' url=' + meta.lastUrl : '');
  }
  fields.append(hint);
  const recapture = document.getElementById('recapture');
  recapture.hidden = false;
  recapture.addEventListener('click', () => chrome.tabs.reload(tab.id));
}

if (record && record.error === null && record.verdict !== 'public' && record.issuer) {
  const allow = document.getElementById('allow');
  const host = hostnameFromUrl(tab.url) || hostnameFromUrl(record.pageUrl || record.url);
  const overlays = await loadOverlays();
  const allowed = overlayDnsHasHost(overlayForIssuer(record.issuer, overlays), host);
  allow.hidden = false;
  allow.textContent = (allowed ? 'Disallow' : 'Allow') + ' this issuer for ' + host;
  allow.addEventListener('click', async () => {
    const next = allowed
      ? removeOverlayHost(overlays, record.issuer, host)
      : mergeOverlay(overlays, record.issuer, host);
    await saveOverlays(next);
    const updated = {
      ...record,
      pageUrl: record.pageUrl || tab.url,
      verdict: classify({
        issuer: record.issuer,
        hostname: host,
        publicCas: pickPublicCas(null, null, publicCasPacked),
        overlays: next,
        chainSpkis: [],
        certNc: record.certNc,
      }),
    };
    await chrome.storage.session.set({ [key]: updated, [okKey]: updated });
    await chrome.runtime.sendMessage({
      type: 'overlays-changed',
      tabId: tab.id,
      record: updated,
    });
    location.reload();
  });
}

document.getElementById('debug').textContent = formatCaptureDebug({
  tab,
  record,
  meta,
  hasHttps,
  source,
  overlayCount: (await loadOverlays()).reduce((n, o) => n + ((o && o.dns && o.dns.length) || 0), 0),
});
