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
// ponytail: public-cas.json is ~145KB — load only for Allow, not on every popup open

const FLAG_DISABLED =
  'TLS cert API is disabled. Open chrome://flags, search WebRequestSecurityInfo, set Enabled, restart the browser. If that flag is missing, launch with --enable-features=WebRequestSecurityInfo';

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

function ping(msg) {
  try {
    void chrome.runtime.sendMessage(msg).catch(() => {});
  } catch {
    // service worker restarting / not ready
  }
}

/** First error-free record among the given session-storage keys. */
function pickBestRecord(got, keys) {
  for (const k of keys) {
    const r = got[k];
    if (r && r.error === null) return r;
  }
  return null;
}

/** Wait for the background capture to land in session storage (max ~1s). */
function waitForCapture(keys, ms = 1000) {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      chrome.storage.onChanged.removeListener(onChange);
      resolve(value);
    };
    const timer = setTimeout(() => finish(null), ms);
    const onChange = async (changes, area) => {
      if (area !== 'session' || !keys.some((k) => k in changes)) return;
      const hit = pickBestRecord(await chrome.storage.session.get(keys), keys);
      if (hit) finish(hit);
    };
    chrome.storage.onChanged.addListener(onChange);
  });
}

/** Why is there no verdict for this tab? First matching diagnosis wins. */
function reloadHint(hasHttps, meta) {
  const m = meta ?? {};
  const rows = [
    [
      !hasHttps,
      'Needs HTTPS site access to read certificates. Chrome → this extension → Site access → On all sites.',
    ],
    [!m.attachedSpec, 'webRequest did not attach. Open chrome://extensions → Zscaler MITM → service worker errors.'],
    [!m.lastAt && !m.canaryAt, 'Reload this tab to capture the certificate.'],
    [!m.lastAt && m.canaryAt, FLAG_DISABLED],
    [
      (m.lastTabId ?? -1) < 0 && m.hasSi,
      'A certificate was read but Chrome did not attach it to this tab. Reload this page, or click the toolbar icon again after the page finishes loading.',
    ],
    [m.hasSi === false, FLAG_DISABLED],
  ];
  const hit = rows.find(([when]) => when);
  if (hit) return hit[1];
  return (
    'Last capture tab=' +
    m.lastTabId +
    ' si=' +
    (m.hasSi ? 'yes' : 'no') +
    (m.lastError ? ' err=' + m.lastError : '') +
    (m.lastUrl ? ' url=' + m.lastUrl : '')
  );
}

function paintDebug(state) {
  document.getElementById('debug').textContent = formatCaptureDebug(state);
}

function paintStatus(record) {
  const status = document.getElementById('status');
  status.textContent = statusLine(record);
  status.className = iconKind(record);
}

function paintFields({ record, meta, hasHttps, tab }) {
  const fields = document.getElementById('fields');
  fields.replaceChildren();
  const grant = document.getElementById('grant');
  const recapture = document.getElementById('recapture');
  grant.hidden = true;
  recapture.hidden = true;

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
    return;
  }

  if (record && record.error === 'parse') {
    const hint = document.createElement('p');
    hint.id = 'hint';
    hint.textContent = record.detail || meta?.lastDetail || meta?.derKind || '';
    fields.append(hint);
    return;
  }

  if (!record || record.error === 'reload') {
    const hint = document.createElement('p');
    hint.id = 'hint';
    hint.textContent = reloadHint(hasHttps, meta);
    fields.append(hint);
    grant.hidden = !hasHttps;
    recapture.hidden = false;
  }
}

function paintAll(state) {
  paintStatus(state.record);
  paintFields(state);
  paintDebug(state);
}

function lastSuccessFits(meta, tab) {
  if (!meta?.lastSuccess || meta.lastSuccess.error !== null) return false;
  if (Number(meta.lastTabId) === tab.id || Number(meta.resolvedTabId) === tab.id) return true;
  return (
    sameHttpsOrigin(meta.lastSuccess.pageUrl || meta.lastSuccess.url, tab.url) ||
    certFitsTab(meta.lastSuccess.url, tab.url) ||
    certFitsTab(meta.lastSuccess.pageUrl, tab.url)
  );
}

async function readState(tab) {
  const key = 'tab:' + tab.id;
  const okKey = 'ok:' + tab.id;
  const originKey = storageOriginKey(tab.url);
  const got = await chrome.storage.session.get([key, okKey, originKey, 'meta:wr'].filter(Boolean));
  const meta = got['meta:wr'] ?? null;
  const hasHttps = await chrome.permissions.contains({ origins: ['https://*/*'] });

  let record = got[key] ?? null;
  let source = record && record.error === null ? 'tab' : 'none';
  if (!record || record.error === 'reload') {
    const best =
      pickBestRecord(got, [okKey, originKey].filter(Boolean)) ??
      (lastSuccessFits(meta, tab) ? meta.lastSuccess : null);
    if (best) {
      record = best;
      source = best === got[okKey] ? 'ok' : originKey && best === got[originKey] ? 'origin' : 'lastSuccess';
      await chrome.storage.session.set({ [key]: record });
    }
  }
  return { tab, key, okKey, originKey, record, meta, hasHttps, source, overlayCount: 0 };
}

function wireGrantRecapture(tab) {
  document.getElementById('grant').addEventListener('click', async () => {
    const ok = await chrome.permissions.request({ origins: ['https://*/*'] });
    const hint = document.getElementById('hint');
    if (hint) {
      hint.textContent = ok ? 'Access granted. Reload this tab.' : 'Permission denied.';
    }
    document.getElementById('grant').hidden = ok;
  });
  document.getElementById('recapture').addEventListener('click', () => chrome.tabs.reload(tab.id));
}

async function probeIfNeeded(state) {
  const { tab, key, okKey, originKey, hasHttps } = state;
  if (state.record && state.record.error !== 'reload') return;
  if (!hasHttps || !tab.url || !tab.url.startsWith('https:')) return;
  ping({ type: 'probe', url: tab.url, tabId: tab.id });
  const hit = await waitForCapture([key, okKey, originKey].filter(Boolean));
  if (hit) {
    state.record = hit;
    state.source = 'probe';
    await chrome.storage.session.set({ [key]: hit });
    ping({ type: 'apply-icon', tabId: tab.id });
    paintStatus(hit);
  }
  const metaGot = await chrome.storage.session.get('meta:wr');
  if (metaGot['meta:wr']) {
    state.meta = metaGot['meta:wr'];
    paintFields(state);
    paintDebug(state);
  }
}

async function wireAllow(state, overlays) {
  const { tab, key, okKey, record } = state;
  if (!record || record.error !== null || record.verdict === 'public' || !record.issuer) return;
  const allow = document.getElementById('allow');
  const host = hostnameFromUrl(tab.url) || hostnameFromUrl(record.pageUrl || record.url);
  const allowed = overlayDnsHasHost(overlayForIssuer(record.issuer, overlays), host);
  allow.hidden = false;
  allow.textContent = (allowed ? 'Disallow' : 'Allow') + ' this issuer for ' + host;
  allow.addEventListener('click', async () => {
    const next = allowed
      ? removeOverlayHost(overlays, record.issuer, host)
      : mergeOverlay(overlays, record.issuer, host);
    await saveOverlays(next);
    const { default: publicCasPacked } = await import('./public-cas.json', {
      with: { type: 'json' },
    });
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
    ping({
      type: 'overlays-changed',
      tabId: tab.id,
      record: updated,
    });
    location.reload();
  });
}

async function main() {
  document.getElementById('debug').textContent = 'popup.js running…';

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || typeof tab.id !== 'number') {
    document.getElementById('status').textContent = 'No active tab';
    document.getElementById('debug').textContent = 'tabs.query returned no tab';
    return;
  }

  const state = await readState(tab);
  let overlays = [];
  try {
    overlays = await loadOverlays();
  } catch {
    // ignore
  }
  state.overlayCount = overlays.reduce((n, o) => n + ((o && o.dns && o.dns.length) || 0), 0);

  // paint before probe / icon — hung messaging used to leave a blank popup
  paintAll(state);
  wireGrantRecapture(tab);

  if (state.record && state.record.error === null) {
    ping({ type: 'apply-icon', tabId: tab.id });
  }

  await probeIfNeeded(state);
  await wireAllow(state, overlays);
}

main().catch((e) => {
  const status = document.getElementById('status');
  const debug = document.getElementById('debug');
  if (status) status.textContent = 'Popup error';
  if (debug) debug.textContent = String(e && e.stack ? e.stack : e);
});
