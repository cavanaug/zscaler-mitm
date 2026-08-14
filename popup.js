import { iconKind, statusLine } from './cert.js';

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
const got = await chrome.storage.session.get([key, 'meta:wr']);
const record = got[key] ?? null;
const meta = got['meta:wr'] ?? null;
const hasHttps = await chrome.permissions.contains({ origins: ['https://*/*'] });

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
} else if (record && record.error === 'parse') {
  const hint = document.createElement('p');
  hint.id = 'hint';
  hint.textContent = record.detail || meta?.lastDetail || meta?.derKind || '';
  fields.append(hint);
} else if (!record || record.error === 'reload') {
  const hint = document.createElement('p');
  hint.id = 'hint';
  if (!hasHttps) {
    hint.textContent = 'Needs HTTPS site access to read certificates.';
    grant.hidden = false;
  } else if (!meta?.attachedSpec) {
    hint.textContent =
      'webRequest did not attach. Open chrome://extensions → Zscaler MITM → service worker errors.';
  } else if (!meta.lastAt && !meta.canaryAt) {
    hint.textContent = 'Reload this tab to capture the certificate.';
  } else if (!meta.lastAt && meta.canaryAt) {
    hint.textContent =
      'TLS cert API is disabled. Open chrome://flags, search WebRequestSecurityInfo, set Enabled, restart the browser. If that flag is missing, launch with --enable-features=WebRequestSecurityInfo';
  } else {
    hint.textContent =
      'Last capture tab=' +
      meta.lastTabId +
      ' si=' +
      (meta.hasSi ? 'yes' : 'no') +
      (meta.lastError ? ' err=' + meta.lastError : '');
  }
  fields.append(hint);
}
