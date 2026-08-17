import publicCasPacked from './public-cas.json' with { type: 'json' };
import { pickPublicCas } from './cert.js';
import { loadOverlays, saveOverlays } from './overlay-store.js';

function parseDnsInput(text) {
  return text
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

function overlayKey(o) {
  return o.O + '\0' + (o.CN ?? '');
}

function renderList(items) {
  const list = document.getElementById('list');
  const empty = document.getElementById('empty');
  list.replaceChildren();
  if (!items.length) {
    empty.hidden = false;
    return;
  }
  empty.hidden = true;
  for (const o of items) {
    const li = document.createElement('li');
    const meta = document.createElement('div');
    meta.className = 'meta';
    meta.textContent = 'O: ' + o.O + (o.CN ? ' · CN: ' + o.CN : '');
    const dns = document.createElement('div');
    dns.className = 'dns';
    dns.textContent = 'DNS: ' + ((o.dns && o.dns.length) ? o.dns.join(', ') : '—');
    const del = document.createElement('button');
    del.type = 'button';
    del.textContent = 'Delete';
    del.addEventListener('click', async () => {
      const next = overlays.filter((x) => overlayKey(x) !== overlayKey(o));
      await applyOverlays(next);
    });
    li.append(meta, dns, del);
    list.append(li);
  }
}

async function applyOverlays(next) {
  overlays = next;
  await saveOverlays(overlays);
  await chrome.runtime.sendMessage({ type: 'overlays-changed' });
  renderList(overlays);
}

async function renderFooter() {
  const got = await chrome.storage.local.get(['publicCas', 'publicCasFetchedAt']);
  const publicCas = pickPublicCas(got.publicCas, null, publicCasPacked);
  document.getElementById('generated-at').textContent =
    'Public list generatedAt: ' + (publicCas.generatedAt || '—');
  const refresh = document.getElementById('last-refresh');
  if (typeof got.publicCasFetchedAt === 'number') {
    refresh.textContent =
      'Last GitHub refresh: ' + new Date(got.publicCasFetchedAt).toLocaleString();
  } else {
    refresh.textContent = 'Last GitHub refresh: packed snapshot';
  }
}

let overlays = await loadOverlays();
renderList(overlays);
await renderFooter();

document.getElementById('add').addEventListener('submit', async (e) => {
  e.preventDefault();
  const O = document.getElementById('o').value.trim();
  const cnRaw = document.getElementById('cn').value.trim();
  const dns = parseDnsInput(document.getElementById('dns').value);
  if (!O || !dns.length) return;
  const entry = { O, CN: cnRaw || null, dns };
  let next = [...overlays];
  const hit = next.find((x) => overlayKey(x) === overlayKey(entry));
  if (hit) {
    const merged = new Set([...(hit.dns || []), ...dns]);
    hit.dns = [...merged];
  } else {
    next.push(entry);
  }
  await applyOverlays(next);
  e.target.reset();
});
