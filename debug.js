function ago(ms) {
  if (typeof ms !== 'number' || !Number.isFinite(ms)) return '—';
  const s = Math.max(0, Math.round((Date.now() - ms) / 1000));
  if (s < 60) return s + 's ago';
  if (s < 3600) return Math.round(s / 60) + 'm ago';
  return Math.round(s / 3600) + 'h ago';
}

function shortUrl(u) {
  if (!u) return '—';
  try {
    const x = new URL(u);
    const path = x.pathname.length > 48 ? x.pathname.slice(0, 48) + '…' : x.pathname;
    return x.host + path;
  } catch {
    return String(u).slice(0, 72);
  }
}

export function formatCaptureDebug({ tab, record, meta, hasHttps, source, overlayCount }) {
  const m = meta || {};
  const rec = record || {};
  const tabId = tab && typeof tab.id === 'number' ? tab.id : '—';
  const last = m.lastTabId;
  const resolved = m.resolvedTabId;
  const tabMatch = last === tabId ? 'match' : 'mismatch';
  const lines = [
    'tab ' + tabId + ' last ' + (last ?? '—') + ' resolved ' + (resolved ?? '—') + ' (' + tabMatch + ')',
    'tabUrl ' + shortUrl(tab && tab.url),
    'httpsAccess ' + (hasHttps ? 'yes' : 'no') + ' spec ' + (m.attachedSpec || m.attachError || '—'),
    'record err=' + (rec.error === null ? 'ok' : rec.error || 'none') +
      ' verdict=' + (rec.verdict || '—') +
      ' src=' + (source || '—'),
    'certUrl ' + shortUrl(rec.url),
    'pageUrl ' + shortUrl(rec.pageUrl),
    'si ' + (m.hasSi === true ? 'yes' : m.hasSi === false ? 'no' : '—') +
      ' der=' + (m.derKind || '—') +
      ' lastErr=' + (m.lastError || rec.detail || '—'),
    'lastUrl ' + shortUrl(m.lastUrl),
    'lastAt ' + ago(m.lastAt) + ' canary ' + ago(m.canaryAt) +
      (m.canaryType ? ' ' + m.canaryType : ''),
  ];
  if (typeof overlayCount === 'number') lines.push('overlayHosts ' + overlayCount);
  if (m.canaryUrl) lines.push('canaryUrl ' + shortUrl(m.canaryUrl));
  if (m.lastSuccess && m.lastSuccess.url && m.lastSuccess.url !== rec.url) {
    lines.push('lastSuccess ' + shortUrl(m.lastSuccess.url));
  }
  return lines.join('\n');
}
