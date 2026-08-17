import { certFitsTab, sameHttpsOrigin } from './cert.js';

export { certFitsTab };

export function isOwnWebRequest(details, selfPrefix) {
  if (!details) return false;
  const url = details.url || '';
  return Boolean(selfPrefix && url.startsWith(selfPrefix));
}

export function storageOriginKey(url) {
  try {
    const u = new URL(url);
    if (u.protocol !== 'https:') return null;
    return 'okOrigin:' + u.origin;
  } catch {
    return null;
  }
}

export function storageOriginKeys(pageUrl, url) {
  const out = [];
  for (const u of [pageUrl, url]) {
    const k = storageOriginKey(u);
    if (k && !out.includes(k)) out.push(k);
  }
  return out;
}

export function documentUrl(details, tabUrl) {
  if (details && details.type === 'main_frame' && details.url) return details.url;
  const init = details && details.initiator;
  if (typeof init === 'string' && init.startsWith('https://')) return init;
  return tabUrl || (details && details.url) || '';
}

export function existingBelongsToTab(existing, tabUrl) {
  if (!existing || existing.error !== null) return false;
  if (!tabUrl) return false;
  return sameHttpsOrigin(existing.pageUrl || existing.url, tabUrl);
}

export function requestIsPageCert(details, tabUrl) {
  if (!details || !details.url) return false;
  if (details.type === 'main_frame' || details.type === 'sub_frame') return true;
  const page = documentUrl(details, tabUrl) || tabUrl;
  if (!page) return false;
  return sameHttpsOrigin(details.url, page) || certFitsTab(details.url, page);
}

export function shouldSkipCapture(existing, details, tabUrl) {
  if (!details || details.type === 'main_frame') return false;
  return existingBelongsToTab(existing, tabUrl);
}

export function pickTabId(details, tabs, activeTab) {
  if (details && typeof details.tabId === 'number' && details.tabId >= 0) {
    return details.tabId;
  }
  const url = details && details.url;
  let origin = '';
  try {
    origin = new URL(url).origin;
  } catch {
    origin = '';
  }
  const list = Array.isArray(tabs) ? tabs : [];
  if (origin) {
    const exact = list.filter((t) => t && t.url === url);
    if (exact.length === 1) return exact[0].id;
    const sameOrigin = list.filter((t) => {
      try {
        return new URL(t.url).origin === origin;
      } catch {
        return false;
      }
    });
    if (sameOrigin.length === 1) return sameOrigin[0].id;
    const related = list.filter((t) => t && certFitsTab(url, t.url));
    if (related.length === 1) return related[0].id;
    if (activeTab && activeTab.id >= 0 && certFitsTab(url, activeTab.url)) {
      return activeTab.id;
    }
  }
  // securityInfo events often have tabId -1; pin to the focused tab
  if (activeTab && activeTab.id >= 0) return activeTab.id;
  return -1;
}
