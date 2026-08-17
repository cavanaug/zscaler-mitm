export async function loadOverlays() {
  let local = [];
  try {
    const got = await chrome.storage.local.get('overlays');
    if (Array.isArray(got.overlays)) local = got.overlays;
  } catch {
    // local unavailable
  }
  if (local.length) return local;
  try {
    const got = await chrome.storage.sync.get('overlays');
    if (Array.isArray(got.overlays)) return got.overlays;
  } catch {
    // sync unavailable
  }
  return local;
}

export async function saveOverlays(overlays) {
  await chrome.storage.local.set({ overlays });
  try {
    await chrome.storage.sync.set({ overlays });
  } catch {
    // managed Chrome often blocks sync; local is enough
  }
}
