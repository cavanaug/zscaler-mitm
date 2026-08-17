/** Timed HEAD/GET so popup probe cannot hang the service worker reply. */
export async function probeFetch(url, fetchFn = fetch, ms = 4000) {
  let target = url;
  try {
    target = new URL(url).origin + '/';
  } catch {
    // use as-is
  }
  const once = (method) =>
    fetchFn(target, {
      method,
      cache: 'no-store',
      redirect: 'follow',
      signal: AbortSignal.timeout(ms),
    });
  try {
    await once('HEAD');
  } catch {
    try {
      await once('GET');
    } catch {
      // page may require cookies; user can reload
    }
  }
}
