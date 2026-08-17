# Privacy policy — Zscaler MITM

Zscaler MITM is a browser extension that classifies the current tab’s HTTPS certificate issuer and shows a toolbar signal: public CA, constrained private CA, or unconstrained intercepting CA.

## Data we do not collect

This extension does not collect, sell, share, or transmit personal data or browsing history. There is no analytics, account, or remote server operated by the extension. The only network request is a GET of a static JSON file (see below).

## Data stored on your device

- **`chrome.storage.session`** — per-tab certificate summary: tab URL, certificate subject and issuer CN / O / OU, classification verdict, and a short error if the certificate could not be read. Discarded when the browser session ends.
- **`chrome.storage.sync`** — issuer DNS overlays you add (`{ O, CN, dns[] }`), synced across signed-in browsers when Chrome sync is available. If sync is unavailable, the same overlays are stored in **`chrome.storage.local`** instead.
- **`chrome.storage.local`** — cached copy of the public CA list (`publicCas`, `publicCasFetchedAt`) after a refresh from GitHub; overlay fallback when sync is unavailable.

This data stays on your device and is not sold or shared.

## Network access

The extension may GET `https://raw.githubusercontent.com/cavanaug/zscaler-mitm/master/public-cas.json` to refresh a list of public CA organization names, issuer CNs, and root SPKI hashes. That file contains certificate-issuer metadata only — not executable code and not your browsing history. The JSON is parsed as data; it is never executed as remote code.

## Permissions

- **HTTPS site access** — so the extension can read the leaf TLS certificate of the tab you are viewing. It does not read page content, cookies, or form data.
- **GitHub raw host access** — for the `public-cas.json` GET described above.
- **webRequest** — observational only, to obtain `securityInfoRawDer`. Requests and responses are not modified.
- **tabs** — to match the toolbar icon and popup to the active tab.
- **storage** — for the on-device data described above.

## Contact

Questions: open an issue on the project repository if it is public, or contact the developer who provided this extension.
