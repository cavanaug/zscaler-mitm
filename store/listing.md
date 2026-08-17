# Chrome Web Store listing (paste-ready)

These are dashboard fields, not zip errors. Fill **Privacy practices**, upload a screenshot, then **Save draft**.

## Single purpose description

Show a toolbar signal when the current tab’s HTTPS certificate issuer is a public CA, a constrained private CA, or an unconstrained intercepting CA.

## Remote code

Select **No, I am not using remote code.**

If a text box is still required:

This extension does not execute remote code. All JavaScript, HTML, and icons ship inside the uploaded package. It does not fetch, eval, or inject scripts from the network. It may GET a static JSON file from GitHub (`public-cas.json`) containing public CA organization names, issuer CNs, and root SPKI hashes — certificate-issuer metadata only, not executable code.

## Host permission (`https://*/*`)

The extension must observe HTTPS responses on the active tab so Chromium can expose that tab’s leaf TLS certificate (`webRequest` `securityInfoRawDer`). Access is used only to read certificate subject and issuer CN / O / OU, classify the issuer, and color the toolbar icon. It does not read page content, cookies, or form data.

## Host permission (`https://raw.githubusercontent.com/cavanaug/zscaler-mitm/*`)

Used only to GET the raw `public-cas.json` file (public CA metadata). The response is parsed as JSON data; it is not executed as code. No browsing history is sent.

## `storage`

- **`chrome.storage.session`** — per-tab certificate summary (tab URL, subject CN/O/OU, issuer CN/O/OU, verdict, and a short error if the cert could not be read). Discarded when the browser session ends.
- **`chrome.storage.sync`** — user-defined issuer DNS overlays (`{ O, CN, dns[] }`), synced across signed-in browsers when sync is available; falls back to **`chrome.storage.local`** if sync is unavailable.
- **`chrome.storage.local`** — cached copy of `public-cas.json` after a GitHub refresh (`publicCas`, `publicCasFetchedAt`); overlay fallback when sync is unavailable.

Data stays on-device and is not sold or transmitted except the explicit GET of `public-cas.json` described above.

## `tabs`

Used to identify the active tab (id and URL) so the toolbar icon and popup show the certificate for the tab the user is looking at, not another tab.

## `webRequest`

`webRequest.onHeadersReceived` with `securityInfoRawDer` is the only Chromium API that exposes the leaf TLS certificate to an extension. The listener is observational: it does not block, redirect, or modify requests or responses.

## Data usage / certification

Check the box that your data usage complies with the Developer Program Policies.

This extension does not collect, sell, or transmit user browsing history. Certificate fields are stored only in on-device storage as described above. The only network fetch is GET of GitHub raw `public-cas.json` (issuer metadata).

## Homepage URL

Leave it **blank**.

Do not use `https://github.com/cavanaug/zscaler-mitm` — that repo is private, so the store’s reachability check fails.

If the form requires a URL, host a public HTTPS page (a public GitHub gist of `store/privacy.md`, or make the repo public) and paste that.

## Privacy policy URL (if the form asks)

Host `store/privacy.md` on a **public** HTTPS URL, then paste that URL. A private GitHub file will fail the same reachability check.

## Screenshot

Upload `store/screenshot-1280x800.png` (1280×800). Chrome Web Store requires at least one 1280×800 or 640×400 image.
