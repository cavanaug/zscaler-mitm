# Privacy policy — Zscaler MITM

Zscaler MITM is a browser extension that shows a toolbar warning when the current tab’s HTTPS certificate is issued by Zscaler.

## Data we do not collect

This extension does not collect, sell, share, or transmit personal data. There is no analytics, account, or remote server.

## Data stored on your device

The extension stores a per-tab certificate summary in `chrome.storage.session`: the tab URL, certificate subject and issuer CN / O / OU, whether the issuer matched Zscaler, and a short error if the certificate could not be read. This data stays on your device for the browser session and is discarded when the session ends. It is not synced.

## Permissions

- **HTTPS site access** — so the extension can read the leaf TLS certificate of the tab you are viewing. It does not read page content, cookies, or form data.
- **webRequest** — observational only, to obtain `securityInfoRawDer`. Requests and responses are not modified.
- **tabs** — to match the toolbar icon and popup to the active tab.
- **storage** — for the on-device session summary above.

## Contact

Questions: open an issue on the project repository if it is public, or contact the developer who provided this extension.
