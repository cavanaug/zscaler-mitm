# Zscaler MITM

Toolbar icon that classifies the active tab’s TLS issuer: **dark green** for a public CA, **blue** for a constrained private CA on an allowed host, **red** for an unconstrained or off-scope intercepting CA, **yellow** when the certificate is not yet available, and **grey** on non-HTTPS pages. Click the icon to see subject and issuer CN / O / OU and the verdict line.

Requires Chrome, Brave, or Edge with Chromium **144+** and the **WebRequestSecurityInfo** flag enabled (`webRequest` `securityInfoRawDer`). The API is still off by default.

## Load unpacked

1. Open `chrome://extensions` (Brave: `brave://extensions` also works; Edge: `edge://extensions`)
2. Enable **Developer mode**
3. Click **Load unpacked** and select this folder
4. Pin **Zscaler MITM** to the toolbar
5. On the extension card, set **Site access** → **On all sites** (required for `webRequest` to see HTTPS)
6. Enable **WebRequestSecurityInfo**: `chrome://flags` → search that name → **Enabled** → restart. If the flag is not listed, launch with `--enable-features=WebRequestSecurityInfo`

## Test

```bash
npm test
```

No extra packages. Parser + match tests only; they do not launch a browser.

## Manual smoke checklist

- [ ] Public HTTPS site (`example.com`) — dark green spy; popup “Public CA”
- [ ] Zscaler-intercepted HTTPS — red; “Unconstrained or off-scope intercepting CA”
- [ ] After Allow on an HP (or other private) host — blue on that host; red on Gmail with that issuer
- [ ] `chrome://` or `http://` — grey; “Not HTTPS — no certificate”
- [ ] Already-open HTTPS tab without reload — yellow; reload updates
- [ ] Options page shows overlays and public-list `generatedAt`
- [ ] Browser shows no Manifest V2 / “no longer supported” warning

## Out of scope (v1)

- ZeroOmega / proxy switching
- Coloring the tab itself
- Chrome Web Store
