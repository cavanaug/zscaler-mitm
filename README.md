# Zscaler MITM

Toolbar icon that turns **red** when the active tab’s TLS certificate is issued by Zscaler, **yellow** when the extension cannot tell, and stays the default spy icon otherwise. Click the icon to see subject and issuer CN / O / OU.

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

- [ ] Pin the icon. Open `https://example.com` — default spy icon; popup shows a non-Zscaler issuer
- [ ] On a Zscaler-intercepted HTTPS tab — red spy icon; popup issuer O/OU/CN matches Zscaler
- [ ] Open `chrome://extensions` or an `http://` page — default spy icon; popup says “Not HTTPS — no certificate”
- [ ] Load the extension, then click an already-open HTTPS tab without reloading — yellow; popup says “Reload the tab to inspect the certificate”; reload — icon updates
- [ ] Browser shows no Manifest V2 / “no longer supported” warning

## Out of scope (v1)

- ZeroOmega / proxy switching
- Coloring the tab itself
- Chrome Web Store
