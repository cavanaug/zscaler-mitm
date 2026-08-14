# Zscaler MITM — Design Spec

**Date:** 2026-08-14  
**Status:** Approved  
**Approach:** Tiny standalone MV3 extension (not a ZeroOmega/SwitchyOmega fork)

## Context

Zscaler SSL inspection presents a locally trusted cert whose **issuer** is Zscaler, not the site’s real CA. The user wants a toolbar signal when the **active tab** is under that MITM, without changing the tab strip.

This lives next to `xml-tree/` in the `brave-extensions` repo. Load unpacked in Brave/Chrome the same way.

ZeroOmega is a proxy switcher. It does not expose certificate fields, and its toolbar icon already means “active proxy profile.” Forking it does not help.

## Goals

- Toolbar **action icon** (pinned / visible in Chrome’s main UI) turns **red** when the active tab’s HTTPS leaf cert is issued by Zscaler.
- Same icon stays **default** when the cert is not Zscaler (or there is no TLS).
- Icon turns **yellow** when the extension cannot tell (error / missing API / no record yet).
- Clicking the icon opens a popup showing subject and issuer **CN / O / OU**.
- Personal unpacked extension; Chromium 144+ (`webRequest` `securityInfoRawDer`).

### Non-goals (v1)

- Forking or integrating ZeroOmega / SwitchyOmega
- Coloring or badging the tab itself
- Origin/hostname cache (beyond per-tab session state)
- Options page, content scripts, native messaging, `chrome.debugger`
- Incognito (unless the user enables it on the extension card)
- Chrome Web Store publish
- Detecting Zscaler via HTTP headers or proxy profile

## Success criteria

1. Active tab with a Zscaler-issued HTTPS cert → red spy icon.
2. Active tab with a normal public CA → default spy icon (including a real `zscaler.com` cert issued by DigiCert or similar).
3. Popup shows parsed subject + issuer CN/O/OU and whether it matched.
4. Parse failure, missing `securityInfo`, or no stored record → yellow spy icon + an explanatory popup line.
5. HTTP / `chrome://` / `file://` → default spy icon + “Not HTTPS — no certificate”.
6. `node --test` (or equivalent assert file) covering `cert.js` passes.

## Product decisions

| Decision | Choice |
|----------|--------|
| Where the signal lives | Extension toolbar action icon only |
| Clean HTTPS | Default spy icon (not green) |
| Zscaler issuer | Red spy icon |
| Can’t tell | Yellow spy icon |
| Glyph | Spy/fedora silhouette (`icons/source-spy.png`), three tints |
| Click | Popup with subject + issuer CN/O/OU |
| Match target | **Issuer** only, not subject |
| Extra site cache | No — per-tab `chrome.storage.session` only |
| Distribution (v1) | Load unpacked |

## Match rule

Parse the **leaf** certificate (first entry in `securityInfo.certificates`). Read **issuer** CN, O, OU.

Treat as Zscaler if **any** of:

1. issuer O is exactly `Zscaler Inc.`
2. issuer OU is exactly `Zscaler Inc.`
3. issuer CN starts with `Zscaler Intermediate Root CA`

Rule 3 covers `Zscaler Intermediate Root CA (zscalerthree.net) (t)` and the same pattern on other Zscaler clouds (`zscalerone.net`, `zscalertwo.net`, `zscaler.net`, `zscloud.net`, …).

Do **not** match on subject. A legitimate `zscaler.com` leaf is issued *to* Zscaler by a public CA; a MITM leaf is issued *by* Zscaler’s intermediate.

## Architecture

```text
HTTPS main_frame navigation
        │
        ▼
 service worker: background.js
   webRequest.onHeadersReceived + securityInfoRawDer
        │
        ▼
 cert.js
   DER → { subject: {CN,O,OU}, issuer: {CN,O,OU} }
   isZscalerIssuer(issuer) → boolean
        │
        ▼
 chrome.storage.session[tabId] = { url, subject, issuer, zscaler, error }
        │
        ├── tabs.onActivated / onRemoved → setIcon (default | yellow | red)
        └── action popup → read active tab record and render
```

Chrome 144+ `SecurityInfo` gives fingerprints plus optional `rawDER`, not Firefox-style subject/issuer strings. Parse those three fields from the leaf DER (tiny walker, no library).

`onHeadersReceived` is filtered to `main_frame`. Subresource requests are ignored. Compute is one leaf parse per top-level navigation; an origin cache would save nothing and can go stale when Zscaler starts or stops.

## Components

| File | Job |
|------|-----|
| `manifest.json` | MV3, `action` (icons + popup), service worker, `webRequest`, `storage`, host `https://*/*` |
| `background.js` | Listen, parse, persist per tab, set icon on activate/remove |
| `cert.js` | DER parse + `isZscalerIssuer` |
| `popup.html` / `popup.js` | Show current tab’s stored fields + match/error line |
| `icons/` | Spy silhouette PNGs: `default` / `yellow` / `red` at 16, 32, 48, 128; master `source-spy.png` |
| `test/cert.test.js` | Node asserts for parser + matcher |
| `README.md` | Load unpacked + manual Brave checklist |

No options page. No content scripts. No new npm dependencies.

## Data flow

1. HTTPS `main_frame` `onHeadersReceived` includes `securityInfo`.
2. Parse leaf `rawDER` → subject + issuer; run `isZscalerIssuer`.
3. Write `chrome.storage.session` keyed by `tabId`.
4. If that tab is active, `chrome.action.setIcon` to default / yellow / red.
5. `tabs.onActivated`: read that tab’s record (or yellow if none) and set the icon.
6. `tabs.onRemoved`: delete the record.
7. Popup: `tabs.query({ active: true, currentWindow: true })`, read that record, render.

Service worker restarts: session storage keeps the per-tab map. If the page loaded before the extension, there is no record until the next navigation (yellow + “Reload the tab to inspect the certificate”).

## Icon asset

Master glyph: `icons/source-spy.png` (solid fedora spy silhouette). Not MDI glasses; not the iStock spyware stop-sign.

Transparent background, pad to square. One silhouette, three fills:

- `default-*`: original dark gray/black (toolbar-neutral)
- `yellow-*`: warning
- `red-*`: Zscaler match

Chrome sizes (PNG RGBA):

| Use | Files |
|-----|--------|
| Toolbar `action` / `setIcon` | 16 and 32 |
| Manifest `icons` | 48 and 128 |

Filenames: `{default,yellow,red}-{16,32,48,128}.png`.

## Icon states

| Case | Icon | Popup |
|------|------|--------|
| HTTPS, issuer is not Zscaler | default spy | Subject + issuer fields, not matched |
| Issuer matches Zscaler | red spy | Subject + issuer fields, matched |
| Parse failure | yellow spy | “Couldn’t parse certificate” |
| No `securityInfo` (Chromium older than 144) | yellow spy | “Needs Chrome/Brave 144+” |
| No stored record yet | yellow spy | “Reload the tab to inspect the certificate” |
| HTTP / `chrome://` / `file://` | default spy | “Not HTTPS — no certificate” |

Never throw out of the service worker. Icon updates must not depend on the popup being open.

## Testing

One Node test file, no Playwright, no extra deps.

| Fixture | Expect |
|---------|--------|
| issuer O = `Zscaler Inc.` | match |
| issuer OU = `Zscaler Inc.` | match |
| issuer CN = `Zscaler Intermediate Root CA (zscalerthree.net) (t)` | match |
| same CN with `zscalerone.net` / `zscalertwo.net` | match |
| subject O = `Zscaler Inc.`, issuer = DigiCert | **no match** |
| garbage bytes | parse error, no uncaught throw |

Manual Brave checklist in the README: load unpacked, pin the icon, HTTPS tab default vs red, error/reload yellow, popup fields.

## Out of scope (v1)

- Web Store, update pipeline, i18n
- Matching Zscaler HTTP headers or proxy PAC
- `chrome.debugger` fallback for old Chromium
- Per-origin disk cache
- Incognito by default
