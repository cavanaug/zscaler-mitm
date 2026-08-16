# Public CA classify — Design Spec

**Date:** 2026-08-16  
**Status:** Approved  
**Repo:** `zscaler-mitm` (this document). Not `wsl-dnssec`.  
**Approach:** Generalize the existing MV3 toolbar extension. Replace the hard-coded Zscaler issuer matcher with a public-CA list plus Name Constraint policy.

## Context

v1 turns the spy icon red when the active tab’s leaf TLS issuer is Zscaler (`cert.js` `isZscalerIssuer`). That is one intercepting CA. The Windows trust store on the author’s machine also contains unconstrained enterprise roots (Zscaler, HP, Poly, Intune). Those CAs can mint a cert for `mail.google.com` unless the **client** treats them as scoped.

X.509 Name Constraints (`2.5.29.30`) would be the technical scope limit, but the interesting roots here ship **without** that extension. Scope is therefore:

1. A **public CA baseline** (Chrome/Mozilla-class issuers) → treat as the real web PKI.
2. **RFC 5280 Name Constraints** on the issuer cert if Chromium includes it in the chain.
3. A **user overlay** of permitted DNS names per issuer, stored in the extension.

This spec replaces “is it Zscaler?” with those rules. Zscaler becomes an unconstrained alternate CA (red), not a special case.

## Goals

- Dark **green** spy icon when the leaf issuer matches the public CA list.
- **Blue** spy icon when a non-public issuer is constrained (cert NC and/or user overlay) and the tab hostname is in the permitted DNS set.
- **Red** spy icon when a non-public issuer has no constraints, or the hostname is outside them.
- **Yellow** when the cert cannot be read (unchanged).
- **Grey** (current default spy) when there is no HTTPS cert.
- Public list is a file **in this repo**, packed with the extension, and refreshed from **GitHub raw** of that same file.
- User can add permitted DNS names for the current tab’s issuer from the popup, and edit overlays on an options page.
- Chromium 144+ `securityInfoRawDer` as today. No new npm dependencies.

## Non-goals

- Fetching CCADB or Chrome Root Store at runtime (repo file only).
- Full certificate path building or AIA fetching.
- Using the live OS/browser trust store (that includes Zscaler).
- Tab-strip coloring, ZeroOmega, content scripts, `chrome.debugger`.
- Chrome Web Store pipeline changes beyond what already exists.
- Automatic “registrable domain” truncation in the popup (use the tab hostname; user edits in options).

## Success criteria

1. `https://mail.google.com` with a Google Trust Services (or other list) issuer → green; popup says public CA.
2. Same site with a Zscaler-issued leaf, no user overlay → red.
3. `https://www.hp.com` with an HP issuer and user overlay `hp.com` → blue.
4. `https://mail.google.com` with that same HP issuer and overlay → red (off-scope).
5. Non-public issuer whose chain issuer cert has permitted DNS covering the host, even with no overlay → blue.
6. GitHub raw fetch failure leaves classification unchanged (packed or last-good list); a Zscaler tab must not turn green.
7. HTTP / `chrome://` → grey + “Not HTTPS — no certificate”.
8. `node --test` covering classify + NC matching + list match passes.

## Classify rules

Hostname = URL host of the tab (lowercase, no trailing dot). Issuer = leaf subject-issuer Name (`CN`, `O`, `OU`).

**Public** = any of:

- leaf issuer `O` is in `public-cas.json` `organizations` (exact string), or
- leaf issuer `CN` is in `issuerCNs` (exact string), or
- a certificate in `securityInfo.certificates` has SPKI SHA-256 in `rootSpkis` (only when chain bytes exist).

**Constraints** for a non-public issuer = union of:

- RFC 5280 Name Constraints DNS permitted/excluded on the **issuer** certificate (`certificates[1]`) when present,
- user overlay `dns` entries for that issuer.

A `dns` entry `example.com` matches `example.com` and subdomains (`www.example.com`). Cert excluded subtrees still exclude. Combined permitted set **empty** on a non-public issuer → treat as unconstrained.

| Situation | Icon | Popup sense |
|-----------|------|-------------|
| Not HTTPS / `chrome://` / `file://` | grey | Not HTTPS — no certificate |
| Parse / missing `securityInfo` / no record yet | yellow | Same strings as v1 |
| Issuer is public | dark green | Public CA |
| Non-public, constraints exist, host in permitted DNS | blue | Private CA, in-scope |
| Non-public, no constraints, or host out of permitted / excluded | red | Unconstrained or off-scope intercepting CA |

Public issuers **skip** constraint logic (Let’s Encrypt / GTS with no NC stay green).

`isZscalerIssuer` is removed from product logic. Existing Zscaler DER fixtures become “not public, unconstrained → red” tests.

## Architecture

```text
HTTPS navigation
    → background.js  webRequest + securityInfoRawDer
    → cert.js        leaf (+ issuer cert in chain if present)
                       subject/issuer names; optional Name Constraints
    → classify(issuer, hostname, publicCas, userPolicies)
         public list hit                    → green
         constraints cover host             → blue
         otherwise non-public               → red
    → chrome.storage.session[tabId]
    → setIcon  grey | yellow | green | blue | red

public-cas.json  (git + extension package)
    ← fetch GitHub raw of the same path (startup + every 24h)
    ← chrome.storage.local last-good; else packed copy

user overlays    chrome.storage.sync
    { O, CN?, dns[] }
```

Listen and per-tab session behavior stay as v1 (`main_frame` preferred, subresource only if no success yet, never throw from the service worker).

## Components

| File | Job |
|------|-----|
| `cert.js` | DER parse (leaf names; issuer cert NC when given). `classify`. Overlay host match. |
| `public-cas.json` | Generated public baseline (committed). |
| `scripts/update-public-cas` | Rebuild JSON from CCADB (roots **and** intermediates, websites/TLS). Human runs it; commit the result. |
| `background.js` | Parse, classify, icons, list refresh, persist tab records. |
| `popup.html` / `popup.js` | Fields + verdict; “Allow this issuer for `<host>`” when not public. |
| `options.html` / `options.js` | CRUD overlays; show list `generatedAt` and last refresh. |
| `manifest.json` | `options_page`; `storage`; host permission for GitHub raw of this repo. |
| `icons/` | Add `green-*` and `blue-*` PNG tints from `source-spy.png` (16/32 toolbar; 48/128 manifest as needed). |
| `test/cert.test.js` | Parser + classify table. |

No new npm packages. Makefile target to regenerate icon tints if one already exists for default/yellow/red.

## `public-cas.json` shape

```json
{
  "version": 1,
  "generatedAt": "2026-08-16T00:00:00Z",
  "source": "ccadb-intermediates+roots",
  "organizations": ["DigiCert Inc", "Google Trust Services"],
  "issuerCNs": ["WE2"],
  "rootSpkis": ["base64-or-hex-sha256"]
}
```

Generation uses CCADB public CSV (roots and intermediates with websites/TLS trust), not a live Salesforce fetch from the extension. The committed file is the source of truth. Refresh URL is the GitHub **raw** URL of this file on `master` of this repo (option A). Success overwrites `chrome.storage.local`. Failure: last good, then packed copy. Fetch failure must not classify alternate CAs as public.

## User overlay

```json
{ "O": "HP Inc", "CN": null, "dns": ["hp.com", "hpe.com"] }
```

Match overlay to issuer by `O`; if `CN` is non-null it must match too. Popup “Allow this issuer for `<tab host>`” merges that host into `dns` (create overlay if needed). Options page can add, edit, delete names and issuers.

## Icon assets

Same spy silhouette. Fills:

- `default-*`: grey (no TLS)
- `yellow-*`: cannot tell
- `green-*`: public CA
- `blue-*`: constrained private CA, in-scope
- `red-*`: unconstrained or off-scope

Toolbar still 16 and 32 via `setIcon`.

## Data flow

1. HTTPS `onHeadersReceived` → leaf (+ optional chain) DER.
2. Parse names; parse NC from issuer cert if present.
3. Load public list (local cache / packed) and user overlays.
4. `classify` → record `{ url, subject, issuer, verdict, error, … }` with `verdict` in `public | in-scope | intercept |` plus existing error kinds.
5. Active tab → `setIcon`.
6. Popup reads record; may write an overlay then re-classify is not required until next navigation (acceptable: tell the user to reload, or re-run classify on the stored issuer + new overlay for the current tab — prefer re-run on the stored record so the icon updates immediately).
7. Options edits apply on next classify; if a tab record exists, re-classify that tab after overlay change.

## Error handling

- Service worker never throws out to the browser.
- Missing chain → skip cert NC and root SPKI; still use `O`/`CN` list + overlays.
- Malformed `public-cas.json` (packed or fetched) → ignore the bad copy, keep previous good, else empty list (everything non-parseable stays yellow; unlisted issuers red — do **not** fail open to green).
- No `storage.sync` (rare) → fall back to `storage.local` for overlays.

## Testing

`node --test` only. Cover:

| Case | Expect |
|------|--------|
| Issuer `O` in `organizations` | green / public |
| Issuer `CN` in `issuerCNs` | green / public |
| Chain root SPKI in `rootSpkis` | green / public |
| Zscaler-like `O`, no NC, no overlay | red |
| Subject Zscaler, issuer DigiCert | green (public issuer) |
| HP `O` + overlay `hp.com` + host `www.hp.com` | blue |
| Same overlay + host `mail.google.com` | red |
| Cert permitted DNS `.hp.com`, no overlay, host `hp.com` | blue |
| Fetch/list failure must not turn unconstrained issuer green | red still |

Keep current DER fixtures; add minimal synthetic NC cases if the parser grows (or table-driven classify tests with already-parsed names/NC so DER NC parse can be a thin extra).

Manual checklist in README: green on a public HTTPS site, red on Zscaler, blue after allowing HP for `hp.com`, grey on `chrome://`, yellow before reload.

## Product decisions

| Decision | Choice |
|----------|--------|
| Baseline list | File in git, generated from CCADB offline |
| Runtime refresh | GitHub raw of that file, 24h + startup |
| Live CCADB/Chrome CDN | No |
| Public match | Issuer `O`, issuer `CN`, optional root SPKI |
| User NC | Overlay `dns[]` per issuer `O` (+ optional `CN`) |
| Cert NC | Parse from issuer cert in chain when present; union with overlay |
| In-scope private icon | Blue (not light green) |
| Public CA icon | Dark green |
| Unconstrained / off-scope | Red |
| v1 Zscaler special-case | Removed |

## Open implementation notes (not TBD product)

- Exact GitHub raw URL is `https://raw.githubusercontent.com/<owner>/<repo>/master/public-cas.json` once `origin` is known at implement time.
- `rootSpkis` encoding (hex vs base64) picked in the update script and documented in the script header; classify must use the same.
- Icon tint pipeline: reuse whatever v1 used to derive yellow/red from `source-spy.png`.
