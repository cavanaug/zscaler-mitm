# Popup Debug Toggle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Hide the popup debug dump by default, toggle it with a Debug / Hide debug link, and remember the choice in `chrome.storage.session` for the browser session only.

**Architecture:** Tiny pure helper applies visibility + link label. Popup reads/writes `showDebug` in session storage. HTML adds a muted link; `#debug` stays in the DOM.

**Tech Stack:** Vanilla JS MV3 popup, `chrome.storage.session`, Node `node:test` (no new deps).

**Spec:** `docs/superpowers/specs/2026-08-21-popup-debug-toggle-design.md`

**Working directory:** `/home/cavanaug/wip_other/projects/zscaler-mitm`

## Global Constraints

- No new permissions (already has `storage`).
- Prefer `chrome.storage.session`, not `local`.
- Default off when key missing.
- No hotkeys / `commands`.
- No change to `formatCaptureDebug` output.
- Do not commit unless the user explicitly asks (repo commit policy).

---

## File map

| Path | Responsibility |
|------|----------------|
| `debug.js` | Add `applyDebugVisibility(show, debugEl, linkEl)` |
| `popup.html` | Debug toggle link + light link CSS; `#debug` unchanged content |
| `popup.js` | Load/save `showDebug`; wire click; paint debug only when shown |
| `popup-boot.js` | If module never starts, unhide `#debug` so the failure message is visible |
| `test/debug.test.js` | Unit tests for `applyDebugVisibility` |
| `test/popup-boot.test.js` | Assert link + boot unhide behavior |

---

### Task 1: `applyDebugVisibility` helper

**Files:**
- Modify: `debug.js`
- Modify: `test/debug.test.js`

**Interfaces:**
- Consumes: none
- Produces: `export function applyDebugVisibility(show, debugEl, linkEl)` — sets `debugEl.hidden = !show`, `linkEl.textContent = show ? 'Hide debug' : 'Debug'`

- [ ] **Step 1: Write the failing test**

Append to `test/debug.test.js`:

```javascript
import { applyDebugVisibility, formatCaptureDebug } from '../debug.js';

test('applyDebugVisibility toggles hidden and link label', () => {
  const debugEl = { hidden: false };
  const linkEl = { textContent: '' };
  applyDebugVisibility(false, debugEl, linkEl);
  assert.equal(debugEl.hidden, true);
  assert.equal(linkEl.textContent, 'Debug');
  applyDebugVisibility(true, debugEl, linkEl);
  assert.equal(debugEl.hidden, false);
  assert.equal(linkEl.textContent, 'Hide debug');
});
```

(Keep existing `formatCaptureDebug` import/usage; merge imports into one line.)

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test test/debug.test.js`

Expected: FAIL — `applyDebugVisibility` not exported.

- [ ] **Step 3: Write minimal implementation**

In `debug.js`, export:

```javascript
export function applyDebugVisibility(show, debugEl, linkEl) {
  if (debugEl) debugEl.hidden = !show;
  if (linkEl) linkEl.textContent = show ? 'Hide debug' : 'Debug';
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test test/debug.test.js`

Expected: PASS (all tests in file).

- [ ] **Step 5: Commit** — skip unless the user asked to commit.

---

### Task 2: Wire popup HTML + session toggle + boot unhide

**Files:**
- Modify: `popup.html`
- Modify: `popup.js`
- Modify: `popup-boot.js`
- Modify: `test/popup-boot.test.js`

**Interfaces:**
- Consumes: `applyDebugVisibility` from `debug.js`
- Session key: `showDebug` (boolean) in `chrome.storage.session`
- Produces: link `#debug-toggle` toggles visibility and persists flag

- [ ] **Step 1: Extend popup-boot HTML test (failing)**

Update `test/popup-boot.test.js` to also assert:

```javascript
assert.match(html, /id="debug-toggle"/);
assert.match(html, />Debug</);
const boot = readFileSync(join(root, 'popup-boot.js'), 'utf8');
assert.match(boot, /popup\.js did not start/);
assert.match(boot, /\.hidden\s*=\s*false/);
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test test/popup-boot.test.js`

Expected: FAIL — no `debug-toggle` / no boot `.hidden = false`.

- [ ] **Step 3: Update `popup.html`**

Add CSS:

```css
#debug-toggle {
  display: inline-block;
  margin-top: 10px;
  font-size: 12px;
  color: #666;
  cursor: pointer;
  text-decoration: underline;
  background: none;
  border: none;
  padding: 0;
  font: inherit;
}
```

Before `<pre id="debug">`, add:

```html
<button type="button" id="debug-toggle">Debug</button>
```

Keep `<pre id="debug">starting…</pre>` (do not put `hidden` in HTML — JS applies default off after load so boot can still reveal failures).

- [ ] **Step 4: Update `popup-boot.js`**

```javascript
setTimeout(function () {
  var d = document.getElementById('debug');
  if (d && d.textContent === 'starting…') {
    d.hidden = false;
    d.textContent = 'popup.js did not start — reload the extension on chrome://extensions';
  }
}, 2000);
```

- [ ] **Step 5: Wire `popup.js`**

Import `applyDebugVisibility` from `./debug.js`.

Near top of module state (or inside `main`):

```javascript
const DEBUG_KEY = 'showDebug';
let showDebug = false;

function paintDebug(state) {
  if (!showDebug) return;
  document.getElementById('debug').textContent = formatCaptureDebug(state);
}

async function initDebugToggle() {
  const got = await chrome.storage.session.get(DEBUG_KEY);
  showDebug = got[DEBUG_KEY] === true;
  applyDebugVisibility(showDebug, document.getElementById('debug'), document.getElementById('debug-toggle'));
  document.getElementById('debug-toggle').addEventListener('click', async () => {
    showDebug = !showDebug;
    applyDebugVisibility(showDebug, document.getElementById('debug'), document.getElementById('debug-toggle'));
    await chrome.storage.session.set({ [DEBUG_KEY]: showDebug });
    // if turning on after paintAll, caller should re-paint; store last state or re-read
  });
}
```

In `main()`, before `paintAll(state)`:

1. `await initDebugToggle()` but **without** the click handler closing over missing state — better structure:

```javascript
async function main() {
  document.getElementById('debug').textContent = 'popup.js running…';
  // ... tab query + readState + overlays as today ...

  const got = await chrome.storage.session.get(DEBUG_KEY);
  showDebug = got[DEBUG_KEY] === true;
  const debugEl = document.getElementById('debug');
  const toggle = document.getElementById('debug-toggle');
  applyDebugVisibility(showDebug, debugEl, toggle);

  paintAll(state);
  // ... existing wireGrantRecapture / apply-icon / probe / allow ...

  toggle.addEventListener('click', async () => {
    showDebug = !showDebug;
    applyDebugVisibility(showDebug, debugEl, toggle);
    await chrome.storage.session.set({ [DEBUG_KEY]: showDebug });
    if (showDebug) paintDebug(state);
  });
}
```

Keep module-level `let showDebug = false` and update `paintDebug` to no-op when `!showDebug` so `paintAll` / `probeIfNeeded` stay correct.

- [ ] **Step 6: Run tests**

Run: `node --test test/popup-boot.test.js test/debug.test.js`

Expected: PASS.

Run full suite: `npm test` (or `node --test test/*.test.js`)

Expected: all PASS.

- [ ] **Step 7: Manual smoke**

1. Reload unpacked extension.
2. Open popup — no debug dump; link says `Debug`.
3. Click `Debug` — dump appears; label `Hide debug`.
4. Close and reopen popup — dump still visible.
5. Fully quit browser and reopen — dump hidden again.

- [ ] **Step 8: Commit** — skip unless the user asked to commit.

---

## Spec coverage

| Spec requirement | Task |
|------------------|------|
| Default hidden | Task 2 (`showDebug === true` only) |
| Debug / Hide debug link | Tasks 1–2 |
| `chrome.storage.session` | Task 2 |
| No new permissions / hotkeys | Global constraints |
| Boot failure still visible | Task 2 `popup-boot.js` |

## Placeholder scan

None.
