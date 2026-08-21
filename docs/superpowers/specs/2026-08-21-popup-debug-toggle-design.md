# Popup debug toggle — Design Spec

**Date:** 2026-08-21  
**Status:** Approved  
**Approach:** Hide `#debug` by default; toggle via a text link; remember for the browser session only.

## Context

The popup always shows a dense `formatCaptureDebug` dump. That is useful when diagnosing capture/attach issues and noisy otherwise.

## Goals

- Debug block **hidden by default**.
- A muted **Debug** / **Hide debug** control toggles visibility.
- Preference stored in **`chrome.storage.session`** (survives popup close; clears when the browser fully quits → back to default off).
- No new permissions, no hotkey, no options-page change.

## Non-goals

- `chrome.storage.local` persistence across restarts.
- Manifest `commands` / global hotkeys.
- Changing the debug dump format.

## Behavior

1. On popup open, read `showDebug` from `chrome.storage.session`. Missing or false → hide `#debug`.
2. Link label: `Debug` when hidden, `Hide debug` when visible.
3. Click flips visibility, writes `showDebug`, updates label and `#debug.hidden`.
4. Still call `paintDebug` when visible (or always paint text while hidden — either is fine; prefer skip paint when hidden to avoid work).

## Files

- `popup.html` — add the link; `#debug` may start `hidden`.
- `popup.js` — load/toggle/persist session flag.
- One small test asserting the link exists and `#debug` can be hidden (static HTML and/or tiny unit helper if extracted).

## Success criteria

- Fresh browser session: popup opens with no debug dump visible, link says `Debug`.
- After toggle on: dump visible for the rest of the session across popup reopens.
- After full browser quit: dump hidden again.
