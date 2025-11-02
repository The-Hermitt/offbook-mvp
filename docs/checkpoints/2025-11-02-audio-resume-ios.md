# OffBook — Checkpoint LOG (Audio Lost After App Switch • iPhone Safari)

## Summary
**Issue:** After leaving OffBook (e.g., to Photos) and returning, **READER audio** in **Rehearse/Record** was silent and **3-2-1 beeps** were missing.  
**Status:** ✅ **Resolved**. The app now survives iOS background/return with reliable READER playback and count-in beeps.

---

## Symptoms (as reported)
- Rehearse: Partner audio silent after returning from another app; Play appears to “stall.”
- Record: Pressing **REC** yields **no 3-2-1 beeps**, and reader doesn’t start.
- Re-render didn’t help; only a full reload sometimes restored audio.
- Repro was **iPhone Safari/PWA**, often after watching a video in **Photos**.

---

## Root Causes (what we learned)
1) **iOS “interrupted” audio state**  
   After another app plays audio, WebKit may leave `AudioContext` (global and reader) in **`interrupted`** (not just `suspended`). `context.resume()` alone can fail; contexts sometimes must be **rebuilt**.

2) **HTMLMediaElement pipeline inert after BFCache return**  
   `<audio>` can appear fine but never emit audio again until fully **revived** (clear/remove `src`, `.load()`, re-set with a cache-buster, `.load()` again).

3) **Multiple readers + wrong target**  
   Both `E.rehearseAudio` and `#readerAudio` exist; earlier resume logic only targeted one.

4) **Duplicate helper functions later in file**  
   A second `ensureReaderCtx()` (and others) **overrode** the fixed versions, removing health checks/rebuilds and undoing patches.

5) **Gesture/autoplay policies on iOS**  
   Beeps and play can be blocked post-return unless the pipeline is re-primed from a **user gesture**.

---

## Attempt History (what we tried)
- Simple resume: `AudioContext.resume()` + `element.load()` → intermittent.
- Resume-on-return hooks: `visibilitychange` / `pageshow` → improved, still failed for “interrupted”.
- Count-in gating: resume before beeps → still silent if context stayed interrupted.
- Active reader routing: switch target per tab → reduced misses, not sufficient.
- **Context rebuilds**: detect unhealthy contexts and **recreate** → major improvement.
- **Media revival**: clear/reset `src` with cache-buster → reliably reanimated HTMLAudio.
- **Silent WebAudio poke** (1-frame buffer from user tap) → re-primes iOS output route.
- **On-device debug overlay** (`?debug=1`) → confirmed states without desktop tools.

---

## Final Fix (what actually solved it)
**A. Robust resume pipeline**
- `isCtxHealthy(ctx)` + **rebuild** functions for **main** and **reader** contexts when not `running` (incl. `interrupted`).
- `resumeMediaPipeline(reason)` ensures/rebuilds contexts then **revives all reader elements**: remember `src` → remove `src` → `.load()` → re-set with `?revive=<ts>` → `.load()`.

**B. “First-tap unlock” with silent WebAudio poke**
- `oneShotUnlock()` runs on initial **Play/Render/REC** click:
  - `resumeMediaPipeline(...)`
  - **`silentPoke()`** (128-frame silent buffer) to warm the iOS route without autoplaying.

**C. Correct reader targeting**
- `setActiveReader(el)` + `getAllReaderEls()` cover **both** Rehearse and Record readers.
- On tab switch: point to `E.rehearseAudio` (Rehearse) or `R.audio` (Record).

**D. Duplicate-removal & guardrails**
- Removed **later** duplicates of `ensureReaderCtx()`, `micConstraints()`, `preloadReaderBuffers()`.
- Added “**Do not redefine**” comments to prevent regressions.

**E. Entry-point coverage**
- Call `resumeMediaPipeline()`/`silentPoke()`:
  - on **tab enter** (Rehearse/Record),
  - **before Play**,
  - **before REC/count-in**,
  - on **pageshow** / visibility return (prep only; no autoplay).

---

## Audio Routes (what mattered)
- Headphones (A2DP) vs HFP “call mode” can cause mute; we avoid SR on iOS and stabilize mic setup to keep A2DP.  
- “Headphones: On” is recommended to avoid echo/ducking.

---

## How to Reproduce & Verify (phone-only)
1) Open: `…/app-tabs.html?secret=1976&debug=1` → overlay shows `[ctx]` and `[reader]`.
2) Rehearse → Render (if needed) → **Play** (hear partner).
3) Home → open **Photos**, play a video w/ audio ~10s.
4) Return → tap **Play** once. If silent, tap **Probe** (runs `silentPoke`) and try Play again.
5) Record → **REC** → hear **3-2-1** beeps → reader starts.

---

## “If it happens again” — Triage Steps
1) **Overlay check** (`?debug=1`): ensure `[ctx] running`, `[reader] running` post-tap; if not, hit **Probe**.  
2) **Asset headers** (tunnels/proxies): MP3s must serve
   - `Content-Type: audio/mpeg`
   - `Accept-Ranges: bytes`
   - avoid `Content-Disposition: attachment`
3) **Headphone route**: toggle “Headphones” once, retry Play/REC.
4) **Hard reload** as last resort.

---

## Limitations (Web vs Native)
- **Web (iOS Safari/PWA):** No official “interruption” events; rely on **resume + rebuild + silent poke**. Works with our guardrails.  
- **Native (iOS):** `AVAudioSession` provides interruption/route callbacks; recovery is deterministic. Consider a thin native shell if mission-critical.

---

## Guardrails to Keep
- Do **not** re-introduce duplicate audio helpers later in the file.
- Always revive **both** reader elements.
- Keep iOS SR disabled; use STT-lite timing only.
- Ensure resume hooks on tab-enter, Play, REC, and `pageshow`.

---

## Patch Artifacts to Search in `public/app-tabs.html`
- `isCtxHealthy`, `rebuildMainCtx`, `rebuildReaderCtx`
- `resumeMediaPipeline(reason)`
- `rememberSrc`, `reviveMediaEl`, `getAllReaderEls`, `setActiveReader`
- `oneShotUnlock`, `silentPoke`
- Debug overlay: `mountDebugOverlay`, `updateDebugOverlay` (gated by `?debug=1`)

---

## One-liner “What fixed it”
**Detect and rebuild interrupted contexts, revive all reader elements, and prime the iOS audio route with a user-gesture “silent poke” — on tab enter, play/REC, and when returning from background — while ensuring we target the correct reader element and avoid duplicate overrides.**
