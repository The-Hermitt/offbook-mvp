# OffBook — Checkpoint LOG Addendum (Audio Resume Watchdog • iPhone Safari)

## Context
Stubborn recurrence of **silent READER / missing 3-2-1 beeps** after switching to **iPhone Photos** (or returning from Gallery playback) and coming back to **Rehearse/Record**. Prior fixes handled most cases (resume contexts, revive <audio>, silent poke, staggered resume, network-aware revive, kill gallery playback), but a rare “wedged” state still surfaced.

## New Trigger Pattern Observed
- Return from Photos (BFCache) or from Gallery where a <video> recently played.
- First user gesture is NOT play/rec (e.g., tab change), so earlier unlocks may not run in time.
- Even after resume + revive + poke, the audio path remains **wedged** (decoders/contexts appear alive but output is zero).

## Root Cause (final 10%)
iOS can restore a page with:
- **AudioContext** objects reporting `running`, yet effectively **interrupted** in practice, or
- `<audio>` decoders that never output until **recreated** (fresh element) — especially after Media Session handoffs (Photos / inline video).
These states are not reliably detectable without measuring actual signal energy.

## Final Resolution (Watchdog + Hard Reset)
1) **Reader Path Probe**
   - `probeReaderPath(tag)` sends a tiny, short WebAudio ping and measures RMS via the existing analyser tap.
   - If RMS is below a threshold (e.g., `< 0.003`) after resume/poke, consider the stack **stuck**.

2) **Hard Reset (only if stuck)**
   - `hardResetAudioStack(reason)`:
     - Stops all audio, **closes** main & reader contexts, nulls references.
     - **Replaces `<audio>` elements** (`E.rehearseAudio`, `#readerAudio`) with fresh ones, preserving last src and cache-busting.
     - Rebuilds contexts, re-taps the graph, and runs a final **silent poke**.

3) **When it runs**
   - **On pageshow** (post-return, after staggered resume) → probe; if stuck → hard reset.
   - **On first pointer gesture anywhere** (global one-shot) → probe; if stuck → hard reset.
   - **On entering Rehearse/Record** → probe; if stuck → hard reset.

## Why This Works
- We don’t blindly reload; we **measure** actual audio energy.
- Only when the pipeline is truly wedged do we **recreate** contexts and media elements.
- Keeps prior layers (resume, revive, network-aware retry, gallery stop, silent poke) for fast paths.

## Guardrails (keep)
- No duplicate definitions of audio helpers later in the file.
- Always target **both** readers (Rehearse + Record) for revive/error.
- Continue staggered resume (`pageshow + 600–800ms`) to let tunnels wake.
- Maintain global first-gesture unlock.

## Field Test (phone-only)
1) Open `…/app-tabs.html?secret=1976&debug=1`.
2) Rehearse → Play (hear partner).
3) Photos → play any clip → return.
4) Tap anything (tab or button). If the stack is wedged, watchdog triggers, hard-resets, and audio is back on the next Play/REC.
5) Record → REC → hear **3-2-1** and reader.

## Rollback
- The watchdog only acts on a **detected stuck** state; no behavior change in healthy flow.
- To revert: comment out calls to `probeReaderPath()` / `hardResetAudioStack()` in `pageshow`, `pointerdown`, and tab-enter.
