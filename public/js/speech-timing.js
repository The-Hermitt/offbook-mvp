// Shared speech timing heuristics for OffBook rehearsal + record flows.
// DO NOT TUNE in Record; Rehearse is the source of truth.

export const AFTER_ADV_COOLDOWN_MS = 380;

export function expectedMinMsFor(t = "") {
  const n = (t || "").trim().length;
  if (n <= 5) return 260;
  if (n <= 15) return 550;
  if (n <= 40) return 900;
  return 1100;
}

// Tight end-of-line dash check (em/en/hyphen) — no middle/beginning matches
export function endsWithDashy(text = "") {
  const t = String(text || "").trim();
  return /[\u2014\u2013-]$/.test(t);
}

export function isSpeaking(energySamples = []) {
  if (!Array.isArray(energySamples) || !energySamples.length) return false;
  let max = 0;
  for (const sample of energySamples) {
    const v = Math.abs(sample || 0);
    if (v > max) max = v;
  }
  return max >= 0.032;
}

// Require some progress before allowing dash cut-in to avoid early false positives
export function progressRatio(lineText = "", interim = "") {
  const a = (lineText || "").toLowerCase().replace(/[^a-z0-9' ]+/g, " ").trim();
  const b = (interim || "").toLowerCase().replace(/[^a-z0-9' ]+/g, " ").trim();
  if (!a.length) return 0;
  return Math.min(1, b.length / a.length);
}

export function readyForAdvance({
  text = "",
  interim = "",
  isSilentNow = false,
  elapsedMs = 0,
  lastAdvanceAt = 0,
  dashyMode = false
} = {}) {
  const min = expectedMinMsFor(text);
  const since = performance.now() - (lastAdvanceAt || 0);
  if (since <= AFTER_ADV_COOLDOWN_MS) return false;

  const silentOk = isSilentNow && elapsedMs > Math.min(min, 800);
  const timeOk = elapsedMs > min;

  const ratio = progressRatio(text, interim);
  const dashAtEnd = dashyMode && endsWithDashy(text);
  const dashCutIn = dashAtEnd && ratio >= 0.30 && isSilentNow && elapsedMs > 140;
  const interimOk = ratio >= 0.72;

  return dashCutIn || silentOk || timeOk || interimOk;
}
