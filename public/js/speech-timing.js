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
  const since = performance.now() - (lastAdvanceAt || 0);
  if (since <= AFTER_ADV_COOLDOWN_MS) return false;

  const t = (text || "").trim();
  const min = expectedMinMsFor(t);

  const interimNorm = (interim || "").trim();
  const hasTranscript = interimNorm.length > 0;

  const charLen = t.length;
  const sentenceCount = t.split(/[.!?]/).filter(s => s.trim().length > 0).length;
  const isComplex = charLen > 60 || sentenceCount > 1;

  let silentThreshold;
  let timeThreshold;

  if (!isComplex) {
    // Preserve previous behavior for short/simple lines.
    silentThreshold = Math.min(min, 800);
    timeThreshold = min;
  } else if (hasTranscript) {
    // We have speech recognition: be slightly stricter but still responsive.
    silentThreshold = Math.max(min, 900);
    timeThreshold = Math.round(min * 1.2);
  } else {
    // No transcript (iOS case): be conservative to avoid cutting off multi-sentence lines.
    silentThreshold = Math.max(Math.round(min * 1.4), 1400);
    timeThreshold = Math.round(min * 1.6);
  }

  const silentOk = isSilentNow && elapsedMs > silentThreshold;
  const timeOk = hasTranscript && elapsedMs > timeThreshold;

  const ratio = progressRatio(t, interimNorm);

  // Treat dash-ending lines the same as everything else for now.
  // This avoids "hanging" on lines like:
  //   "Or happier. A time when you were—"
  //
  // If we want a special dash rule later, we can reintroduce it with
  // much softer thresholds; but the priority is never getting stuck.
  const interimOk = ratio >= 0.72;

  return silentOk || timeOk || interimOk;
}
