/**
 * stt-lite.js — minimal timing-focused STT controller for OffBook.
 * Prefers Web Speech API. If unavailable, falls back to a timing-only window.
 * We only need end-of-speech timing to trigger the partner cue — no transcripts required.
 */
export function createSTT() {
  const hasWebSpeech = typeof window !== "undefined" && ("webkitSpeechRecognition" in window || "SpeechRecognition" in window);
  let rec = null, active = false, abortTimer = null;

  const clearAbortTimer = () => { if (abortTimer) { clearTimeout(abortTimer); abortTimer = null; } };

  function makeRecognizer(){
    const Ctor = window.SpeechRecognition || window.webkitSpeechRecognition;
    if(!Ctor) return null;
    const r = new Ctor();
    r.lang = "en-US";
    r.interimResults = true;
    r.continuous = true;
    r.maxAlternatives = 1;
    return r;
  }

  function start({ onPartial, onFinal, onStart, onStop, maxSilenceMs = 380 } = {}) {
    if (active) return;
    active = true;
    onStart?.();

    if (hasWebSpeech) {
      rec = makeRecognizer();
      if (!rec) { active = false; onStop?.(); return; }

      const resetSilenceWatch = () => {
        clearAbortTimer();
        abortTimer = setTimeout(() => {
          onFinal?.({ text: "", reason: "silence" });
          stop();
        }, maxSilenceMs);
      };

      rec.onresult = (e) => {
        resetSilenceWatch();
        for (let i = e.resultIndex; i < e.results.length; i++) {
          const res = e.results[i];
          const seg = res[0]?.transcript || "";
          if (!res.isFinal) onPartial?.({ text: seg });
          else onFinal?.({ text: seg, reason: "final" });
        }
      };
      rec.onerror = () => { stop(); };
      rec.onend = () => { stop(); };

      try { rec.start(); resetSilenceWatch(); } catch { stop(); }
    } else {
      // Fallback: timing-only “end-of-speech” feel
      clearAbortTimer();
      abortTimer = setTimeout(() => {
        onFinal?.({ text: "", reason: "timer" });
        stop();
      }, 1200);
    }
  }

  function stop() {
    if (!active) return;
    clearAbortTimer();
    try { rec?.stop?.(); } catch {}
    try { rec?.abort?.(); } catch {}
    rec = null;
    active = false;
    onMicrotask(() => onStop?.()); // schedule end-of-cycle
  }

  function onMicrotask(fn){ Promise.resolve().then(fn).catch(()=>{}); }

  function isActive(){ return active; }

  return { start, stop, isActive };
}
