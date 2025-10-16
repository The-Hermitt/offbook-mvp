// @ts-nocheck
// src/lib/pdf.ts
//
// "Real" PDF parser with safe fallback.
// - Tries to parse with pdfjs-dist (Node-only).
// - Heuristics to detect SCENES + SPEAKERS and lines.
// - On any error or low-confidence parse, falls back to STUB.
//
// Output shape matches our REST routes:
//   Scene = { id, title, lines: [{ speaker, text }] }
//
// Notes:
// - This is intentionally conservative — if we can't find clear roles,
//   we return a single scene with UNKNOWN lines.
// - Later we can swap this for a cloud parser and keep the same API.

export type Scene = {
  id: string;
  title: string;
  lines: Array<{ speaker: string; text: string }>;
};

// --- Public API -------------------------------------------------------------

export async function parseScript(pdf_url: string): Promise<Scene[]> {
  try {
    const arrBuf = await downloadPdf(pdf_url);
    const text = await extractTextWithPdfJs(arrBuf);
    const scenes = analyzeScriptText(text);

    // sanity check: require at least 1 line
    if (!scenes.length || !scenes[0]?.lines?.length) {
      return parseStub(pdf_url);
    }
    return scenes;
  } catch (err) {
    console.warn('[pdf] parse failed, falling back to stub:', err?.message || err);
    return parseStub(pdf_url);
  }
}

// --- Fallback stub (exported for other modules if needed) -------------------

export async function parseStub(_pdf_url: string): Promise<Scene[]> {
  return [
    {
      id: 'scene-1',
      title: 'Stub Scene',
      lines: [
        { speaker: 'UNKNOWN', text: 'Hello there.' },
        { speaker: 'UNKNOWN', text: 'This is a stub line for MVP.' },
      ],
    },
  ];
}

// --- Helpers ----------------------------------------------------------------

async function downloadPdf(url: string): Promise<ArrayBuffer> {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`download failed: ${res.status} ${res.statusText}`);
  return await res.arrayBuffer();
}

async function extractTextWithPdfJs(arrBuf: ArrayBuffer): Promise<string> {
  // pdfjs in Node
  const pdfjsLib = await import('pdfjs-dist/legacy/build/pdf.js');
  // @ts-ignore - worker not needed in Node; avoid console noise
  pdfjsLib.GlobalWorkerOptions.workerSrc = undefined;

  const loadingTask = pdfjsLib.getDocument({ data: arrBuf });
  const pdf = await loadingTask.promise;

  let out = '';
  for (let p = 1; p <= pdf.numPages; p++) {
    const page = await pdf.getPage(p);
    const tc = await page.getTextContent();
    // Join items with newlines between text runs to preserve some structure.
    // (PDFs vary wildly; this is best-effort.)
    const pageText = tc.items.map((it: any) => (it?.str ?? '')).join('\n');
    out += pageText + '\n\n';
  }
  return normalizeWhitespace(out);
}

function normalizeWhitespace(s: string): string {
  return s
    .replace(/\r/g, '\n')
    .replace(/\u00A0/g, ' ') // nbsp
    .replace(/[ \t]+\n/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

/**
 * Heuristic scene + dialogue parser.
 * - Scene boundaries: lines starting with INT./EXT./SCENE or "Scene \d+".
 * - Speaker lines: UPPERCASE NAME (optionally with colon) at line start,
 *   e.g.  JANE: Hello there.
 *         JANE (quietly): …   -> speaker=JANE
 * - Non-matching text is attached to the last speaker (if any) or dropped.
 */
function analyzeScriptText(raw: string): Scene[] {
  if (!raw) return [];

  const lines = raw.split(/\n+/).map((l) => l.trim()).filter(Boolean);

  // Split into rough scenes
  const sceneIdxs: number[] = [];
  const sceneTitleAt: Record<number, string> = {};
  for (let i = 0; i < lines.length; i++) {
    const L = lines[i];
    if (/^(INT\.|EXT\.|I\/E\.|SCENE\b|SCENE\s+\d+)/i.test(L)) {
      sceneIdxs.push(i);
      sceneTitleAt[i] = L;
    }
  }
  if (sceneIdxs.length === 0) {
    // single pseudo-scene
    return [buildScene('scene-1', 'Scene', lines)];
  }

  const scenes: Scene[] = [];
  for (let s = 0; s < sceneIdxs.length; s++) {
    const start = sceneIdxs[s];
    const end = s + 1 < sceneIdxs.length ? sceneIdxs[s + 1] : lines.length;
    const title = sceneTitleAt[start] || `Scene ${s + 1}`;
    const chunk = lines.slice(start, end);
    scenes.push(buildScene(`scene-${s + 1}`, title, chunk));
  }
  return scenes;
}

function buildScene(id: string, title: string, chunk: string[]): Scene {
  const outLines: Array<{ speaker: string; text: string }> = [];

  // Regex for SPEAKER at line start:
  // uppercase words/dashes/spaces, optionally with parenthetical or colon
  const SPEAKER_RE = /^([A-Z][A-Z0-9 \-]{1,30})(?:\s*\([^)]*\))?\s*:?\s*(.+)?$/;

  let currentSpeaker: string | null = null;
  let buffer: string[] = [];

  const flush = () => {
    if (currentSpeaker && buffer.length) {
      const text = buffer.join(' ').replace(/\s{2,}/g, ' ').trim();
      if (text) outLines.push({ speaker: currentSpeaker, text });
    }
    buffer = [];
  };

  for (const rawLine of chunk) {
    const line = rawLine.trim();

    // speaker line?
    const m = line.match(SPEAKER_RE);
    if (m && looksLikeSpeaker(m[1], line)) {
      // new speaker; flush previous
      flush();
      currentSpeaker = m[1].trim();
      const rest = (m[2] || '').trim();
      if (rest) buffer.push(rest);
      continue;
    }

    // continuation of previous speaker?
    if (currentSpeaker) {
      // ignore pure scene headers/stage directions in all-caps without punctuation
      if (/^[A-Z0-9 \-]{4,}$/.test(line)) continue;
      buffer.push(line);
      continue;
    }

    // no current speaker → ignore non-dialogue until first speaker appears
  }

  flush();

  // If we detected no speaker lines, make a single UNKNOWN blob
  if (outLines.length === 0) {
    const text = chunk.join(' ').replace(/\s{2,}/g, ' ').trim();
    if (text) {
      return {
        id,
        title,
        lines: [
          { speaker: 'UNKNOWN', text },
        ],
      };
    }
  }

  return { id, title, lines: outLines };
}

function looksLikeSpeaker(name: string, fullLine: string): boolean {
  // Basic sanity: mostly uppercase, not INT/EXT, and line not crazy long
  if (!name) return false;
  if (name.length > 30) return false;
  if (/^(INT|EXT|SCENE)\b/.test(name)) return false;
  // Heuristic: name must be all-caps-ish (allow spaces/dashes/numbers)
  if (!/^[A-Z0-9 \-]+$/.test(name)) return false;

  // If there is a colon after the name (SPEAKER: text) → strong signal
  if (/^[A-Z0-9 \-]+:/.test(fullLine)) return true;

  // If the remainder of the line looks like dialogue (has lowercase letters), also OK
  const rest = fullLine.replace(/^[A-Z0-9 \-]+(?:\s*\([^)]*\))?\s*:?\s*/, '');
  return /[a-z]/.test(rest);
}
