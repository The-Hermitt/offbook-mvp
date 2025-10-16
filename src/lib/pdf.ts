// @ts-nocheck
// src/lib/pdf.ts
//
// Robust-ish PDF/text parser with safe fallback.
// Emits DIALOGUE only; skips scene headings, parentheticals, all-caps action,
// page numbers, and common footer/header junk.
//
// Public API:
//   - parseScript(pdf_url)
//   - parseArrayBuffer(arrBuf)
//   - parseText(text)
//   - parseStub()

export type Scene = {
  id: string;
  title: string;
  lines: Array<{ speaker: string; text: string }>;
};

// ----------------- Public APIs -----------------

export async function parseScript(pdf_url: string): Promise<Scene[]> {
  try {
    const arrBuf = await downloadPdf(pdf_url);
    return await parseArrayBuffer(arrBuf);
  } catch (err) {
    console.warn('[pdf] parseScript failed → stub:', err?.message || err);
    return parseStub('url');
  }
}

export async function parseArrayBuffer(arrBuf: ArrayBuffer): Promise<Scene[]> {
  try {
    const raw = await extractTextWithPdfJs(arrBuf);
    const scenes = analyzeScriptText(raw);
    if (!hasDialogue(scenes)) return parseStub('file');
    return scenes;
  } catch (err) {
    console.warn('[pdf] parseArrayBuffer failed → stub:', err?.message || err);
    return parseStub('file-err');
  }
}

export async function parseText(text: string): Promise<Scene[]> {
  try {
    const scenes = analyzeScriptText(text || '');
    if (!hasDialogue(scenes)) return parseStub('text');
    return scenes;
  } catch {
    return parseStub('text-err');
  }
}

export async function parseStub(_hint?: string): Promise<Scene[]> {
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

// ----------------- Helpers -----------------

function hasDialogue(scenes: Scene[]): boolean {
  return Array.isArray(scenes) && scenes.some(s => Array.isArray(s.lines) && s.lines.length > 0);
}

async function downloadPdf(url: string): Promise<ArrayBuffer> {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`download failed: ${res.status} ${res.statusText}`);
  return await res.arrayBuffer();
}

async function extractTextWithPdfJs(arrBuf: ArrayBuffer): Promise<string> {
  const pdfjs = await import('pdfjs-dist/legacy/build/pdf.js');
  // @ts-ignore worker not needed in Node
  pdfjs.GlobalWorkerOptions.workerSrc = undefined;

  const loadingTask = pdfjs.getDocument({ data: arrBuf });
  const pdf = await loadingTask.promise;

  let out = '';
  for (let p = 1; p <= pdf.numPages; p++) {
    const page = await pdf.getPage(p);
    const tc = await page.getTextContent();
    const pageText = tc.items.map((it: any) => (it?.str ?? '')).join('\n');
    out += pageText + '\n\n';
  }
  return normalizeWhitespace(out);
}

function normalizeWhitespace(s: string): string {
  return (s || '')
    .replace(/\r/g, '\n')
    .replace(/\u00A0/g, ' ')
    .replace(/[ \t]+\n/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

// ----------------- Heuristics -----------------

const SCENE_HEAD_RE = /^(?:INT\.|EXT\.|I\/E\.|INT\/EXT\.|SCENE\b|SCENE\s+\d+)/i;
const ALLCAPS_RE = /^[A-Z0-9 .,'\-]+$/;
const ONLY_DIGITS_RE = /^\d{1,4}$/;

const STOP_NAMES = new Set([
  'INT', 'EXT', 'SCENE', 'CUT TO', 'FADE IN', 'FADE OUT', 'DISSOLVE TO',
  'SMASH CUT', 'ANGLE ON', "CONT'D", 'CONT’D', 'CONTINUED'
]);

function isSceneHeading(line: string): boolean {
  return SCENE_HEAD_RE.test(line.trim());
}
function isParenthetical(line: string): boolean {
  const t = line.trim();
  return t.startsWith('(') && t.endsWith(')');
}
function isLikelyPageNumber(line: string): boolean {
  return ONLY_DIGITS_RE.test(line.trim());
}
function isFooterHeader(line: string): boolean {
  const t = line.toLowerCase();
  return (
    t.includes('actors access') ||
    t.includes('breakdown services') ||
    t.startsWith('page ') ||
    t.includes('©') ||
    t.includes('copyright') ||
    t.includes('www.') ||
    t.includes('http://') || t.includes('https://')
  );
}
function isNoiseLine(line: string): boolean {
  const t = line.trim();
  if (!t) return true;
  return isLikelyPageNumber(t) || isFooterHeader(t);
}
function cleanName(line: string): string {
  return line.replace(/\s*\([^)]*\)\s*/g, '').trim();
}
function looksLikeSpeakerName(name: string): boolean {
  if (!name) return false;
  const base = name.replace(/\s+/g, ' ').trim();
  if (base.length < 2 || base.length > 30) return false;
  // must be mostly uppercase and contain at least one letter
  const upperish = ALLCAPS_RE.test(base) && !/[a-z]/.test(base) && /[A-Z]/.test(base);
  if (!upperish) return false;
  if (STOP_NAMES.has(base)) return false;
  if (SCENE_HEAD_RE.test(base)) return false;
  if (ONLY_DIGITS_RE.test(base)) return false; // reject "43" etc.
  return true;
}

/**
 * Parse raw text into scenes & dialogue lines.
 * Accepts formats like:
 *   JANE: Hello there.
 *   JANE (quietly)
 *   I… uh…
 *   GABE
 *     (with feeling)
 *     Don’t go.
 */
function analyzeScriptText(rawInput: string): Scene[] {
  const raw = normalizeWhitespace(rawInput || '');
  if (!raw) return [];

  // Split to lines, drop obvious noise early
  const lines = raw
    .split(/\n+/)
    .map(l => l.trim())
    .filter(l => l && !isNoiseLine(l));

  // Partition into scenes first
  const sceneStarts: number[] = [];
  const titles: Record<number,string> = {};
  for (let i=0;i<lines.length;i++){
    if (isSceneHeading(lines[i])) { sceneStarts.push(i); titles[i] = lines[i]; }
  }
  if (sceneStarts.length === 0) {
    return [buildScene('scene-1', 'Scene', lines)];
  }

  const scenes: Scene[] = [];
  for (let s=0; s<sceneStarts.length; s++){
    const start = sceneStarts[s];
    const end   = s+1 < sceneStarts.length ? sceneStarts[s+1] : lines.length;
    const chunk = lines.slice(start, end);
    const title = titles[start] || `Scene ${s+1}`;
    scenes.push(buildScene(`scene-${s+1}`, title, chunk));
  }
  return scenes;
}

function buildScene(id: string, title: string, chunk: string[]): Scene {
  const out: Array<{ speaker: string; text: string }> = [];

  let currentSpeaker: string | null = null;
  let buf: string[] = [];

  const flush = () => {
    if (currentSpeaker && buf.length) {
      const spoken = buf.filter(l =>
        !isParenthetical(l) &&
        !isSceneHeading(l) &&
        hasAnyLower(l)
      );
      const text = spoken.join(' ').replace(/\s{2,}/g,' ').trim();
      if (text) out.push({ speaker: currentSpeaker, text });
    }
    buf = [];
  };

  function startsNewSpeaker(i: number): string | null {
    const line = chunk[i] || '';
    if (!line || isNoiseLine(line)) return null;

    // "NAME: Dialogue"
    const colonMatch = line.match(/^([A-Z0-9 .,'\-]{2,30})\s*:?\s*(.*)$/);
    if (colonMatch) {
      const name = cleanName(colonMatch[1]);
      const rest = (colonMatch[2] || '').trim();
      if (looksLikeSpeakerName(name)) {
        if (rest && hasAnyLower(rest) && !isParenthetical(rest)) return name;
        // Peek next few lines for dialogue signal
        for (let j=i+1; j<Math.min(i+4, chunk.length); j++){
          const nxt = (chunk[j] || '').trim();
          if (!nxt || isNoiseLine(nxt)) continue;
          if (isParenthetical(nxt)) return name; // (beat)
          if (hasAnyLower(nxt)) return name;     // actual dialogue
          if (isSceneHeading(nxt)) break;
        }
      }
    }
    return null;
  }

  for (let i=0;i<chunk.length;i++){
    const line = (chunk[i] || '').trim();
    if (!line || isNoiseLine(line)) continue;

    // New scene header resets any speaker
    if (isSceneHeading(line)) { flush(); currentSpeaker = null; continue; }

    const maybe = startsNewSpeaker(i);
    if (maybe) {
      // commit previous
      flush();
      currentSpeaker = maybe;
      // capture text after "NAME:" on the same line
      const after = line.replace(/^([A-Z0-9 .,'\-]{2,30})(?:\s*\([^)]*\))?\s*:?\s*/, '').trim();
      if (after && hasAnyLower(after) && !isParenthetical(after)) buf.push(after);
      continue;
    }

    // If we have a speaker, buffer likely dialogue; skip parentheticals & all-caps action
    if (currentSpeaker) {
      if (isParenthetical(line)) continue;
      if (isAllCapsAction(line)) continue;
      if (hasAnyLower(line)) { buf.push(line); continue; }
      continue; // ignore remaining all-caps action/noise
    }

    // Outside a speech block → ignore (action)
  }

  flush();
  return { id, title, lines: out };
}

function hasAnyLower(s: string): boolean {
  return /[a-z]/.test(s);
}
function isAllCapsAction(s: string): boolean {
  const t = s.trim();
  if (!t) return false;
  if (isSceneHeading(t)) return false;
  if (isParenthetical(t)) return false;
  return ALLCAPS_RE.test(t) && !/[a-z]/.test(t);
}
