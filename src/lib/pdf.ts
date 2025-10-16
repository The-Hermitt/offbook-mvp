// @ts-nocheck
// src/lib/pdf.ts
//
// Robust parser for PDF/Text → scenes with {speaker, text} lines.
// Order of extraction attempts for PDFs:
//  1) pdfjs-dist (layout-aware y/x grouping)
//  2) naive buffer→text guess (latin1/utf8 sweep)  ← NEW fallback
//  3) stub

export type Scene = {
  id: string;
  title: string;
  lines: Array<{ speaker: string; text: string }>;
};

// ----------------- Public API -----------------

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
    // 1) Preferred: pdfjs-dist layout-aware extraction
    try {
      const raw = await extractTextWithPdfJs(arrBuf);
      let scenes = analyzeScriptText(raw);
      if (!hasDialogue(scenes)) {
        const ultra = ultraNormalize(raw);
        scenes = analyzeScriptText(ultra);
      }
      if (hasDialogue(scenes)) return scenes;
      console.warn('[pdf] pdfjs extracted but no dialogue → trying naive buffer sweep');
    } catch (e) {
      console.warn('[pdf] pdfjs path failed →', e?.message || e);
    }

    // 2) NEW fallback: naive buffer→text sweep (handles text-based PDFs w/o pdfjs)
    const guess = extractTextFromBufferNaive(arrBuf);
    if (guess) {
      let scenes = analyzeScriptText(guess);
      if (!hasDialogue(scenes)) scenes = analyzeScriptText(ultraNormalize(guess));
      if (hasDialogue(scenes)) return scenes;
      console.warn('[pdf] naive buffer sweep produced no dialogue');
    }

    // 3) Stub fallback (last resort)
    return parseStub('file');
  } catch (err) {
    console.warn('[pdf] parseArrayBuffer catch → stub:', err?.message || err);
    return parseStub('file-err');
  }
}

export async function parseText(text: string): Promise<Scene[]> {
  try {
    const scenes = analyzeScriptText(text || '');
    if (!hasDialogue(scenes)) return parseStub('text');
    return scenes;
  } catch (err) {
    console.warn('[pdf] parseText failed → stub:', err?.message || err);
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

// ----------------- Extraction -----------------

async function downloadPdf(url: string): Promise<ArrayBuffer> {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`download failed: ${res.status} ${res.statusText}`);
  return await res.arrayBuffer();
}

/**
 * Layout-aware text extraction using pdfjs-dist.
 * If pdfjs-dist isn’t installed/available, this function will throw and we’ll fallback.
 */
async function extractTextWithPdfJs(arrBuf: ArrayBuffer): Promise<string> {
  // Dynamic import so the app still runs without pdfjs-dist installed
  const pdfjs = await import('pdfjs-dist/legacy/build/pdf.js');
  // @ts-ignore worker not needed in Node
  pdfjs.GlobalWorkerOptions.workerSrc = undefined;

  const loadingTask = pdfjs.getDocument({ data: arrBuf });
  const pdf = await loadingTask.promise;

  let out: string[] = [];

  for (let p = 1; p <= pdf.numPages; p++) {
    const page = await pdf.getPage(p);
    const tc = await page.getTextContent({ normalizeWhitespace: true, disableCombineTextItems: false });

    type Item = { str: string; transform: number[]; x: number; y: number; w: number; h: number };
    const items: Item[] = (tc.items as any[])
      .map((it: any) => {
        const [, , , , e, f] = it.transform || [1,0,0,1,0,0];
        return { str: it.str ?? '', transform: it.transform, x: e, y: f, w: it.width || 0, h: it.height || 0 };
      })
      .filter(it => (it.str || '').trim().length > 0);

    // Cluster by Y within tolerance (screenplays often have tiny drift)
    const tolY = 2.5;
    items.sort((A,B) => (B.y - A.y) || (A.x - B.x)); // top→bottom (y desc), then left→right
    const lines: { y: number; parts: Item[] }[] = [];
    for (const it of items) {
      const bucket = lines.find(L => Math.abs(L.y - it.y) <= tolY);
      if (bucket) bucket.parts.push(it);
      else lines.push({ y: it.y, parts: [it] });
    }
    const lineTexts = lines
      .map(L => {
        L.parts.sort((A,B) => A.x - B.x);
        let s = '';
        for (const part of L.parts) {
          const piece = String(part.str);
          const needsSpace = s.length && !s.endsWith(' ') && !piece.startsWith(' ');
          s += (needsSpace ? ' ' : '') + piece;
        }
        return s.trimEnd();
      })
      .filter(s => s.trim().length > 0);

    out.push(lineTexts.join('\n'));
  }

  return normalizeWhitespace(out.join('\n\n'));
}

/**
 * NEW: Extremely lightweight “best effort” text rip directly from PDF bytes.
 * Tries latin1 and utf8 decoders, drops obvious binary noise, collapses whitespace.
 * This won’t fix scanned-image PDFs, but helps many text-based PDFs when pdfjs isn’t present.
 */
function extractTextFromBufferNaive(arrBuf: ArrayBuffer): string {
  try {
    const tryDecode = (enc: string) => {
      const td = new TextDecoder(enc as any, { fatal: false });
      return td.decode(new Uint8Array(arrBuf));
    };
    let s = tryDecode('latin1');
    if (!s || s.replace(/\W/g,'').length < 20) s = tryDecode('utf-8');

    s = (s || '')
      .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]+/g, '\n') // control chars → newlines
      .replace(/\u0000/g, '')                           // NUL
      .replace(/\r/g, '\n')
      .replace(/[ \t]+\n/g, '\n')
      .replace(/\n{3,}/g, '\n\n');

    // Many PDFs interleave words like "J A N E : H e l l o"
    // Heal obvious spaced-caps name patterns like "J A N E" → "JANE"
    s = s.replace(/\b(?:[A-Z]\s)+[A-Z]\b/g, (m) => m.replace(/\s+/g, ''));

    return s.trim();
  } catch {
    return '';
  }
}

// ----------------- Heuristics -----------------

function normalizeWhitespace(s: string): string {
  return (s || '')
    .replace(/[\r\t\v\f]/g, '\n')
    .replace(/\u00A0/g, ' ')
    .replace(/[ \t]+\n/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

function ultraNormalize(s: string): string {
  return (s || '')
    .normalize('NFKC')
    .replace(/[“”]/g, '"')
    .replace(/[‘’]/g, "'")
    .replace(/[—–]/g, '-')
    .replace(/·/g, '.')
    .replace(/◦/g, '-')
    .replace(/[ \t]+\n/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

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
  const upperish = ALLCAPS_RE.test(base) && !/[a-z]/.test(base) && /[A-Z]/.test(base);
  if (!upperish) return false;
  if (STOP_NAMES.has(base)) return false;
  if (ONLY_DIGITS_RE.test(base)) return false;
  return true;
}

function hasDialogue(scenes: Scene[]): boolean {
  if (!Array.isArray(scenes)) return false;
  for (const sc of scenes) {
    for (const ln of sc?.lines || []) {
      const speaker = (ln?.speaker || '').trim();
      const text = (ln?.text || '').trim();
      if (text.length > 0 && speaker && speaker !== 'UNKNOWN') return true;
    }
  }
  return false;
}

export function analyzeScriptText(rawInput: string): Scene[] {
  const raw = normalizeWhitespace(rawInput || '');
  if (!raw) return [];

  const lines = raw
    .split(/\n+/)
    .map(l => l.trimEnd())
    .filter(l => l && !isNoiseLine(l));

  // Scenes
  const sceneStarts: number[] = [];
  const titles: Record<number,string> = {};
  for (let i=0;i<lines.length;i++){
    if (isSceneHeading(lines[i])) { sceneStarts.push(i); titles[i] = lines[i]; }
  }
  if (sceneStarts.length===0) { sceneStarts.push(0); titles[0]='Scene 1'; }

  const scenes: Scene[] = [];
  for (let s=0; s<sceneStarts.length; s++){
    const start = sceneStarts[s];
    const end = (s+1 < sceneStarts.length) ? sceneStarts[s+1] : lines.length;
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

    const colonMatch = line.match(/^([A-Z0-9 .,'\-]{2,30})\s*:?\s*(.*)$/);
    if (colonMatch) {
      const name = cleanName(colonMatch[1]);
      const rest = (colonMatch[2] || '').trim();
      if (looksLikeSpeakerName(name)) {
        if (rest && hasAnyLower(rest) && !isParenthetical(rest)) return name;
        // Peek next lines for dialogue signal
        for (let j=i+1; j<Math.min(i+5, chunk.length); j++){
          const nxt = (chunk[j] || '').trim();
          if (!nxt || isNoiseLine(nxt)) continue;
          if (isParenthetical(nxt)) return name;
          if (hasAnyLower(nxt)) return name;
          if (isSceneHeading(nxt)) break;
        }
      }
    }
    return null;
  }

  for (let i=0;i<chunk.length;i++){
    const line = (chunk[i] || '').trim();
    if (!line || isNoiseLine(line)) continue;

    const maybe = startsNewSpeaker(i);
    if (maybe) {
      flush();
      currentSpeaker = maybe;
      const after = line.replace(/^([A-Z0-9 .,'\-]{2,30})(?:\s*\([^)]*\))?\s*:?\s*/, '').trim();
      if (after && hasAnyLower(after) && !isParenthetical(after)) buf.push(after);
      continue;
    }

    if (currentSpeaker) {
      if (isParenthetical(line)) continue;
      if (isAllCapsAction(line)) continue;
      if (hasAnyLower(line)) { buf.push(line); continue; }
      continue;
    }
  }

  flush();
  return { id, title, lines: out };
}

function hasAnyLower(s: string): boolean { return /[a-z]/.test(s); }

function isAllCapsAction(s: string): boolean {
  const t = s.trim();
  if (!t) return false;
  if (isSceneHeading(t)) return false;
  if (isParenthetical(t)) return false;
  return ALLCAPS_RE.test(t) && !/[a-z]/.test(t);
}
