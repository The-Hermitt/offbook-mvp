// src/lib/pdf.ts
// PDF/Text parser with optional OCR fallback (tesseract.js recognize()), capped pages & timeout.
// Env flags:
//   OCR_ENABLED=1         enable OCR fallback (default: off)
//   OCR_MAX_PAGES=10      page cap for OCR (default: 10)
//   OCR_LANG=eng          tesseract language (default: 'eng')
//   OCR_SCALE=2.0         rasterization scale for OCR images (default: 2.0)
//   OCR_TIMEOUT_MS=25000  hard timeout for the entire OCR pass (default: 25000)

import path from 'path';
import { fileURLToPath } from 'url';

export type Line = { speaker: string; text: string };
export type Scene = { id: string; title: string; lines: Line[] };

export type RoleStats = { total: number; badCount: number; badRatio: number };
export type ParserMeta = {
  pathUsed: 'pdfjs' | 'naive' | 'strict' | 'ocr' | 'stub';
  roleStats: RoleStats;
  rawLength: number;
  pagesTried?: number;
  timedOut?: boolean;
};

const SCENE_HEAD_RE = /^(?:INT\.|EXT\.|I\/E\.|INT\/EXT\.|SCENE\b|SCENE\s+\d+)/i;
const ONLY_DIGITS_RE = /^\d{1,4}$/;
const ALLCAPS_NAME_RE = /^[A-Z .,'\-&]+$/;

const STOP_NAMES = new Set([
  'INT','EXT','SCENE','CUT TO','FADE IN','FADE OUT','DISSOLVE TO',
  'SMASH CUT','ANGLE ON',"CONT'D",'CONT’D','CONTINUED'
]);

const OCR_ENABLED = process.env.OCR_ENABLED === '1' || process.env.OCR_ENABLED === 'true';
const OCR_MAX_PAGES = Math.max(1, Number(process.env.OCR_MAX_PAGES || 10));
const OCR_LANG = process.env.OCR_LANG || 'eng';
const OCR_SCALE = Math.max(1, Number(process.env.OCR_SCALE || 2.0));
const OCR_TIMEOUT_MS = Math.max(5000, Number(process.env.OCR_TIMEOUT_MS || 25000));

// pdf.js standard fonts dir (for Node canvas rendering)
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const STANDARD_FONTS_DIR = path.join(__dirname, '../../node_modules/pdfjs-dist/standard_fonts');

// ───────────────────────── utils
function normalizeWhitespace(s: string): string {
  return (s || '')
    .normalize('NFKC')
    .replace(/[“”]/g, '"')
    .replace(/[‘’]/g, "'")
    .replace(/[—–]/g, '-')
    .replace(/·/g, '.')
    .replace(/◦/g, '-')
    .replace(/\u00A0/g, ' ')
    .replace(/[ \t]+\n/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}
function isSceneHeading(line: string): boolean { return SCENE_HEAD_RE.test((line || '').trim()); }
function isParenthetical(line: string): boolean { const t = (line || '').trim(); return t.startsWith('(') && t.endsWith(')'); }
function isLikelyPageNumber(line: string): boolean { return ONLY_DIGITS_RE.test((line || '').trim()); }
function isFooterHeader(line: string): boolean {
  const t = (line || '').toLowerCase();
  return (
    t.startsWith('page ') ||
    t.includes('actors access') ||
    t.includes('breakdown services') ||
    t.includes('©') || t.includes('copyright') ||
    t.includes('www.') || t.includes('http://') || t.includes('https://')
  );
}
function isNoiseLine(line: string): boolean {
  const t = (line || '').trim();
  if (!t) return true;
  return isLikelyPageNumber(t) || isFooterHeader(t);
}
function cleanName(line: string): string {
  return (line || '').replace(/\s*\([^)]*\)\s*/g, '').replace(/\s{2,}/g, ' ').trim();
}

// ───────────────────────── heuristics
function looksLikeSpeakerName(name: string): boolean {
  if (!name) return false;
  const base = cleanName(name).replace(/\s{2,}/g, ' ');
  if (!base) return false;
  if (!ALLCAPS_NAME_RE.test(base)) return false;
  if (STOP_NAMES.has(base)) return false;

  const letters = (base.match(/[A-Z]/g) || []).length;
  if (letters < 3) return false;

  const hasVowel = /[AEIOUY]/.test(base);
  const multi = base.includes(' ') || base.includes('&');
  if (!hasVowel && !multi) return false;

  return true;
}
function rolesFromScenes(scenes: Scene[]): string[] {
  const set = new Set<string>();
  for (const sc of scenes) for (const ln of sc.lines || []) if (ln.speaker) set.add(ln.speaker);
  return Array.from(set);
}
function scoreRoles(scenes: Scene[]): RoleStats {
  const roles = rolesFromScenes(scenes);
  if (!roles.length) return { total: 0, badCount: 0, badRatio: 0 };
  let bad = 0;
  for (const role of roles) {
    const r = cleanName(role);
    const letters = (r.match(/[A-Z]/g) || []).length;
    const hasDigit = /\d/.test(r);
    const hasVowel = /[AEIOUY]/.test(r);
    const multi = r.includes(' ') || r.includes('&');
    if (letters < 3 || hasDigit || (!hasVowel && !multi)) bad++;
  }
  return { total: roles.length, badCount: bad, badRatio: bad / roles.length };
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

// ───────────────────────── analyzer
export function analyzeScriptText(rawInput: string, strictColon = false): Scene[] {
  const raw = normalizeWhitespace(rawInput || '');
  if (!raw) return [];

  const lines = raw
    .split(/\n+/)
    .map(l => l.trimEnd())
    .filter(l => l && !isNoiseLine(l));

  const scenes: Scene[] = [];
  let current: Scene = { id: `scene-1`, title: 'Scene 1', lines: [] };
  scenes.push(current);

  const colonRe = /^([A-Z .,'\-&]+):\s*(.+)$/;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (isSceneHeading(line)) {
      current = { id: `scene-${scenes.length + 1}`, title: line, lines: [] };
      scenes.push(current);
      continue;
    }

    if (strictColon) {
      const m = line.match(colonRe);
      if (m) {
        const name = cleanName(m[1].trim());
        if (looksLikeSpeakerName(name)) {
          current.lines.push({ speaker: name, text: (m[2] || '').trim() });
        }
      }
      continue;
    }

    // NAME: text
    const m = line.match(colonRe);
    if (m) {
      const name = cleanName(m[1].trim());
      if (looksLikeSpeakerName(name)) {
        current.lines.push({ speaker: name, text: (m[2] || '').trim() });
        continue;
      }
    }

    // NAME on its own + run of following lines
    if (looksLikeSpeakerName(line) && !isParenthetical(line)) {
      const name = cleanName(line);
      const textParts: string[] = [];
      let j = i + 1;
      while (j < lines.length) {
        const nxt = lines[j];
        if (!nxt || isSceneHeading(nxt)) break;
        if (looksLikeSpeakerName(nxt)) break;
        if (isNoiseLine(nxt) || isLikelyPageNumber(nxt) || isParenthetical(nxt)) { j++; continue; }
        textParts.push(nxt.trim());
        j++;
      }
      if (textParts.length > 0) {
        current.lines.push({ speaker: name, text: textParts.join(' ') });
        i = j - 1;
        continue;
      }
    }

    // continuation
    if (current.lines.length > 0 && !isParenthetical(line)) {
      const last = current.lines[current.lines.length - 1];
      last.text = (last.text ? last.text + ' ' : '') + line.trim();
    }
  }

  for (const sc of scenes) {
    sc.lines = sc.lines
      .map(l => ({ speaker: cleanName(l.speaker), text: (l.text || '').trim() }))
      .filter(l => l.text.length > 0 && l.speaker);
  }
  return scenes.filter(sc => sc.lines.length > 0);
}

// ───────────────────────── CanvasFactory for @napi-rs/canvas
type CanvasAndContext = { canvas: any; context: any };
function makeCanvasFactory(createCanvas: (w:number,h:number)=>any) {
  return {
    create: (w:number, h:number): CanvasAndContext => {
      const canvas = createCanvas(Math.ceil(w), Math.ceil(h));
      const context = canvas.getContext('2d');
      return { canvas, context };
    },
    reset: (target: CanvasAndContext, w:number, h:number) => {
      if (!target?.canvas) return;
      target.canvas.width = Math.ceil(w);
      target.canvas.height = Math.ceil(h);
    },
    destroy: (target: CanvasAndContext) => {
      if (!target) return;
      try { if (target.canvas) { target.canvas.width = 0; target.canvas.height = 0; } } catch {}
      (target as any).canvas = null;
      (target as any).context = null;
    }
  };
}

// ───────────────────────── PDF text extraction (fast path)
async function extractTextWithPdfJs(bytes: Uint8Array): Promise<{ text: string; numPages: number }> {
  const pdfjs = await import('pdfjs-dist/legacy/build/pdf.js');
  const loadingTask = pdfjs.getDocument({
    data: bytes,
    standardFontDataUrl: `file://${STANDARD_FONTS_DIR}/`
  });
  const pdf = await loadingTask.promise;

  const parts: string[] = [];
  const pageCount = pdf.numPages;
  for (let p = 1; p <= Math.min(pageCount, 100); p++) {
    const page = await pdf.getPage(p);
    const content = await page.getTextContent();
    const strs = content.items.map((it: any) => (it?.str ?? '')).filter(Boolean);
    parts.push(strs.join('\n'));
  }
  return { text: normalizeWhitespace(parts.join('\n')), numPages: pageCount };
}

// ───────────────────────── OCR fallback using recognize()
async function ocrPdfFirstPages(bytes: Uint8Array, maxPages: number, lang: string, scale: number): Promise<{ text: string; pages: number }> {
  const pdfjs = await import('pdfjs-dist/legacy/build/pdf.js');
  const { createCanvas } = await import('@napi-rs/canvas');
  const { recognize } = await import('tesseract.js');

  const loadingTask = pdfjs.getDocument({
    data: bytes,
    standardFontDataUrl: `file://${STANDARD_FONTS_DIR}/`
  });
  const pdf = await loadingTask.promise;

  const pagesToDo = Math.min(pdf.numPages, Math.max(1, maxPages));
  const canvasFactory = makeCanvasFactory(createCanvas);

  let acc = '';
  for (let p = 1; p <= pagesToDo; p++) {
    const page = await pdf.getPage(p);
    const viewport = page.getViewport({ scale }); // e.g., 2.0

    const cc = canvasFactory.create(viewport.width, viewport.height);
    await page.render({ canvasContext: cc.context, viewport, canvasFactory }).promise;

    const png = cc.canvas.toBuffer('image/png');

    // One-shot recognize with tuned params (no worker init)
    const { data: { text } } = await recognize(png, lang, {
      langPath: 'https://tessdata.projectnaptha.com/4.0.0',
      preserve_interword_spaces: '1',
      tessedit_pageseg_mode: '6',
      user_defined_dpi: '300',
      tessedit_char_whitelist: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 .,'-&:;?!()",
    });

    if (text) acc += '\n' + text;

    canvasFactory.destroy(cc);
    await new Promise(r => setTimeout(r, 0));
  }

  return { text: normalizeWhitespace(acc), pages: pagesToDo };
}

// ───────────────────────── guards
function maybeReparseStrictIfNoisy(scenes: Scene[], raw: string): Scene[] {
  const stats = scoreRoles(scenes);
  if (!stats.total) return scenes;
  const tooManyBad = stats.badCount > 20 || stats.badRatio > 0.5;
  if (!tooManyBad) return scenes;
  const strict = analyzeScriptText(raw, /*strictColon*/ true);
  const sStats = scoreRoles(strict);
  const strictBetter =
    (hasDialogue(strict) && !hasDialogue(scenes)) ||
    (sStats.total && sStats.badCount < stats.badCount) ||
    (hasDialogue(strict) && sStats.badRatio <= stats.badRatio);
  return strictBetter ? strict : scenes;
}

async function withTimeout<T>(p: Promise<T>, ms: number): Promise<{ ok: true; value: T } | { ok: false; error: any }> {
  let to: NodeJS.Timeout;
  try {
    const val = await Promise.race([
      p,
      new Promise<never>((_, rej) => { to = setTimeout(() => rej(new Error('ocr_timeout')), ms); })
    ]);
    clearTimeout(to!);
    // @ts-ignore
    return { ok: true, value: val };
  } catch (e) {
    if (to) clearTimeout(to);
    return { ok: false, error: e };
  }
}

// ───────────────────────── public API
export async function parseArrayBufferWithMeta(input: ArrayBuffer | Buffer): Promise<{ scenes: Scene[]; meta: ParserMeta }> {
  const bytes = input instanceof Buffer ? new Uint8Array(input) : new Uint8Array(input);

  // 1) pdfjs text
  try {
    const { text, numPages } = await extractTextWithPdfJs(bytes);
    if (text && text.length > 0) {
      let scenes = analyzeScriptText(text, false);
      scenes = maybeReparseStrictIfNoisy(scenes, text);
      if (hasDialogue(scenes)) {
        return { scenes, meta: { pathUsed: 'pdfjs', roleStats: scoreRoles(scenes), rawLength: text.length, pagesTried: Math.min(numPages, 100) } };
      }
    }
  } catch (err) {
    console.warn('[pdf] pdfjs extract failed:', (err as Error)?.message);
  }

  // 2) naive buffer as UTF-8
  try {
    const raw = Buffer.isBuffer(input) ? input.toString('utf8') : Buffer.from(bytes).toString('utf8');
    if (raw && raw.length > 0) {
      let scenes = analyzeScriptText(raw, false);
      scenes = maybeReparseStrictIfNoisy(scenes, raw);
      if (hasDialogue(scenes)) return { scenes, meta: { pathUsed: 'naive', roleStats: scoreRoles(scenes), rawLength: raw.length } };
      const strict = analyzeScriptText(raw, true);
      if (hasDialogue(strict)) return { scenes: strict, meta: { pathUsed: 'strict', roleStats: scoreRoles(strict), rawLength: raw.length } };
    }
  } catch (err) {
    console.warn('[pdf] naive buffer parse failed:', (err as Error)?.message);
  }

  // 3) OCR fallback (flagged, capped, timeout-protected)
  if (OCR_ENABLED) {
    const result = await withTimeout(ocrPdfFirstPages(bytes, OCR_MAX_PAGES, OCR_LANG, OCR_SCALE), OCR_TIMEOUT_MS);
    if (result.ok) {
      try {
        const { text, pages } = result.value as any;
        if (text && text.length > 0) {
          let scenes = analyzeScriptText(text, false);
          scenes = maybeReparseStrictIfNoisy(scenes, text);
          if (hasDialogue(scenes)) return { scenes, meta: { pathUsed: 'ocr', roleStats: scoreRoles(scenes), rawLength: text.length, pagesTried: pages } };
          const strict = analyzeScriptText(text, true);
          if (hasDialogue(strict)) return { scenes: strict, meta: { pathUsed: 'ocr', roleStats: scoreRoles(strict), rawLength: text.length, pagesTried: pages } };
        }
      } catch (err) {
        console.warn('[pdf] ocr parse failed:', (err as Error)?.message);
      }
    } else {
      console.warn('[pdf] ocr timed out or failed:', (result as any).error?.message || (result as any).error);
      const stub: Scene[] = [{ id: 'scene-1', title: 'Scene 1', lines: [] }];
      return { scenes: stub, meta: { pathUsed: 'stub', roleStats: { total: 0, badCount: 0, badRatio: 0 }, rawLength: 0, timedOut: true } };
    }
  }

  // 4) stub
  const stub: Scene[] = [{ id: 'scene-1', title: 'Scene 1', lines: [] }];
  return { scenes: stub, meta: { pathUsed: 'stub', roleStats: { total: 0, badCount: 0, badRatio: 0 }, rawLength: 0 } };
}

export async function parseArrayBuffer(input: ArrayBuffer | Buffer): Promise<Scene[]> {
  const { scenes } = await parseArrayBufferWithMeta(input);
  return scenes;
}
