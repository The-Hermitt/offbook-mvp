// src/lib/pdf.ts
// PDF/Text parser with optional OCR fallback (tesseract.js), capped pages.
// Exports:
//   analyzeScriptText(raw, strictColon?)
//   parseArrayBufferWithMeta(buf)  -> { scenes, meta }
//   parseArrayBuffer(buf)          -> scenes
//
// Env flags:
//   OCR_ENABLED=1       enable OCR fallback (default: off)
//   OCR_MAX_PAGES=10    page cap for OCR (default: 10)
//   OCR_LANG=eng        tesseract language (default: 'eng')

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

// ----- pdf.js standard fonts path (needed when rendering pages in Node) -----
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const STANDARD_FONTS_DIR = path.join(__dirname, '../../node_modules/pdfjs-dist/standard_fonts');

// ----- Utils -----
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

// ----- Speaker heuristics -----
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

// ----- Role scoring / quality -----
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

// ----- Core text analyzer -----
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

    // Loose: NAME: text
    const m = line.match(colonRe);
    if (m) {
      const name = cleanName(m[1].trim());
      if (looksLikeSpeakerName(name)) {
        current.lines.push({ speaker: name, text: (m[2] || '').trim() });
        continue;
      }
    }

    // NAME alone + following dialogue lines
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

    // Continuation
    if (current.lines.length > 0 && !isParenthetical(line)) {
      const last = current.lines[current.lines.length - 1];
      last.text = (last.text ? last.text + ' ' : '') + line.trim();
    }
  }

  // Cleanup
  for (const sc of scenes) {
    sc.lines = sc.lines
      .map(l => ({ speaker: cleanName(l.speaker), text: (l.text || '').trim() }))
      .filter(l => l.text.length > 0 && l.sp
