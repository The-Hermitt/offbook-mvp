// src/lib/pdf.ts

import { Scene } from './types'; // or wherever your types are declared

const SCENE_HEAD_RE = /^(?:INT\.|EXT\.|I\/E\.|INT\/EXT\.|SCENE\b|SCENE\s+\d+)/i;
const ONLY_DIGITS_RE = /^\d{1,4}$/;
const ALLCAPS_NAME_RE = /^[A-Z .,'\-&]+$/;

const STOP_NAMES = new Set([
  'INT','EXT','SCENE','CUT TO','FADE IN','FADE OUT','DISSOLVE TO',
  'SMASH CUT','ANGLE ON',"CONT'D",'CONT’D','CONTINUED'
]);

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

function ultraNormalize(s: string): string {
  return normalizeWhitespace(s);
}

function isSceneHeading(line: string): boolean { return SCENE_HEAD_RE.test(line.trim()); }
function isParenthetical(line: string): boolean { const t = line.trim(); return t.startsWith('(') && t.endsWith(')'); }
function isLikelyPageNumber(line: string): boolean { return ONLY_DIGITS_RE.test(line.trim()); }
function isFooterHeader(line: string): boolean {
  const t = line.toLowerCase();
  return (
    t.startsWith('page ') ||
    t.includes('actors access') ||
    t.includes('breakdown services') ||
    t.includes('©') || t.includes('copyright') ||
    t.includes('www.') || t.includes('http://') || t.includes('https://')
  );
}
function isNoiseLine(line: string): boolean {
  const t = line.trim();
  if (!t) return true;
  return isLikelyPageNumber(t) || isFooterHeader(t);
}
function cleanName(line: string): string {
  return line.replace(/\s*\([^)]*\)\s*/g, '').replace(/\s{2,}/g,' ').trim();
}

// Heuristic: only accept all-caps names with 3+ letters and at least one vowel or multi-word
function looksLikeSpeakerName(name: string): boolean {
  if (!name) return false;
  const base = cleanName(name).replace(/\s{2,}/g, ' ');
  if (!ALLCAPS_NAME_RE.test(base)) return false;
  if (STOP_NAMES.has(base)) return false;

  const letters = (base.match(/[A-Z]/g) || []).length;
  if (letters < 3) return false;

  const hasVowel = /[AEIOUY]/.test(base);
  const hasMultiWord = base.includes(' ') || base.includes('&');
  if (!hasVowel && !hasMultiWord) return false;

  return true;
}

function getRoles(scenes: Scene[]): string[] {
  const set = new Set<string>();
  for (const sc of scenes) for (const ln of sc.lines || []) if (ln.speaker) set.add(ln.speaker);
  return Array.from(set);
}

function scoreRoles(scenes: Scene[]): { total: number; badCount: number; badRatio: number } {
  const roles = getRoles(scenes);
  if (!roles.length) return { total: 0, badCount: 0, badRatio: 0 };

  let bad = 0;
  for (const role of roles) {
    const cleaned = cleanName(role);
    const letters = (cleaned.match(/[A-Z]/g) || []).length;
    const hasDigit = /\d/.test(cleaned);
    const hasVowel = /[AEIOUY]/.test(cleaned);
    const multiWord = cleaned.includes(' ') || cleaned.includes('&');
    if (letters < 3 || hasDigit || (!hasVowel && !multiWord)) bad++;
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

function maybeReparseStrictIfNoisy(scenes: Scene[], raw: string): Scene[] {
  const originalStats = scoreRoles(scenes);
  if (!originalStats.total) return scenes;

  const tooManyBad = originalStats.badCount > 20 || originalStats.badCount / originalStats.total > 0.5;
  if (!tooManyBad) return scenes;

  const strictScenes = analyzeScriptText(raw, /* strictColon */ true);
  const strictStats = scoreRoles(strictScenes);

  const strictHasDialogue = hasDialogue(strictScenes);
  const originalHasDialogue = hasDialogue(scenes);

  const strictBetter =
    (strictHasDialogue && !originalHasDialogue) ||
    (strictStats.total && strictStats.badCount < originalStats.badCount) ||
    (strictHasDialogue && strictStats.badRatio <= originalStats.badRatio);

  return strictBetter ? strictScenes : scenes;
}

// Main analyzer (strictColon optional)
export function analyzeScriptText(rawInput: string, strictColon = false): Scene[] {
  const raw = normalizeWhitespace(rawInput || '');
  if (!raw) return [];

  const lines = raw
    .split(/\n+/)
    .map(l => l.trimEnd())
    .filter(l => l && !isNoiseLine(l));

  // ... existing scene segmentation logic ...
  // (Keep this logic as-is — you already had it working)
  
  return []; // fill in your existing logic
}
