// src/lib/pdf.ts
// Paste-ready. Adds strict heuristics + diagnostics and pdfjs fallback chain.

export type Line = { speaker: string; text: string };
export type Scene = { id: string; title: string; lines: Line[] };

export type RoleStats = { total: number; badCount: number; badRatio: number };
export type ParserMeta = {
  pathUsed: 'pdfjs' | 'naive' | 'strict' | 'stub';
  roleStats: RoleStats;
  rawLength: number;
};

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

// Tight speaker heuristics
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

// Core analyzer
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

    // Loose: first try NAME: text
    const m = line.match(colonRe);
    if (m) {
      const name = cleanName(m[1].trim());
      if (looksLikeSpeakerName(name)) {
        current.lines.push({ speaker: name, text: (m[2] || '').trim() });
        continue;
      }
    }

    // Then NAME on its own line + subsequent dialogue lines
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
      .filter(l => l.text.length > 0 && l.speaker);
  }
  return scenes.filter(sc => sc.lines.length > 0);
}

// pdfjs text extraction
async function extractTextWithPdfJs(bytes: Uint8Array): Promise<string> {
  const pdfjs = await import('pdfjs-dist/legacy/build/pdf.js');
  const loadingTask = pdfjs.getDocument({ data: bytes });
  const pdf = await loadingTask.promise;

  const parts: string[] = [];
  const pageCount = Math.min(pdf.numPages, 100);
  for (let p = 1; p <= pageCount; p++) {
    const page = await pdf.getPage(p);
    const content = await page.getTextContent();
    const strs = content.items.map((it: any) => (it?.str ?? '')).filter(Boolean);
    parts.push(strs.join('\n'));
  }
  return normalizeWhitespace(parts.join('\n'));
}

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

// Public API with diagnostics
export async function parseArrayBufferWithMeta(input: ArrayBuffer | Buffer): Promise<{ scenes: Scene[]; meta: ParserMeta }> {
  const bytes = input instanceof Buffer ? new Uint8Array(input) : new Uint8Array(input);

  // 1) pdfjs
  try {
    const text = await extractTextWithPdfJs(bytes);
    if (text && text.length > 0) {
      let scenes = analyzeScriptText(text, false);
      scenes = maybeReparseStrictIfNoisy(scenes, text);
      if (hasDialogue(scenes)) return { scenes, meta: { pathUsed: 'pdfjs', roleStats: scoreRoles(scenes), rawLength: text.length } };
    }
  } catch (err) {
    console.warn('[pdf] pdfjs extract failed:', (err as Error)?.message);
  }

  // 2) naive buffer utf8
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

  // 3) stub
  const stub: Scene[] = [{ id: 'scene-1', title: 'Scene 1', lines: [] }];
  return { scenes: stub, meta: { pathUsed: 'stub', roleStats: { total: 0, badCount: 0, badRatio: 0 }, rawLength: 0 } };
}

// Back-compat export
export async function parseArrayBuffer(input: ArrayBuffer | Buffer): Promise<Scene[]> {
  const { scenes } = await parseArrayBufferWithMeta(input);
  return scenes;
}
