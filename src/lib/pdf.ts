// @ts-nocheck
// src/lib/pdf.ts
//
// PDF/text parsing with safe fallback.
//
// Exports:
//   - parseScript(pdf_url)
//   - parseArrayBuffer(arrBuf)
//   - parseText(text)
//   - parseStub()

export type Scene = {
  id: string;
  title: string;
  lines: Array<{ speaker: string; text: string }>;
};

// Public APIs ---------------------------------------------------------------

export async function parseScript(pdf_url: string): Promise<Scene[]> {
  try {
    const arrBuf = await downloadPdf(pdf_url);
    return await parseArrayBuffer(arrBuf);
  } catch (err) {
    console.warn('[pdf] parseScript failed, using stub:', err?.message || err);
    return parseStub(pdf_url);
  }
}

export async function parseArrayBuffer(arrBuf: ArrayBuffer): Promise<Scene[]> {
  try {
    const text = await extractTextWithPdfJs(arrBuf);
    const scenes = analyzeScriptText(text);
    if (!scenes.length || !scenes[0]?.lines?.length) return [{ id: 'scene-1', title: 'Scene', lines: [{ speaker: 'UNKNOWN', text }] }];
    return scenes;
  } catch (err) {
    console.warn('[pdf] parseArrayBuffer failed, using stub:', err?.message || err);
    return [{ id: 'scene-1', title: 'Stub Scene', lines: [{ speaker: 'UNKNOWN', text: 'Hello there.' }, { speaker: 'UNKNOWN', text: 'This is a stub line for MVP.' }] }];
  }
}

export async function parseText(raw: string): Promise<Scene[]> {
  try {
    const text = normalizeWhitespace(raw || '');
    const scenes = analyzeScriptText(text);
    if (!scenes.length || !scenes[0]?.lines?.length) return parseStub('text:empty');
    return scenes;
  } catch {
    return parseStub('text:error');
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

// Helpers ------------------------------------------------------------------

async function downloadPdf(url: string): Promise<ArrayBuffer> {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`download failed: ${res.status} ${res.statusText}`);
  return await res.arrayBuffer();
}

async function extractTextWithPdfJs(arrBuf: ArrayBuffer): Promise<string> {
  const pdfjsLib = await import('pdfjs-dist/legacy/build/pdf.js');
  // @ts-ignore
  pdfjsLib.GlobalWorkerOptions.workerSrc = undefined;

  const loadingTask = pdfjsLib.getDocument({ data: arrBuf });
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

// Heuristic scene + dialogue parser
function analyzeScriptText(raw: string): Scene[] {
  if (!raw) return [];
  const lines = raw.split(/\n+/).map((l) => l.trim()).filter(Boolean);

  // Scene boundaries
  const sceneIdxs: number[] = [];
  const sceneTitleAt: Record<number, string> = {};
  for (let i = 0; i < lines.length; i++) {
    const L = lines[i];
    if (/^(INT\.|EXT\.|I\/E\.|SCENE\b|SCENE\s+\d+)/i.test(L)) {
      sceneIdxs.push(i);
      sceneTitleAt[i] = L;
    }
  }
  if (sceneIdxs.length === 0) return [buildScene('scene-1', 'Scene', lines)];

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
    const m = line.match(SPEAKER_RE);
    if (m && looksLikeSpeaker(m[1], line)) {
      flush();
      currentSpeaker = m[1].trim();
      const rest = (m[2] || '').trim();
      if (rest) buffer.push(rest);
      continue;
    }
    if (currentSpeaker) {
      if (/^[A-Z0-9 \-]{4,}$/.test(line)) continue;
      buffer.push(line);
      continue;
    }
  }
  flush();

  if (outLines.length === 0) {
    const text = chunk.join(' ').replace(/\s{2,}/g, ' ').trim();
    if (text) return { id, title, lines: [{ speaker: 'UNKNOWN', text }] };
  }
  return { id, title, lines: outLines };
}

function looksLikeSpeaker(name: string, fullLine: string): boolean {
  if (!name || name.length > 30) return false;
  if (/^(INT|EXT|SCENE)\b/.test(name)) return false;
  if (!/^[A-Z0-9 \-]+$/.test(name)) return false;
  if (/^[A-Z0-9 \-]+:/.test(fullLine)) return true;
  const rest = fullLine.replace(/^[A-Z0-9 \-]+(?:\s*\([^)]*\))?\s*:?\s*/, '');
  return /[a-z]/.test(rest);
}
