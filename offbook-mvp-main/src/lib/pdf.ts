// src/lib/pdf.ts
// NOTE: This file keeps the ORIGINAL exports your app expects:
// - analyzeScriptText(text, strictColon?) => Scene[]
// - parseArrayBufferWithMeta(buf) => { scenes: Scene[], meta: ParserMeta }
// It performs text-only PDF extraction (no page.render()) to avoid node-canvas
// crashes on Render.

import type { PDFDocumentProxy, TextContent } from "pdfjs-dist";
import * as pdfjs from "pdfjs-dist/legacy/build/pdf";

export type Line = { speaker: string; text: string };
export type Scene = { id: string; title: string; lines: Line[] };

// Kept loose so we don’t couple callers to internal fields
export type ParserMeta = {
  pathUsed: "text-only" | "open-failed" | "text-empty";
  pageCount?: number;
  pagesRead?: number;
  rawLength?: number;
  scannedSuspected?: boolean;
  timedOut?: boolean;
  roleStats?: { total: number; badCount: number; badRatio: number };
};

/**
 * Very small, robust analyzer that turns raw text into scenes/lines.
 * - Accepts "NAME: dialogue" or "NAME (note): dialogue"
 * - Skips INT./EXT./SCENE headings, URLs, page numbers, ALL-CAPS action
 * - Returns a single scene (MVP-compatible)
 */
export function analyzeScriptText(text: string, strictColon: boolean = false): Scene[] {
  const lines = (text || "").replace(/\r/g, "").split("\n");
  const scene: Scene = { id: "scene_1", title: "Scene 1", lines: [] };
  const re = strictColon
    ? /^([A-Z][A-Z0-9 ]{1,})(?:\s*\([^)]*\))?:\s+(.+)$/
    : /^([A-Z][A-Z0-9 ]{1,})(?:\s*\([^)]*\))?:\s*(.+)$/;

  for (const raw of lines) {
    const s = raw.trim();
    if (!s) continue;

    // Skip obvious non-dialogue
    if (/^(INT\.|EXT\.|SCENE\s)/i.test(s)) continue;
    if (/^https?:\/\//i.test(s)) continue;
    if (/^\d{1,3}\s*$/.test(s)) continue; // page number
    if (/^[A-Z0-9 .\-]+$/.test(s) && s.length > 4 && !/:/.test(s)) continue; // ALL-CAPS action/cues

    const m = s.match(re);
    if (m) {
      const speaker = m[1].trim();
      const lineText = m[2].trim();
      if (speaker && lineText) scene.lines.push({ speaker, text: lineText });
    }
  }

  return [scene];
}

/**
 * Extract text content from a PDF buffer using pdf.js TEXT ONLY.
 * We never call page.render() (no node-canvas), which avoids Render crashes.
 */
async function extractPdfTextOnly(buf: Buffer, maxPages = 50): Promise<{ text: string; meta: ParserMeta }> {
  const meta: ParserMeta = {
    pathUsed: "text-only",
    pageCount: 0,
    pagesRead: 0,
    rawLength: 0,
    scannedSuspected: false,
    timedOut: false,
  };

  let doc: PDFDocumentProxy | null = null;
  try {
    doc = await pdfjs.getDocument({ data: buf }).promise;
  } catch (_err) {
    meta.pathUsed = "open-failed";
    meta.scannedSuspected = true;
    return { text: "", meta };
  }

  meta.pageCount = doc.numPages;
  const pages = Math.min(maxPages, doc.numPages);

  const chunks: string[] = [];
  for (let i = 1; i <= pages; i++) {
    try {
      const page = await doc.getPage(i);
      const tc: TextContent = await page.getTextContent(); // TEXT LAYER ONLY
      const joined = (tc.items as any[])
        .map((it: any) => ("str" in it ? it.str : ""))
        .join(" ")
        .replace(/\s{2,}/g, " ")
        .trim();
      if (joined) chunks.push(joined);
      meta.pagesRead = (meta.pagesRead || 0) + 1;
    } catch {
      // ignore per-page failures; keep going
    }
  }

  const text = chunks.join("\n\n");
  meta.rawLength = text.length;

  const charCount = text.replace(/\s/g, "").length;
  if (charCount < 40 || (meta.pagesRead || 0) === 0) {
    meta.pathUsed = "text-empty";
    meta.scannedSuspected = true;
  }

  return { text, meta };
}

/**
 * The original API your routes expect.
 * - Returns scenes derived from the text-only extractor
 * - Adds meta (with scannedSuspected when text looks empty)
 */
export async function parseArrayBufferWithMeta(buf: Buffer): Promise<{ scenes: Scene[]; meta: ParserMeta }> {
  const { text, meta } = await extractPdfTextOnly(buf, 50);
  const scenes = analyzeScriptText(text, false);
  return { scenes, meta };
}
