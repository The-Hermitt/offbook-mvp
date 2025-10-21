import type { PDFDocumentProxy, TextContent } from "pdfjs-dist";
import * as pdfjs from "pdfjs-dist/legacy/build/pdf";

/**
 * Extract text from a PDF buffer using pdf.js text layer only.
 * We never call page.render() (no node-canvas), which avoids crashes on Render.
 */
export async function extractPdfText(
  buf: Buffer,
  maxPages = 50
): Promise<{ text: string; meta: PdfExtractMeta }> {
  const meta: PdfExtractMeta = {
    pageCount: 0,
    pagesRead: 0,
    pathUsed: "text-only",
    timedOut: false,
    scannedSuspected: false,
  };

  let doc: PDFDocumentProxy | null = null;
  try {
    doc = await pdfjs.getDocument({ data: buf }).promise;
  } catch (err) {
    meta.pathUsed = "open-failed";
    meta.scannedSuspected = true;
    return { text: "", meta };
  }

  meta.pageCount = doc.numPages;
  const pages = Math.min(maxPages, doc.numPages);

  const out: string[] = [];
  for (let i = 1; i <= pages; i++) {
    try {
      const page = await doc.getPage(i);
      const tc: TextContent = await page.getTextContent();
      const line = (tc.items as any[])
        .map((it: any) => ("str" in it ? it.str : ""))
        .join(" ")
        .replace(/\s{2,}/g, " ")
        .trim();
      if (line) out.push(line);
      meta.pagesRead++;
    } catch {
      // ignore page error; keep going
    }
  }

  const text = out.join("\n\n");
  const charCount = text.replace(/\s/g, "").length;

  if (charCount < 40 || meta.pagesRead === 0) {
    meta.scannedSuspected = true;
    meta.pathUsed = "text-empty";
  }

  return { text, meta };
}

export type PdfExtractMeta = {
  pageCount: number;
  pagesRead: number;
  pathUsed: "text-only" | "open-failed" | "text-empty";
  timedOut: boolean;
  scannedSuspected: boolean;
};

/**
 * Back-compat helper used by routes: parses a PDF upload.
 * Routes can decide:
 * - If meta.scannedSuspected === true -> respond { scanned:true } (let client OCR silently)
 * - Else -> continue to parse script text -> scenes
 */
export async function parseUploadedPdf(
  buf: Buffer
): Promise<{ text: string; meta: PdfExtractMeta }> {
  return extractPdfText(buf, 50);
}

/**
 * Exported text analyzer (back-compat).
 * Some parts of the app import { analyzeScriptText } from "./lib/pdf.js".
 * Provide it here so those imports stop failing.
 *
 * Very simple heuristic: split lines, keep ONLY dialog in the form:
 *   NAME: dialogue
 *   NAME (parenthetical): dialogue
 * Skip scene headings (INT./EXT./SCENE), ALL-CAPS action, URLs, page numbers.
 */
export function analyzeScriptText(text: string): {
  scenes: { id: string; title: string; lines: { speaker: string; text: string }[] }[];
  roles: string[];
} {
  const lines = text.replace(/\r/g, "").split("\n");
  const scene = { id: "s1", title: "Scene 1", lines: [] as { speaker: string; text: string }[] };
  const roleSet = new Set<string>();

  for (const raw of lines) {
    const s = raw.trim();
    if (!s) continue;

    // Skip obvious non-dialogue
    if (/^(INT\.|EXT\.|SCENE\s)/i.test(s)) continue;
    if (/^https?:\/\//i.test(s)) continue;
    if (/^\d{1,3}\s*$/.test(s)) continue; // page #
    if (/^[A-Z0-9 .\-]+$/.test(s) && s.length > 4 && !/:/.test(s)) {
      // Likely ALL-CAPS action or standalone character cue; skip as dialogue line
      continue;
    }

    // Match NAME: text  or  NAME (xxx): text
    const m = s.match(/^([A-Z][A-Z0-9 ]{1,})(?:\s*\([^)]*\))?:\s*(.+)$/);
    if (m) {
      const speaker = m[1].trim();
      const lineText = m[2].trim();
      scene.lines.push({ speaker, text: lineText });
      roleSet.add(speaker);
    }
  }

  const scenes = [scene];
  const roles = Array.from(roleSet).sort();
  return { scenes, roles };
}
