import fs from "fs";
import path from "path";
import type { PDFDocumentProxy, TextContent } from "pdfjs-dist";
import * as pdfjs from "pdfjs-dist/legacy/build/pdf";

const OCR_ENABLED = process.env.OCR_ENABLED === "1"; // we won't do server OCR; just set signal flags

/**
 * Load a PDF from a Buffer and extract text only.
 * IMPORTANT: We never call page.render() (no node-canvas). This avoids the
 * "Failed to unwrap exclusive reference of CanvasElement" crash on Render.
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

  // Load PDF (no canvas factories)
  let doc: PDFDocumentProxy | null = null;
  try {
    doc = await pdfjs.getDocument({ data: buf }).promise;
  } catch (err) {
    // If pdf.js can't even open it, mark as scannedSuspected so client can OCR.
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
      // Join with spaces and basic noise trim
      const line = tc.items
        .map((it: any) => ("str" in it ? it.str : ""))
        .join(" ")
        .replace(/\s{2,}/g, " ")
        .trim();
      if (line) {
        out.push(line);
      }
      meta.pagesRead++;
    } catch (e) {
      // Non-fatal: keep going
    }
  }

  const text = out.join("\n\n");

  // Heuristic: if there is almost no text, it's probably a scan.
  const charCount = text.replace(/\s/g, "").length;
  if (charCount < 40 || meta.pagesRead === 0) {
    // If OCR is "enabled" server-side, we still DO NOT OCR here.
    // We simply signal the client that OCR is needed.
    meta.pathUsed = OCR_ENABLED ? "stub" : "text-empty";
    meta.scannedSuspected = true;
  }

  return { text, meta };
}

export type PdfExtractMeta = {
  pageCount: number;
  pagesRead: number;
  pathUsed: "text-only" | "stub" | "open-failed" | "text-empty";
  timedOut: boolean;
  scannedSuspected: boolean;
};

/**
 * Convenience wrapper used by the upload route.
 * Returns { text, meta }. The caller decides how to proceed (parse → scenes).
 */
export async function parseUploadedPdf(
  buf: Buffer
): Promise<{ text: string; meta: PdfExtractMeta }> {
  // We explicitly DO NOT run any canvas render or server OCR here.
  return extractPdfText(buf, 50);
}
