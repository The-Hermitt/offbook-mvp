// src/tools/upload-script.ts
import { z } from "zod";
import fs from "node:fs";
import { nanoid } from "nanoid";

import { downloadPDF, parsePDF } from "../lib/pdf.js";
import {
  insertScript, insertScene, insertLine, countScenes,
} from "../lib/db.js";

export const uploadScriptSchema = z.object({
  pdf_url: z.string().url(),
  title: z.string().min(1).max(255),
});

/**
 * Upload and parse a script PDF into the JSON store.
 * Returns { script_id, title, scenes_found }
 */
export async function uploadScript(userId: string | null, params: unknown) {
  const { pdf_url, title } = uploadScriptSchema.parse(params);

  if (!/^https?:\/\//i.test(pdf_url)) {
    throw new Error("pdf_url must start with http:// or https://");
  }

  const pdfPath = await downloadPDF(pdf_url);
  const buffer = fs.readFileSync(pdfPath);
  const parsed: any = await parsePDF(buffer);

  if (!parsed || !Array.isArray(parsed.scenes)) {
    throw new Error("Parser returned unexpected shape (no scenes array).");
  }

  const scriptId = insertScript(String(title), String(pdf_url));

  let sOrd = 0;
  for (const scene of parsed.scenes) {
    const sceneId = insertScene(scriptId, String(scene?.title ?? `Scene ${sOrd + 1}`), sOrd++);
    let lOrd = 0;
    const lines = Array.isArray(scene?.lines) ? scene.lines : [];
    for (const ln of lines) {
      insertLine(sceneId, String(ln?.character ?? "UNKNOWN"), String(ln?.text ?? ""), lOrd++);
    }
  }

  return {
    script_id: scriptId,
    title,
    scenes_found: countScenes(scriptId),
    user_id: userId ?? null,
    nonce: nanoid(), // keep if something upstream expects it
  };
}
