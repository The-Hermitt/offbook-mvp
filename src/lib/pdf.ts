// src/lib/pdf.ts
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import https from "node:https";
import http from "node:http";

export async function downloadPDF(url: string): Promise<string> {
  const id = crypto.randomUUID();
  const outDir = path.join(process.cwd(), "assets", "pdfs");
  fs.mkdirSync(outDir, { recursive: true });
  const outPath = path.join(outDir, `${id}.pdf`);

  await new Promise<void>((resolve, reject) => {
    const client = url.startsWith("https") ? https : http;
    const file = fs.createWriteStream(outPath);
    const req = client.get(url, (res) => {
      if ((res.statusCode ?? 500) >= 400) {
        reject(new Error(`HTTP ${res.statusCode} downloading ${url}`));
        return;
      }
      res.pipe(file);
      file.on("finish", () => file.close(() => resolve()));
    });
    req.on("error", reject);
  });

  return outPath;
}

// Phase-A STUB: ignore real parsing; return a single simple scene.
export async function parsePDF(_buffer: Buffer) {
  return {
    scenes: [
      {
        id: "scene-1",
        title: "Stub Scene",
        lines: [
          { character: "UNKNOWN", text: "This is a stub line for testing." },
          { character: "UNKNOWN", text: "Use me to validate the pipeline." },
        ],
      },
    ],
  };
}
