// src/http-routes.ts
import type { Express, Request, Response, NextFunction } from "express";
import express from "express";
import multer from "multer";
import path from "path";
import fs from "fs";
import crypto from "crypto";

// Optional, lazy-loaded OCR/PDF deps
type PdfParseModule = (buffer: Buffer) => Promise<{ text: string }>;
type TesseractWorker = {
  recognize: (data: Buffer | string, lang?: string) => Promise<{ data: { text: string } }>;
  terminate: () => Promise<void>;
};

// Shared-secret guard (cloak with 404 if missing/wrong)
function secretGuard(req: Request, res: Response, next: NextFunction) {
  const required = process.env.SHARED_SECRET;
  if (!required) return next();
  const provided = req.header("X-Shared-Secret");
  if (provided && provided === required) return next();
  return res.status(404).send("Not Found");
}

// In-memory state (MVP)
type SceneLine = { speaker: string; text: string };
type Scene = { id: string; title: string; lines: SceneLine[] };
type Script = { id: string; title: string; text: string; scenes: Scene[]; voiceMap?: Record<string, string> };

const scripts = new Map<string, Script>();
const renders = new Map<string, { status: "queued" | "working" | "complete" | "error"; file?: string; err?: string }>();

// Assets dir
const ASSETS_DIR = path.join(process.cwd(), "assets");
if (!fs.existsSync(ASSETS_DIR)) fs.mkdirSync(ASSETS_DIR, { recursive: true });

// -------------------------
// Parser (supports two styles)
// -------------------------
function parseScenesFromText(text: string): Scene[] {
  const lines = text.split(/\r?\n/);

  const isAllCapsWordy = (s: string) =>
    /^[A-Z0-9 ,.'"?!\-:;()]+$/.test(s) && s === s.toUpperCase() && s.replace(/\s+/g, "").length > 3;

  const isSceneHeading = (s: string) => /^\s*(INT\.|EXT\.|SCENE\b)/i.test(s.trim());
  const isLikelyHeaderFooter = (s: string) => /(page \d+|actors access|breakdown services|http|https|www\.)/i.test(s);
  const isOnlyParen = (s: string) => /^\s*\([^)]*\)\s*$/.test(s);
  const colonLine = (s: string) => s.match(/^\s*([A-Z][A-Z0-9 _&'.-]{1,30})\s*:\s*(.+)$/);

  const sceneId = crypto.randomUUID();
  const scene: Scene = { id: sceneId, title: "Scene 1", lines: [] };

  // Pass 1: try colon style anywhere
  for (const raw of lines) {
    const s = raw.replace(/\t/g, " ").trimRight();
    if (!s.trim()) continue;
    if (isSceneHeading(s) || isOnlyParen(s) || isLikelyHeaderFooter(s)) continue;
    const m = colonLine(s);
    if (m) scene.lines.push({ speaker: m[1].trim(), text: m[2].trim() });
  }

  // If we already got dialogue, return
  if (scene.lines.length) return [scene];

  // Pass 2: screenplay blocks:
  // NAME (all caps, shortish), optional parenthetical, then one or more dialogue lines until blank or next NAME
  let i = 0;
  while (i < lines.length) {
    let line = lines[i].replace(/\t/g, " ").trimRight();
    i++;

    if (!line.trim()) continue;
    if (isSceneHeading(line) || isLikelyHeaderFooter(line)) continue;

    // Candidate speaker line: all caps, mostly letters, 2–30 chars
    const candidate = line.trim();
    if (/^[A-Z][A-Z0-9 '&.-]{1,29}$/.test(candidate) && isAllCapsWordy(candidate)) {
      const speaker = candidate;

      // Optional parenthetical on next line
      if (i < lines.length && isOnlyParen(lines[i].trim())) i++;

      // Gather dialogue lines
      const buf: string[] = [];
      while (i < lines.length) {
        const peek = lines[i].trimRight();
        const isBlank = !peek.trim();
        const nextIsSpeaker = /^[A-Z][A-Z0-9 '&.-]{1,29}$/.test(peek) && isAllCapsWordy(peek);
        const nextIsHeader = isSceneHeading(peek) || isLikelyHeaderFooter(peek);

        if (isBlank || nextIsSpeaker || nextIsHeader) break;

        // skip pure parenthetical lines inside dialogue
        if (!isOnlyParen(peek)) buf.push(peek);
        i++;
      }

      const text = buf.join(" ").replace(/\s+/g, " ").trim();
      if (text) scene.lines.push({ speaker, text });
      continue;
    }
  }

  return [scene];
}

// Silent MP3 (stub)
function writeSilentMp3(renderId: string): string {
  const safe = renderId.replace(/[^a-zA-Z0-9_-]/g, "_");
  const file = path.join(ASSETS_DIR, `${safe}.mp3`);
  if (!fs.existsSync(file)) fs.writeFileSync(file, Buffer.from([]));
  return file;
}

// Upload (accept PDF or image)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 20 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const ok =
      file.mimetype === "application/pdf" ||
      file.mimetype === "image/png" ||
      file.mimetype === "image/jpeg" ||
      file.mimetype === "image/jpg";
    cb(ok ? null : new Error("Unsupported file type"), ok);
  },
});

// Lazy OCR/PDF helpers
async function importPdfParse(): Promise<PdfParseModule | null> {
  try {
    // @ts-ignore
    const mod = await import("pdf-parse");
    return (mod.default || mod) as PdfParseModule;
  } catch { return null; }
}
async function newTesseractWorker(): Promise<TesseractWorker | null> {
  try {
    const tesseract = await import("tesseract.js");
    const { createWorker } = (tesseract as any);
    const worker = await createWorker({ logger: () => {} });
    await worker.load(); await worker.loadLanguage("eng"); await worker.initialize("eng");
    return worker as TesseractWorker;
  } catch { return null; }
}
async function rasterizePdfToPngBuffers(pdfBuffer: Buffer, maxPages = 3): Promise<Buffer[]> {
  const pdfjs = await import("pdfjs-dist/legacy/build/pdf.js");
  const { createCanvas } = await import("canvas");
  const loadingTask = (pdfjs as any).getDocument({ data: pdfBuffer });
  const pdf = await loadingTask.promise;
  const n = Math.min(pdf.numPages, maxPages);
  const out: Buffer[] = [];
  for (let p = 1; p <= n; p++) {
    const page = await pdf.getPage(p);
    const viewport = page.getViewport({ scale: 2.0 });
    const canvas = createCanvas(viewport.width, viewport.height);
    const ctx = canvas.getContext("2d") as any;
    await page.render({ canvasContext: ctx, viewport }).promise;
    out.push(canvas.toBuffer("image/png"));
  }
  return out;
}
async function extractTextFromPdf(buffer: Buffer): Promise<string> {
  const pdfParse = await importPdfParse();
  if (pdfParse) {
    try {
      const { text } = await pdfParse(buffer);
      if (text && text.replace(/\s+/g, " ").trim().length >= 40) return text;
    } catch {}
  }
  const worker = await newTesseractWorker();
  if (!worker) return "";
  try {
    const pngs = await rasterizePdfToPngBuffers(buffer, 3);
    let ocr = "";
    for (const img of pngs) {
      const res = await worker.recognize(img, "eng");
      ocr += (res?.data?.text || "") + "\n";
      if (ocr.replace(/\s+/g, " ").trim().length >= 40) break;
    }
    await worker.terminate();
    return ocr;
  } catch {
    try { await worker.terminate(); } catch {}
    return "";
  }
}
async function extractTextFromImage(buffer: Buffer): Promise<string> {
  const worker = await newTesseractWorker();
  if (!worker) return "";
  try {
    const res = await worker.recognize(buffer, "eng");
    await worker.terminate();
    return res?.data?.text || "";
  } catch {
    try { await worker.terminate(); } catch {}
    return "";
  }
}
async function extractTextAuto(buffer: Buffer, mime: string): Promise<string> {
  return mime === "application/pdf" ? extractTextFromPdf(buffer) : extractTextFromImage(buffer);
}

// Absolute BASE for download_url
function baseUrlFrom(req: Request): string {
  const env = process.env.BASE_URL?.trim();
  if (env) return env.replace(/\/$/, "");
  const proto = (req.headers["x-forwarded-proto"] as string) || req.protocol || "https";
  const host = req.headers["x-forwarded-host"] || req.get("host");
  return `${proto}://${host}`;
}

// Public API
export function initHttpRoutes(app: Express) {
  const debug = express.Router();
  const api = express.Router();

  debug.use(secretGuard);

  // Paste text
  debug.post("/upload_script_text", (req: Request, res: Response) => {
    const { title, text } = req.body || {};
    if (!title || !text) return res.status(400).json({ error: "title and text are required" });
    const id = crypto.randomUUID();
    const scenes = parseScenesFromText(String(text));
    const script: Script = { id, title: String(title), text: String(text), scenes };
    scripts.set(id, script);
    res.json({ script_id: id, scene_count: scenes.length });
  });

  // PDF/Image upload (OCR fallback)
  debug.post("/upload_script_upload", upload.single("pdf"), async (req: Request, res: Response) => {
    try {
      const title = String(req.body?.title || "Uploaded Script");
      if (!req.file?.buffer || !req.file.mimetype) return res.status(400).json({ error: "missing file" });
      if (req.file.size > 20 * 1024 * 1024) return res.status(413).json({ error: "file too large" });

      const extracted = (await extractTextAuto(req.file.buffer, req.file.mimetype)) || req.file.buffer.toString("utf8");
      const scenes = parseScenesFromText(extracted || "");
      const id = crypto.randomUUID();
      const script: Script = { id, title, text: extracted, scenes };
      scripts.set(id, script);

      res.json({ script_id: id, scene_count: scenes.length });
    } catch {
      res.status(500).json({ error: "could not extract text" });
    }
  });

  // Scenes
  debug.get("/scenes", (req: Request, res: Response) => {
    const scriptId = String(req.query.script_id || "");
    if (!scriptId || !scripts.has(scriptId)) return res.status(404).json({ error: "script not found" });
    const script = scripts.get(scriptId)!;
    res.json({ script_id: script.id, scenes: script.scenes });
  });

  // Voice map
  debug.post("/set_voice", (req: Request, res: Response) => {
    const { script_id, voice_map } = req.body || {};
    if (!script_id || !scripts.has(script_id)) return res.status(404).json({ error: "script not found" });
    if (!voice_map || typeof voice_map !== "object") return res.status(400).json({ error: "voice_map required" });
    const script = scripts.get(script_id)!;
    script.voiceMap = { ...(script.voiceMap || {}), ...voice_map };
    scripts.set(script_id, script);
    res.json({ ok: true });
  });

  // Render (stub)
  debug.post("/render", (req: Request, res: Response) => {
    const { script_id, scene_id, role } = req.body || {};
    if (!script_id || !scene_id || !role) return res.status(400).json({ error: "script_id, scene_id, role required" });
    if (!scripts.has(script_id)) return res.status(404).json({ error: "script not found" });
    const renderId = crypto.randomUUID();
    renders.set(renderId, { status: "working" });
    const file = writeSilentMp3(renderId);
    renders.set(renderId, { status: "complete", file });
    res.json({ render_id: renderId, status: "complete" });
  });

  // Render status
  debug.get("/render_status", (req: Request, res: Response) => {
    const rid = String(req.query.render_id || "");
    if (!rid || !renders.has(rid)) return res.status(404).json({ status: "error", error: "render not found" });
    const job = renders.get(rid)!;
    const payload: any = { status: job.status };
    if (job.status === "complete" && job.file) {
      const base = baseUrlFrom(req);
      const id = path.basename(job.file, ".mp3");
      payload.download_url = `${base}/api/assets/${id}`;
    }
    res.json(payload);
  });

  // Mount routers
  app.use("/debug", debug);
  api.get("/assets/:render_id", (req: Request, res: Response) => {
    const file = path.join(ASSETS_DIR, `${String(req.params.render_id)}.mp3`);
    if (!fs.existsSync(file)) return res.status(404).send("Not Found");
    res.setHeader("Content-Type", "audio/mpeg");
    fs.createReadStream(file).pipe(res);
  });
  app.use("/api", api);
}
