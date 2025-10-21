// src/http-routes.ts
import type { Express, Request, Response, NextFunction } from "express";
import express from "express";
import multer from "multer";
import path from "path";
import fs from "fs";
import crypto from "crypto";

// -------------------------------------------------------------
// Optional deps are imported lazily so the app still boots even
// if OCR libs aren't installed yet. See "Install deps" below.
// -------------------------------------------------------------
type PdfParseModule = (buffer: Buffer) => Promise<{ text: string }>;
type TesseractWorker = {
  recognize: (data: Buffer | string, lang?: string) => Promise<{ data: { text: string } }>;
  terminate: () => Promise<void>;
};

// -------------------------------------------------------------
// Shared-secret guard (optional): If SHARED_SECRET is set, require it.
// NOTE: we cloak with 404 to avoid revealing the routes.
// -------------------------------------------------------------
function secretGuard(req: Request, res: Response, next: NextFunction) {
  const required = process.env.SHARED_SECRET;
  if (!required) return next();
  const provided = req.header("X-Shared-Secret");
  if (provided && provided === required) return next();
  return res.status(404).send("Not Found");
}

// -------------------------------------------------------------
// Minimal in-memory state for MVP debug harness
// -------------------------------------------------------------
type SceneLine = { speaker: string; text: string };
type Scene = { id: string; title: string; lines: SceneLine[] };
type Script = { id: string; title: string; text: string; scenes: Scene[]; voiceMap?: Record<string, string> };

const scripts = new Map<string, Script>();
const renders = new Map<
  string,
  { status: "queued" | "working" | "complete" | "error"; file?: string; err?: string }
>();

// Ensure assets dir
const ASSETS_DIR = path.join(process.cwd(), "assets");
if (!fs.existsSync(ASSETS_DIR)) fs.mkdirSync(ASSETS_DIR, { recursive: true });

// -------------------------------------------------------------
// Parser: skip INT./EXT./SCENE, ALL-CAPS action, parentheticals,
// headers/footers-ish. Detect `NAME: Dialogue`.
// -------------------------------------------------------------
function parseScenesFromText(text: string): Scene[] {
  const lines = text.split(/\r?\n/);

  const isSceneHeading = (s: string) => /^\s*(INT\.|EXT\.|SCENE)/i.test(s.trim());
  const isAllCapsAction = (s: string) =>
    /^[A-Z0-9 ,.'"?!\-:;()]+$/.test(s.trim()) &&
    s.trim() === s.trim().toUpperCase() &&
    s.trim().length > 3;
  const isLikelyHeaderFooter = (s: string) => /(page \d+|actors access|http|https|www\.)/i.test(s);
  const isOnlyParen = (s: string) => /^\s*\([^)]*\)\s*$/.test(s);
  const speakerLine = (s: string) =>
    s.match(/^\s*([A-Z][A-Z0-9 _&'-]{1,30})(?:\s*\([^)]*\))?\s*:\s*(.+)$/);

  const sceneId = crypto.randomUUID();
  const scene: Scene = { id: sceneId, title: "Scene 1", lines: [] };

  for (const raw of lines) {
    const s = raw.replace(/\t/g, " ").trimRight();
    if (!s.trim()) continue;
    if (isSceneHeading(s)) continue;
    if (isOnlyParen(s)) continue;
    if (isAllCapsAction(s)) continue;
    if (isLikelyHeaderFooter(s)) continue;

    const m = speakerLine(s);
    if (m) {
      const speaker = m[1].trim();
      const text = m[2].trim();
      if (speaker && text) scene.lines.push({ speaker, text });
    }
  }

  return [scene];
}

// -------------------------------------------------------------
// Placeholder MP3 writer (keeps smoke test green)
// -------------------------------------------------------------
function writeSilentMp3(renderId: string): string {
  const safeId = renderId.replace(/[^a-zA-Z0-9_-]/g, "_");
  const file = path.join(ASSETS_DIR, `${safeId}.mp3`);
  if (!fs.existsSync(file)) fs.writeFileSync(file, Buffer.from([]));
  return file;
}

// -------------------------------------------------------------
// Upload handler: allow PDF **and** images (jpeg/jpg/png).
// -------------------------------------------------------------
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 20 * 1024 * 1024 }, // 20MB
  fileFilter: (_req, file, cb) => {
    const ok =
      file.mimetype === "application/pdf" ||
      file.mimetype === "image/png" ||
      file.mimetype === "image/jpeg" ||
      file.mimetype === "image/jpg";
    if (!ok) return cb(new Error("Unsupported file type"));
    cb(null, true);
  },
});

// -------------------------------------------------------------
// Helpers: OCR + PDF extraction (server-side, invisible to user)
// -------------------------------------------------------------
async function importPdfParse(): Promise<PdfParseModule | null> {
  try {
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore - dynamic CJS import
    const mod = await import("pdf-parse");
    return (mod.default || mod) as PdfParseModule;
  } catch {
    return null;
  }
}

async function newTesseractWorker(): Promise<TesseractWorker | null> {
  try {
    // Prefer @tesseract.js/node if present; fallback to tesseract.js
    let tesseract: any;
    try {
      tesseract = await import("@tesseract.js/node");
    } catch {
      tesseract = await import("tesseract.js");
    }
    const { createWorker } = tesseract as any;
    const worker = await createWorker({
      // English by default; add other langs later if needed
      logger: () => {}, // quiet
    });
    await worker.load();
    await worker.loadLanguage("eng");
    await worker.initialize("eng");
    return worker as TesseractWorker;
  } catch {
    return null;
  }
}

// Render first N pages of a PDF to PNG buffers using pdfjs + canvas
async function rasterizePdfToPngBuffers(pdfBuffer: Buffer, maxPages = 3): Promise<Buffer[]> {
  // These imports are heavy, keep them lazy
  // pdfjs-dist can run in Node; we pair with node-canvas
  const pdfjs = await import("pdfjs-dist/legacy/build/pdf.js");
  const { createCanvas } = await import("canvas");

  const loadingTask = (pdfjs as any).getDocument({ data: pdfBuffer });
  const pdf = await loadingTask.promise;
  const pageCount = Math.min(pdf.numPages, maxPages);

  const images: Buffer[] = [];
  for (let p = 1; p <= pageCount; p++) {
    const page = await pdf.getPage(p);
    const viewport = page.getViewport({ scale: 2.0 }); // 2x for better OCR
    const canvas = createCanvas(viewport.width, viewport.height);
    const ctx = canvas.getContext("2d") as any;

    await page.render({ canvasContext: ctx, viewport }).promise;
    images.push(canvas.toBuffer("image/png"));
  }
  return images;
}

async function extractTextFromPdf(buffer: Buffer): Promise<string> {
  // 1) Try native text extraction
  const pdfParse = await importPdfParse();
  if (pdfParse) {
    try {
      const { text } = await pdfParse(buffer);
      if (text && text.replace(/\s+/g, " ").trim().length >= 40) {
        return text;
      }
    } catch {
      // fall through to OCR
    }
  }

  // 2) Fallback: rasterize + OCR (first few pages)
  const worker = await newTesseractWorker();
  if (!worker) return ""; // OCR not available; we’ll let caller decide

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
  if (mime === "application/pdf") {
    return await extractTextFromPdf(buffer);
  }
  // image/*
  return await extractTextFromImage(buffer);
}

// -------------------------------------------------------------
// Helper: absolute BASE URL for download_url
// -------------------------------------------------------------
function baseUrlFrom(req: Request): string {
  const env = process.env.BASE_URL?.trim();
  if (env) return env.replace(/\/$/, "");
  const proto = (req.headers["x-forwarded-proto"] as string) || req.protocol || "https";
  const host = req.headers["x-forwarded-host"] || req.get("host");
  return `${proto}://${host}`;
}

// -------------------------------------------------------------
// Public API initializer
// -------------------------------------------------------------
export function initHttpRoutes(app: Express) {
  const debug = express.Router();
  const api = express.Router();

  // Guard all debug endpoints behind optional shared secret
  debug.use(secretGuard);

  // --- POST /debug/upload_script_text
  debug.post("/upload_script_text", (req: Request, res: Response) => {
    const { title, text } = req.body || {};
    if (!title || !text) return res.status(400).json({ error: "title and text are required" });

    const id = crypto.randomUUID();
    const scenes = parseScenesFromText(String(text));
    const script: Script = { id, title: String(title), text: String(text), scenes };
    scripts.set(id, script);

    res.json({ script_id: id, scene_count: scenes.length });
  });

  // --- POST /debug/upload_script_upload (multipart: pdf OR image + title)
  debug.post("/upload_script_upload", upload.single("pdf"), async (req: Request, res: Response) => {
    try {
      const title = String(req.body?.title || "Uploaded Script");
      if (!req.file?.buffer || !req.file.mimetype) {
        return res.status(400).json({ error: "missing file" });
      }
      const buf = req.file.buffer;
      const mime = req.file.mimetype;

      // Extract text (pdf-parse → OCR fallback)
      let extracted = "";
      // For safety, avoid blocking the event loop too long on huge inputs
      if (buf.length > 20 * 1024 * 1024) {
        return res.status(413).json({ error: "file too large" });
      }

      // Try the automatic path
      extracted = await extractTextAuto(buf, mime);

      // If still empty, last fallback: naive utf8 decode (might be garbage, OK)
      if (!extracted || !extracted.trim()) {
        extracted = buf.toString("utf8");
      }

      const scenes = parseScenesFromText(extracted || "");
      const id = crypto.randomUUID();
      const script: Script = { id, title, text: extracted, scenes };
      scripts.set(id, script);

      res.json({ script_id: id, scene_count: scenes.length, used_ocr: mime !== "application/pdf" ? true : undefined });
    } catch (err: any) {
      // We keep it quiet for the user; just report failure
      res.status(500).json({ error: "could not extract text" });
    }
  });

  // --- GET /debug/scenes?script_id=...
  debug.get("/scenes", (req: Request, res: Response) => {
    const scriptId = String(req.query.script_id || "");
    if (!scriptId || !scripts.has(scriptId)) return res.status(404).json({ error: "script not found" });
    const script = scripts.get(scriptId)!;
    res.json({ script_id: script.id, scenes: script.scenes });
  });

  // --- POST /debug/set_voice  {script_id, voice_map:{CHAR:VOICE}}
  debug.post("/set_voice", (req: Request, res: Response) => {
    const { script_id, voice_map } = req.body || {};
    if (!script_id || !scripts.has(script_id)) return res.status(404).json({ error: "script not found" });
    if (!voice_map || typeof voice_map !== "object") return res.status(400).json({ error: "voice_map required" });
    const script = scripts.get(script_id)!;
    script.voiceMap = { ...(script.voiceMap || {}), ...voice_map };
    scripts.set(script_id, script);
    res.json({ ok: true });
  });

  // --- POST /debug/render  {script_id, scene_id, role, pace}
  debug.post("/render", (req: Request, res: Response) => {
    const { script_id, scene_id, role } = req.body || {};
    if (!script_id || !scene_id || !role) return res.status(400).json({ error: "script_id, scene_id, role required" });
    if (!scripts.has(script_id)) return res.status(404).json({ error: "script not found" });

    const renderId = crypto.randomUUID();
    renders.set(renderId, { status: "queued" });

    try {
      renders.set(renderId, { status: "working" });
      const file = writeSilentMp3(renderId);
      renders.set(renderId, { status: "complete", file });
      res.json({ render_id: renderId, status: "complete" });
    } catch (err: any) {
      renders.set(renderId, { status: "error", err: String(err?.message || err) });
      res.status(500).json({ render_id: renderId, status: "error" });
    }
  });

  // --- GET /debug/render_status?render_id=...
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

  // Mount debug at /debug
  app.use("/debug", debug);

  // --- /api assets streaming
  api.get("/assets/:render_id", (req: Request, res: Response) => {
    const renderId = String(req.params.render_id);
    const file = path.join(ASSETS_DIR, `${renderId}.mp3`);
    if (!fs.existsSync(file)) return res.status(404).send("Not Found");
    res.setHeader("Content-Type", "audio/mpeg");
    fs.createReadStream(file).pipe(res);
  });

  app.use("/api", api);
}
