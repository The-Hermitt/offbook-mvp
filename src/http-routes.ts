// src/http-routes.ts
import type { Express, Request, Response, NextFunction } from "express";
import express from "express";
import multer from "multer";
import * as path from "path";
import * as fs from "fs";
import * as os from "os";
import crypto from "crypto";
import { spawn, execFileSync } from "child_process";
import db, { dbGet, dbAll, dbRun, USING_POSTGRES, listByUserAsync, getByIdAsync, saveAsync, deleteByIdAsync, updateNotesAsync } from "./lib/db";
import { generateReaderMp3, ttsProvider } from "./lib/tts";
import { isSttEnabled, transcribeChunk } from "./lib/stt";
import { makeAuditMiddleware } from "./lib/audit";
import { makeRateLimiters } from "./middleware/rateLimit";
import { getPasskeySession, noteRenderComplete, ensureSid } from "./routes/auth";
import { r2Enabled, r2PutFile, r2GetObjectStream, r2Head, r2Delete } from "./lib/r2";

// ---------- Types ----------
type SceneLine = { speaker: string; text: string };
type Scene = { id: string; title: string; lines: SceneLine[] };
type Script = { id: string; title: string; text: string; scenes: Scene[]; voiceMap?: Record<string, string> };

type PdfParseModule = (buffer: Buffer) => Promise<{ text: string }>;
type TesseractWorker = {
  recognize: (data: Buffer | string, lang?: string) => Promise<{ data: { text: string } }>;
  terminate: () => Promise<void>;
};

// ---------- Optional shared-secret guard ----------
function secretGuard(req: Request, res: Response, next: NextFunction) {
  const required = process.env.SHARED_SECRET;
  if (!required) return next();

  // Check header first
  const providedHeader = req.header("X-Shared-Secret");
  if (providedHeader && providedHeader === required) return next();

  // Check query param (for Safari/browser convenience)
  const providedQuery = req.query.secret;
  if (providedQuery && providedQuery === required) return next();

  return res.status(404).send("Not Found");
}

// ---------- In-memory state ----------
const scripts = new Map<string, Script>();
const renders = new Map<string, {
  status: "queued" | "working" | "complete" | "error";
  file?: string;
  err?: string;
  accounted?: boolean;
}>();

type ScriptRow = {
  id: string;
  user_id: string;
  title: string;
  scene_count: number;
  scenes_json: string;
  created_at?: string;
  updated_at?: string;
};

// Persist Script + scenes into the SQLite `scripts` table.
// We store scenes (and optional voiceMap) in `scenes_json` as a JSON payload.
function serializeScriptScenes(script: Script): string {
  const payload: any = {
    scenes: Array.isArray(script.scenes) ? script.scenes : [],
  };
  if (script.voiceMap && typeof script.voiceMap === "object") {
    payload.voiceMap = script.voiceMap;
  }
  return JSON.stringify(payload);
}

function deserializeScriptRow(row: ScriptRow): Script | null {
  try {
    const parsed = row.scenes_json ? JSON.parse(row.scenes_json) : null;
    let scenes: Scene[] = [];
    let voiceMap: Record<string, string> | undefined;

    if (Array.isArray(parsed)) {
      // Legacy payload: just an array of scenes
      scenes = parsed as Scene[];
    } else if (parsed && typeof parsed === "object") {
      if (Array.isArray(parsed.scenes)) {
        scenes = parsed.scenes as Scene[];
      }
      if (parsed.voiceMap && typeof parsed.voiceMap === "object") {
        voiceMap = parsed.voiceMap as Record<string, string>;
      }
    }

    const script: Script = {
      id: row.id,
      title: row.title,
      text: "", // we don't persist full text yet; not needed for current flows
      scenes,
    };
    if (voiceMap) {
      script.voiceMap = voiceMap;
    }
    return script;
  } catch (err) {
    console.error("[scripts] failed to parse scenes_json for script", row.id, err);
    return null;
  }
}

async function saveScriptToDb(script: Script, userId: string) {
  if (!userId || !userId.trim()) {
    throw new Error("saveScriptToDb: userId is required");
  }

  const scenesJson = serializeScriptScenes(script);
  const sceneCount = Array.isArray(script.scenes) ? script.scenes.length : 0;

  try {
    // Check if script exists
    const existing = await dbGet<{ id: string }>("SELECT id FROM scripts WHERE id = ?", [script.id]);

    if (existing) {
      // Update existing script
      await dbRun(
        "UPDATE scripts SET title = ?, scene_count = ?, scenes_json = ? WHERE id = ?",
        [script.title, sceneCount, scenesJson, script.id]
      );
    } else {
      // Insert new script
      await dbRun(
        "INSERT INTO scripts (id, user_id, title, scene_count, scenes_json) VALUES (?, ?, ?, ?, ?)",
        [script.id, userId.trim(), script.title, sceneCount, scenesJson]
      );
    }
  } catch (err) {
    console.error("[scripts] failed to upsert script", script.id, err);
  }
}

async function loadScriptFromDb(scriptId: string, userId: string): Promise<Script | null> {
  if (!scriptId || !scriptId.trim() || !userId || !userId.trim()) return null;
  try {
    const row = await dbGet<ScriptRow>(
      "SELECT id, user_id, title, scene_count, scenes_json FROM scripts WHERE id = ? AND user_id = ?",
      [scriptId, userId]
    );
    if (!row) return null;
    return deserializeScriptRow(row);
  } catch (err) {
    console.error("[scripts] failed to load script", scriptId, userId, err);
    return null;
  }
}

// Helper that prefers in-memory cache but can rehydrate from DB.
async function getOrLoadScript(scriptId: string, userId: string): Promise<Script | null> {
  if (!userId || !userId.trim()) return null;

  const cacheKey = `${userId}:${scriptId}`;
  const cached = scripts.get(cacheKey);
  if (cached) return cached;

  const loaded = await loadScriptFromDb(scriptId, userId);
  if (loaded) {
    scripts.set(cacheKey, loaded);
    return loaded;
  }
  return null;
}

function getUserIdOr401(req: Request, res: Response): string | null {
  const { passkeyLoggedIn, userId } = getPasskeySession(req as any);
  if (passkeyLoggedIn && userId) {
    return userId;
  }
  res.status(401).json({ error: "not_logged_in" });
  return null;
}

function requireUser(req: Request, res: Response, next: NextFunction) {
  const userId = getUserIdOr401(req, res);
  if (!userId) return;
  const userObj = (req as any).user || { id: userId };
  (req as any).user = userObj;
  res.locals.user = res.locals.user || userObj;
  next();
}

// ---------- Assets dir ----------
const ASSETS_DIR = path.join(process.cwd(), "assets");
if (!fs.existsSync(ASSETS_DIR)) fs.mkdirSync(ASSETS_DIR, { recursive: true });
const UPLOADS_TMP_DIR = path.join(process.cwd(), "uploads", "tmp");
if (!fs.existsSync(UPLOADS_TMP_DIR)) fs.mkdirSync(UPLOADS_TMP_DIR, { recursive: true });
const galleryUpload = multer({
  dest: UPLOADS_TMP_DIR,
});

// ---------- Parser: supports `NAME: line` and screenplay blocks ----------
function parseScenesFromText(text: string): Scene[] {
  const lines = text.split(/\r?\n/);

  const isAllCapsWordy = (s: string) =>
    /^[A-Z0-9 ,.'"?!\-:;()]+$/.test(s) &&
    s === s.toUpperCase() &&
    s.replace(/\s+/g, "").length > 3;

  const isSceneHeading = (s: string) => /^\s*(INT\.|EXT\.|SCENE\b)/i.test(s.trim());
  const isLikelyHeaderFooter = (s: string) => /(page \d+|actors access|breakdown services|http|https|www\.)/i.test(s);
  const isOnlyParen = (s: string) => /^\s*\([^)]*\)\s*$/.test(s);
  const colonLine = (s: string) => s.match(/^\s*([A-Z][A-Z0-9 _&'.-]{1,30})\s*:\s*(.+)$/);

  const scene: Scene = { id: crypto.randomUUID(), title: "Scene 1", lines: [] };

  // Pass 1: NAME: dialogue
  for (const raw of lines) {
    const s = raw.replace(/\t/g, " ").trimRight();
    if (!s.trim()) continue;
    if (isSceneHeading(s) || isOnlyParen(s) || isLikelyHeaderFooter(s)) continue;
    const m = colonLine(s);
    if (m) scene.lines.push({ speaker: m[1].trim(), text: m[2].trim() });
  }
  if (scene.lines.length) return [scene];

  // Pass 2: screenplay blocks (NAME on its own line; optional parenthetical; dialogue lines)
  let i = 0;
  while (i < lines.length) {
    let line = lines[i].replace(/\t/g, " ").trimRight();
    i++;

    if (!line.trim()) continue;
    if (isSceneHeading(line) || isLikelyHeaderFooter(line)) continue;

    const candidate = line.trim();
    if (/^[A-Z][A-Z0-9 '&.-]{1,29}$/.test(candidate) && isAllCapsWordy(candidate)) {
      const speaker = candidate;
      if (i < lines.length && isOnlyParen(lines[i].trim())) i++; // skip parenthetical

      const buf: string[] = [];
      while (i < lines.length) {
        const peek = lines[i].trimRight();
        const isBlank = !peek.trim();
        const nextIsSpeaker = /^[A-Z][A-Z0-9 '&.-]{1,29}$/.test(peek) && isAllCapsWordy(peek);
        const nextIsHeader = isSceneHeading(peek) || isLikelyHeaderFooter(peek);
        if (isBlank || nextIsSpeaker || nextIsHeader) break;
        if (!isOnlyParen(peek)) buf.push(peek);
        i++;
      }
      const t = buf.join(" ").replace(/\s+/g, " ").trim();
      if (t) scene.lines.push({ speaker, text: t });
    }
  }

  return [scene];
}

// ---------- Silent MP3 generation ----------
// 0.5s mono silence @ 44.1kHz, generated via ffmpeg and base64-encoded.
const SILENT_MP3_BASE64 =
  "//uQxAAAAAAAAAAAAAAAAAAAAAAAWGluZwAAAA8AAAACAAADhAC7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7//////////////////////////////////////////////////////////////////8AAAAATGF2YzU4LjEzAAAAAAAAAAAAAAAAJAQKAAAAAAAAA4SJ8+5xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/+xDEAAPAAAGkAAAAIAAANIAAAARMQBVAfAQAb+////vaGJAGC4Pf///6QRdDv/yAHjKf/////+oEMCCf///9QA8ZT//////1AhgQT////qAHjKf//////UAOGUv////9QI4ES/////0AOGUv////+gBw4l/////9ADhlL//////UAOHEv////+oBw4l//////0AOGM//////+gBwxn//////9ADhjP//////oAcMZ///////QA4Yz//////9ADhjP//////oAcMZ///////QA4Y////////UAOGMv//////+gBwxl///////0AOGM///////+gBwxn///////9ADhjP//////oAcMZ////////UAOGUv//////+gBw4l///////0AOGU////////UAOJEv//////+gBxFL//////0AcRS///////oAcRxf//////9AHEQX//////oAcRBf//////UAcRS///////0AcRRf//////oAcRhf//////UAcRy///////0AcRxf//////oAcRxf//////UAcSBf//////0AcSBf//////oA4kC///////UAcSxf//////0AcSxf//////oA4lC////////UAcShf//////+gDiYL///////0AcTBf//////oA4mC////////UAcTRf//////+gDiUL///////0AcShf//////oA4mC////////UAcTBf//////+gDiUL///////0AcShf//////oA4mC////////UAcTBf//////+gDiYL///////0AcShf//////oA4lC////////UAcSxf//////+gDiUL///////0AcShf//////oA4lC////////UAcSxf//////+gDiQL///////0AcSBf//////oA4kC////////UAcRxf//////+gDiQL///////0AcSBf//////oA4kC////////UAcRhf//////+gDiOL///////0AcRxf//////oAcRhf//////9ADiOL//////oAcRxf//////UAcRhf//////0AcRBf//////oAcRBf//////9AHEQX//////oAcRRf//////UAcRBf//////0AHEQX//////oAcRRf//////9ADiKL//////oAcRRf//////UAcRRf//////0AHRSWAAAAP/7EMQA8AAAaQAAAAgAAA0gAAABEv////9AFxFL//////UAXEMv//////9AHEQv//////oAuJAv//////QBxLL//////0AXEsv//////oA4kC///////UBcRS///////9AFxFF//////oA4kC///////UBcRS////////AHEgX//////+gDiQL///////0AXEgX//////oA4kC////////UAcSBf//////+gDiQL///////0AcSxf//////oA4mC////////UAcTBf//////+gDiYL///////0AcTRf//////oA4mC////////UAcTRf//////+gDicL///////0AcThf//////oA4nC////////UAcThf//////+gDikL///////0AcThf//////oA4oC////////UAcTxf//////+gDikL///////0AcThf//////oA4pC////////UAcUBf//////+gDikL///////0AcURf//////oA4pC////////UAcURf//////+gDioL///////0AcURf//////oA4qC////////UAcUhf//////+gDioL///////0AcURf//////oA4rC////////UAcUxf//////+gDiwL///////0AcUxf//////oA4sC////////UAcVBf//////+gDiwL///////0AcVRf//////oA4sC////////UAcVhf//////+gDi0L///////0AcVxf//////oA4tC////////UAcVxf//////+gDi4L///////0AcWBf//////oA4uC////////UAcWBf//////+gDi8L///////0AcWRf//////oA4vC////////UAcWRf//////+gDjAL///////0AcWhf//////oA4wC////////UAcWxf//////+gDjEL///////0AcWxf//////oA4xC////////UAcXBf//////+g==";

function writeSilentMp3(id: string): string {
  const safe = id.replace(/[^\w.-]+/g, "_");
  const file = path.join(ASSETS_DIR, `${safe}.mp3`);
  fs.mkdirSync(ASSETS_DIR, { recursive: true });

  // If a previous file exists and is non-trivial, keep it.
  try {
    if (fs.existsSync(file) && fs.statSync(file).size > 512) return file;
  } catch {}

  // Prefer generating a real MP3 with ffmpeg (Render already uses ffmpeg for mixdown).
  try {
    execFileSync(
      "ffmpeg",
      [
        "-y",
        "-hide_banner",
        "-loglevel",
        "error",
        "-f",
        "lavfi",
        "-i",
        "anullsrc=r=44100:cl=mono",
        "-t",
        "0.5",
        "-q:a",
        "9",
        "-acodec",
        "libmp3lame",
        file,
      ],
      { stdio: "ignore" }
    );
    if (fs.existsSync(file) && fs.statSync(file).size > 512) return file;
  } catch (err) {
    console.warn("[debug/render] ffmpeg silent mp3 generation failed; falling back to embedded silence:", err);
  }

  // Fallback: embedded 0.5s silent MP3 (valid container, non-zero bytes).
  fs.writeFileSync(file, Buffer.from(SILENT_MP3_BASE64, "base64"));
  return file;
}

// ---------- Upload middleware ----------
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 20 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const ok =
      file.mimetype === "application/pdf" ||
      file.mimetype === "image/png" ||
      file.mimetype === "image/jpeg" ||
      file.mimetype === "image/jpg";
    if (ok) {
      cb(null, true);
    } else {
      // reject unsupported types without raising an Error to satisfy TS types
      cb(null, false);
    }
  },
});

// ---------- PDF / OCR helpers ----------
async function importPdfParse(): Promise<PdfParseModule | null> {
  try {
    const mod = await import("pdf-parse");
    return (mod.default || mod) as PdfParseModule;
  } catch {
    return null;
  }
}

async function newTesseractWorker(): Promise<TesseractWorker | null> {
  try {
    const tesseract = await import("tesseract.js");
    const { createWorker } = (tesseract as any);

    // IMPORTANT: no options with logger() → avoids DataCloneError in worker.postMessage
    const worker = await createWorker();
    await worker.load();
    await worker.loadLanguage("eng");
    await worker.initialize("eng");
    return worker as TesseractWorker;
  } catch (e) {
    console.error("[ocr] init failed:", e);
    return null;
  }
}

async function rasterizePdfToPngBuffers(pdfBuffer: Buffer, maxPages = 3): Promise<Buffer[]> {
  const pdfjs = await import("pdfjs-dist/legacy/build/pdf");
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
  } catch (e) {
    console.error("[ocr] pdf ocr failed:", e);
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
  } catch (e) {
    console.error("[ocr] image ocr failed:", e);
    try { await worker.terminate(); } catch {}
    return "";
  }
}

async function extractTextAuto(buffer: Buffer, mime: string): Promise<string> {
  return mime === "application/pdf" ? extractTextFromPdf(buffer) : extractTextFromImage(buffer);
}

function baseUrlFrom(req: Request): string {
  const env = process.env.BASE_URL?.trim();
  if (env) return env.replace(/\/$/, "");
  const proto = (req.headers["x-forwarded-proto"] as string) || req.protocol || "https";
  const host = req.headers["x-forwarded-host"] || req.get("host");
  return `${proto}://${host}`;
}

// ---------- Routes ----------
export function initHttpRoutes(app: Express) {
  if (typeof app?.set === "function") { app.set("trust proxy", 1); }
  const audit = makeAuditMiddleware();
  const { debugLimiter, renderLimiter } = makeRateLimiters();
  const mixdownEnabled =
    !!process.env.MIXDOWN_ENABLED &&
    process.env.MIXDOWN_ENABLED !== "0" &&
    process.env.MIXDOWN_ENABLED.toLowerCase() !== "false";

  // Room diagnosability: capture last mixdown error and event
  let lastMixdownError: any = null;
  let lastMixdownEvent: any = null;

  function runFfmpeg(args: string[]): Promise<void> {
    return new Promise((resolve, reject) => {
      const proc = spawn("ffmpeg", args);
      let stderr = "";
      proc.stderr?.on("data", (d) => (stderr += d.toString()));
      proc.on("error", (err) => reject(err));
      proc.on("close", (code) => {
        if (code === 0) return resolve();
        const err = new Error(`ffmpeg exited with code ${code}: ${stderr}`);
        // Attach structured ffmpeg diagnostics (trim stderr to 4000 chars)
        (err as any).ffmpeg = {
          code,
          stderr: stderr.slice(-4000),
          args
        };
        return reject(err);
      });
    });
  }

  // Helper for robust R2 stream-to-file with timeout and error handling
  async function pipeStreamToFile(
    stream: any,
    destPath: string,
    label: string,
    timeoutMs: number = 120000
  ): Promise<void> {
    return new Promise((resolve, reject) => {
      const writeStream = fs.createWriteStream(destPath);
      let timer: NodeJS.Timeout | null = null;
      let resolved = false;

      const cleanup = () => {
        if (timer) clearTimeout(timer);
        resolved = true;
      };

      const handleError = (err: Error, source: string) => {
        if (resolved) return;
        cleanup();
        try { stream.destroy(); } catch {}
        try { writeStream.close(); } catch {}
        reject(new Error(`${label}_${source}_error: ${err.message}`));
      };

      // Set timeout
      timer = setTimeout(() => {
        if (resolved) return;
        cleanup();
        try { stream.destroy(); } catch {}
        try { writeStream.close(); } catch {}
        reject(new Error(`${label}_timeout`));
      }, timeoutMs);

      // Handle errors
      stream.on("error", (err: Error) => handleError(err, "stream"));
      writeStream.on("error", (err: Error) => handleError(err, "write"));

      // Handle success
      writeStream.on("finish", () => {
        if (resolved) return;
        cleanup();
        resolve();
      });

      // Pipe the stream
      stream.pipe(writeStream);
    });
  }

  const debug = express.Router();
  const api = express.Router();

  debug.use(secretGuard);
  debug.use((req: Request, res: Response, next: NextFunction) => {
    ensureSid(req, res);
    next();
  });

  // GET /debug/whoami - shows current user session info
  debug.get("/whoami", (req: Request, res: Response) => {
    const { passkeyLoggedIn, userId } = getPasskeySession(req as any);
    res.json({ passkeyLoggedIn, userId });
  });

  // GET /debug/my_scripts - list scripts owned by current user
  debug.get("/my_scripts", audit("/debug/my_scripts"), async (req: Request, res: Response) => {
    const { userId } = getPasskeySession(req as any);
    if (!userId) {
      return res.status(401).json({ error: "unauthorized" });
    }

    try {
      const orderClause = USING_POSTGRES
        ? "ORDER BY updated_at DESC"
        : "ORDER BY datetime(updated_at) DESC";

      const rows = await dbAll<{ id: string; user_id: string; title: string; scene_count: number; updated_at: string }>(
        `SELECT id, user_id, title, scene_count, updated_at FROM scripts WHERE user_id = ? ${orderClause}`,
        [userId]
      );

      const scripts = rows.map((row) => ({
        id: row.id,
        title: row.title,
        scene_count: typeof row.scene_count === "number" ? row.scene_count : 0,
        updated_at: row.updated_at,
      }));

      res.json({ userId, scripts });
    } catch (err) {
      console.error("[debug/my_scripts] query failed", err);
      res.status(500).json({ error: "failed_to_list_scripts" });
    }
  });

  // GET /debug/script_probe?script_id=... - diagnostic for script ownership
  debug.get("/script_probe", audit("/debug/script_probe"), (req: Request, res: Response) => {
    const { userId } = getPasskeySession(req as any);
    if (!userId) {
      return res.status(401).json({ error: "unauthorized" });
    }

    const script_id = String(req.query.script_id || "").trim();
    if (!script_id) {
      return res.status(400).json({ error: "script_id required" });
    }

    try {
      const cacheKey = `${userId}:${script_id}`;
      const cacheHit = scripts.has(cacheKey);

      // Check if script exists for this user
      const dbRow = db
        .prepare(`SELECT user_id FROM scripts WHERE id = ? AND user_id = ?`)
        .get(script_id, userId) as { user_id: string } | undefined;
      const dbHit = Boolean(dbRow);

      // Check if script exists with different owner
      const ownerRow = db
        .prepare(`SELECT user_id FROM scripts WHERE id = ?`)
        .get(script_id) as { user_id: string } | undefined;
      const dbOwner = ownerRow?.user_id || null;

      res.json({
        userId,
        script_id,
        cacheHit,
        dbHit,
        dbOwner,
      });
    } catch (err) {
      console.error("[debug/script_probe] query failed", err);
      res.status(500).json({ error: "probe_failed" });
    }
  });

  // GET /debug/voices_probe
  debug.get("/voices_probe", audit("/debug/voices_probe"), (_req: Request, res: Response) => {
    if (ttsProvider() !== "openai") {
      return res.json({ ok: true, voices: ["alloy"] });
    }
    const curatedVoices = ["alloy", "echo", "fable", "onyx", "nova", "shimmer"];
    res.json({ ok: true, voices: curatedVoices });
  });

  // GET /debug/r2_head?key=<key>
  debug.get("/r2_head", audit("/debug/r2_head"), async (req: Request, res: Response) => {
    try {
      const key = String(req.query.key || "");
      if (!key) {
        return res.status(400).json({ ok: false, error: "missing_key" });
      }

      if (!r2Enabled()) {
        return res.json({ ok: false, error: "r2_not_enabled" });
      }

      const result = await r2Head(key);
      return res.json({
        ok: true,
        key,
        exists: result.exists,
        size: result.contentLength,
        etag: result.etag,
      });
    } catch (err) {
      console.error("[debug/r2_head] error:", err);
      return res.status(500).json({ ok: false, error: "r2_head_failed" });
    }
  });

  // GET /debug/last_mixdown - Room diagnosability
  debug.get("/last_mixdown", audit("/debug/last_mixdown"), (req: Request, res: Response) => {
    return res.json({ ok: true, lastMixdownEvent, lastMixdownError });
  });

  // POST /debug/upload_script_text
  debug.post("/upload_script_text", audit("/debug/upload_script_text"), async (req: Request, res: Response) => {
    const { userId } = getPasskeySession(req as any);
    if (!userId) {
      return res.status(401).json({ error: "unauthorized" });
    }

    const { title, text } = req.body || {};
    if (!title || !text) return res.status(400).json({ error: "title and text are required" });

    const id = crypto.randomUUID();
    const scenes = parseScenesFromText(String(text));
    const script: Script = { id, title: String(title), text: String(text), scenes };

    // Cache in memory for this process (user-keyed)
    const cacheKey = `${userId}:${id}`;
    scripts.set(cacheKey, script);

    // Persist to DB so scripts survive server restarts
    await saveScriptToDb(script, userId);

    // Derive a simple list of unique speaker names for the UI status line
    const speakers = Array.from(
      new Set(
        scenes.flatMap((sc) =>
          Array.isArray(sc.lines) ? sc.lines.map((ln) => ln.speaker).filter(Boolean) : []
        )
      )
    );

    res.json({
      script_id: id,
      scene_count: scenes.length,
      speakers,
    });
  });

  // POST /debug/upload_script_upload  (PDF or image)
  debug.post(
    "/upload_script_upload",
    audit("/debug/upload_script_upload"),
    upload.single("pdf"),
    async (req: Request, res: Response) => {
      try {
        const { userId } = getPasskeySession(req as any);
        if (!userId) {
          return res.status(401).json({ error: "unauthorized" });
        }

        const title = String(req.body?.title || "Uploaded Script");
        if (!req.file?.buffer || !req.file.mimetype) {
          return res.status(400).json({ error: "missing file" });
        }
        if (req.file.size > 20 * 1024 * 1024) {
          return res.status(413).json({ error: "file too large" });
        }

        // Try to extract readable text from the upload (PDF or image).
        const rawExtracted = await extractTextAuto(req.file.buffer, req.file.mimetype);
        const extracted = typeof rawExtracted === "string" ? rawExtracted : "";

        // Length of extracted text for debugging / status.
        const textLen = extracted.trim().length;

        // Only attempt scene parsing when we have a reasonable amount of text.
        let scenes: Scene[] = [];
        if (textLen >= 40) {
          const parsed = parseScenesFromText(extracted);
          // Drop any scenes that have no dialogue lines; they are noise.
          scenes = (parsed || []).filter(
            (sc) => Array.isArray(sc.lines) && sc.lines.length > 0
          );
        }

        const id = crypto.randomUUID();
        const script: Script = {
          id,
          title,
          text: extracted,
          scenes,
        };

        // Cache in memory (user-keyed) and persist to DB
        const cacheKey = `${userId}:${id}`;
        scripts.set(cacheKey, script);
        await saveScriptToDb(script, userId);

        // Derive speakers + simple parse meta for the UI
        const speakers = Array.from(
          new Set(
            scenes.flatMap((sc) =>
              Array.isArray(sc.lines) ? sc.lines.map((ln) => ln.speaker).filter(Boolean) : []
            )
          )
        );

        let note: string | undefined;
        if (!scenes.length && textLen > 0) {
          // We got text but could not recognize any dialogue patterns.
          note = "parse-error";
        } else if (textLen > 0 && textLen < 40) {
          // Very short text usually means the PDF is image-only and needs OCR.
          note = "image-only";
        }

        res.json({
          script_id: id,
          scene_count: scenes.length,
          speakers,
          textLen,
          ...(note ? { note } : {}),
        });
      } catch (e) {
        console.error("[upload] failed:", e);
        res.status(500).json({ error: "could not extract text" });
      }
    }
  );

  // GET /debug/scenes
  debug.get("/scenes", audit("/debug/scenes"), async (req: Request, res: Response) => {
    const { userId } = getPasskeySession(req as any);
    if (!userId) {
      return res.status(401).json({ error: "unauthorized" });
    }

    const scriptId = String(req.query.script_id || "");
    if (!scriptId) {
      return res.status(400).json({ error: "script_id required" });
    }

    const script = await getOrLoadScript(scriptId, userId);
    if (!script) {
      return res.status(404).json({ error: "script not found" });
    }

    res.json({ script_id: script.id, scenes: script.scenes });
  });

  // POST /debug/set_voice
  debug.post("/set_voice", audit("/debug/set_voice"), async (req: Request, res: Response) => {
    const { userId } = getPasskeySession(req as any);
    if (!userId) {
      return res.status(401).json({ error: "unauthorized" });
    }

    const { script_id, voice_map } = req.body || {};
    if (!script_id) {
      return res.status(400).json({ error: "script_id required" });
    }
    if (!voice_map || typeof voice_map !== "object") {
      return res.status(400).json({ error: "voice_map required" });
    }

    const script = await getOrLoadScript(script_id, userId);
    if (!script) {
      return res.status(404).json({ error: "script not found" });
    }

    script.voiceMap = { ...(script.voiceMap || {}), ...(voice_map || {}) };
    const cacheKey = `${userId}:${script_id}`;
    scripts.set(cacheKey, script);

    await saveScriptToDb(script, userId);

    res.json({ ok: true });
  });

  // POST /debug/preview_voice
  debug.post("/preview_voice", audit("/debug/preview_voice"), async (req: Request, res: Response) => {
    try {
      const { voice } = req.body || {};
      const v = (typeof voice === "string" && voice.trim()) ? String(voice).trim() : "alloy";

      // If we are in stub mode (no OpenAI key), just return an empty mp3 to keep the flow intact.
      if (ttsProvider() !== "openai") {
        res.setHeader("Content-Type", "audio/mpeg");
        return res.end(Buffer.alloc(0));
      }

      const sampleText = `This is ${v} speaking in OffBook.`;
      const lines = [{ character: "DEMO", text: sampleText }];
      const voiceMap: Record<string, string> = { DEMO: v, UNKNOWN: v };

      const outPath = await generateReaderMp3(lines, voiceMap, "USER", "normal");

      res.setHeader("Content-Type", "audio/mpeg");
      fs.createReadStream(outPath).pipe(res);
    } catch (err) {
      console.error("[preview_voice] error:", err);
      if (!res.headersSent) {
        res.status(500).json({ error: "preview_failed" });
      }
    }
  });

  // POST /debug/tts_line
  debug.post("/tts_line", audit("/debug/tts_line"), async (req: Request, res: Response) => {
    if (ttsProvider() !== "openai") {
      return res.status(200).json({ ok: false, error: "tts_disabled" });
    }

    const body = req.body || {};
    const voice =
      typeof body.voice === "string" && body.voice.trim()
        ? String(body.voice).trim()
        : "alloy";
    const text =
      typeof body.text === "string" && body.text.trim()
        ? String(body.text)
        : "(empty line)";
    const model =
      typeof body.model === "string" && body.model.trim()
        ? String(body.model).trim()
        : "tts-1";

    const lines = [{ character: "DEMO", text }];
    const voiceMap: Record<string, string> = { DEMO: voice, UNKNOWN: voice };

    try {
      const args: any[] = [lines, voiceMap, "USER", "normal"];
      if (typeof generateReaderMp3 === "function" && generateReaderMp3.length >= 5) {
        args.push(model);
      }
      const outPath = await (generateReaderMp3 as any)(...args);
      const id = crypto.randomUUID();
      const dest = path.join(ASSETS_DIR, `${id}.mp3`);
      fs.copyFileSync(outPath, dest);

      // Upload to R2 if enabled
      if (r2Enabled()) {
        try {
          const r2Key = `renders/${id}.mp3`;
          await r2PutFile(r2Key, dest, "audio/mpeg");
          console.log("[debug/tts_line] Uploaded to R2: key=%s", r2Key);
        } catch (err) {
          console.warn("[debug/tts_line] R2 upload failed:", err);
        }
      }

      const base = baseUrlFrom(req);
      return res.json({ ok: true, url: `${base}/api/assets/${id}` });
    } catch (err: any) {
      const status = typeof err?.status === "number" ? err.status : err?.response?.status;
      const code =
        err?.code ||
        err?.error?.code ||
        err?.response?.data?.error?.code ||
        err?.error?.type;
      const message =
        err?.message ||
        err?.error?.message ||
        err?.response?.data?.error?.message;
      const isRateLimited =
        status === 429 ||
        (typeof code === "string" && code.toLowerCase().includes("rate")) ||
        (typeof message === "string" && message.toLowerCase().includes("rate limit"));
      console.error("[tts_line] error:", { status, code, message, raw: err });
      if (isRateLimited) {
        return res.status(429).json({ ok: false, error: "rate_limited" });
      }
      return res.status(500).json({ ok: false, error: "tts_failed" });
    }
  });

  // --- STT (speech-to-text) debug route ---
  debug.post("/stt_transcribe_chunk", audit("/debug/stt_transcribe_chunk"), async (req: Request, res: Response) => {
    try {
      // If STT is not configured, respond gracefully.
      if (!isSttEnabled()) {
        return res.status(200).json({
          ok: false,
          error: "stt_disabled",
        });
      }

      const body = (req as any).body || {};
      const audio_b64 = typeof body.audio_b64 === "string" ? body.audio_b64 : "";
      const mime =
        typeof body.mime === "string" && body.mime.trim()
          ? (body.mime as string)
          : "audio/webm";

      if (!audio_b64.trim()) {
        return res.status(400).json({
          ok: false,
          error: "missing_audio",
        });
      }

      // Decode the base64 payload into a raw Buffer for STT2
      const audioBuffer = Buffer.from(audio_b64, "base64");
      if (!audioBuffer || audioBuffer.length === 0) {
        return res.status(400).json({
          ok: false,
          error: "invalid_audio",
        });
      }

      console.log("[stt] /stt_transcribe_chunk request:", {
        mime,
        base64Length: audio_b64.length,
        bytes: audioBuffer.length,
      });

      try {
        const result = await transcribeChunk({
          audio: audioBuffer,
          mime,
        });

        return res.status(200).json({
          ok: true,
          text: result.text,
          partial: false,
        });
      } catch (err: any) {
        // Try to pull out useful details from OpenAI-style errors
        let code = "stt_failed";
        let message: string | undefined;

        const anyErr: any = err || {};
        const oaiErr = anyErr.error || anyErr.response?.data?.error;

        if (typeof oaiErr?.code === "string") {
          code = oaiErr.code;
        } else if (typeof anyErr.code === "string") {
          code = anyErr.code;
        } else if (typeof anyErr.message === "string") {
          code = anyErr.message;
        }

        if (typeof oaiErr?.message === "string") {
          message = oaiErr.message;
        } else if (typeof anyErr.message === "string") {
          message = anyErr.message;
        }

        console.error("[stt] transcribe_chunk error:", {
          code,
          message,
          mime,
          bytes: audioBuffer.length,
          raw: anyErr,
        });

        return res.status(500).json({
          ok: false,
          error: code,
          message,
          meta: {
            mime,
            bytes: audioBuffer.length,
          },
        });
      }
    } catch (err) {
      console.error("[stt] unexpected error:", err);
      return res.status(500).json({
        ok: false,
        error: "stt_failed",
      });
    }
  });

  // POST /debug/render (real TTS)
  debug.post("/render", renderLimiter, audit("/debug/render"), async (req: Request, res: Response) => {
    const { userId } = getPasskeySession(req as any);
    if (!userId) {
      return res.status(401).json({ error: "unauthorized" });
    }

    const body = req.body || {};
    const script_id = body.script_id;
    const scene_id = body.scene_id || body.script_id; // default single-scene behavior
    const roleRaw = body.role ?? body.my_role; // accept legacy client payload
    const role = String(roleRaw || "").toUpperCase();
    const pace = body.pace || "normal";
    if (!script_id || !scene_id || !role) {
      return res.status(400).json({ error: "script_id, scene_id, role required" });
    }

    const script = await getOrLoadScript(script_id, userId);
    if (!script) {
      return res.status(404).json({ error: "script not found" });
    }

    const renderId = crypto.randomUUID();
    renders.set(renderId, { status: "working", accounted: false });

    // Find the scene
    const scene = script.scenes.find(s => s.id === scene_id) || script.scenes[0];
    if (!scene) {
      renders.set(renderId, { status: "error", accounted: false });
      return res.status(404).json({ error: "scene not found" });
    }

    // Build lines for TTS
    const lines = scene.lines.map(l => ({ character: l.speaker, text: l.text }));

    // Build voiceMap and ensure UNKNOWN fallback
    const voiceMap = script.voiceMap || {};
    if (!voiceMap.UNKNOWN) {
      voiceMap.UNKNOWN = "alloy";
    }

    // Generate reader MP3
    let file: string;
    try {
      file = await generateReaderMp3(lines, voiceMap, role, pace, renderId);
    } catch (ttsErr) {
      console.error("[debug/render] TTS generation failed:", ttsErr);
      renders.set(renderId, { status: "error", accounted: false });
      return res.status(500).json({ error: "tts_failed" });
    }

    // Upload to R2 if enabled
    const r2Key = `renders/${renderId}.mp3`;
    if (r2Enabled()) {
      try {
        await r2PutFile(r2Key, file, "audio/mpeg");
        console.log("[debug/render] Uploaded to R2: key=%s", r2Key);
      } catch (err) {
        console.error("[debug/render] R2 upload failed:", err);
        renders.set(renderId, { status: "error", err: "r2_upload_failed", accounted: false });
        return res.status(500).json({ error: "r2_upload_failed" });
      }
    }

    const job = { status: "complete" as const, file, accounted: false };
    try {
      console.log(
        "[credits] render complete (http-routes:/debug/render): accounting usage; rid=%s",
        renderId
      );
      await noteRenderComplete(req);
      job.accounted = true;
    } catch (err) {
      console.error("[credits] noteRenderComplete failed (http-routes:/debug/render):", err);
    }
    renders.set(renderId, job);
    res.json({ render_id: renderId, status: "complete", r2Key });
  });

  // GET /debug/render_status
  debug.get("/render_status", audit("/debug/render_status"), async (req: Request, res: Response) => {
    const rid = String(req.query.render_id || "");
    if (!rid || !renders.has(rid)) {
      return res.status(404).json({ status: "error", error: "render not found" });
    }
    const job = renders.get(rid)!;

    // When a render first reaches "complete", account for it exactly once.
    if (job.status === "complete" && !job.accounted) {
      try {
        console.log("[credits] render complete (http-routes): accounting usage; rid=%s", rid);
        await noteRenderComplete(req);
        job.accounted = true;
        renders.set(rid, job);
      } catch (err) {
        console.error("[credits] noteRenderComplete failed (http-routes):", err);
      }
    }

    const payload: any = { status: job.status };
    if (job.status === "complete" && job.file) {
      const base = baseUrlFrom(req);
      const id = path.basename(job.file, ".mp3");
      payload.download_url = `${base}/api/assets/${id}`;
    }
    res.json(payload);
  });

  // Mount routers
  app.use("/debug", debugLimiter, debug);

  // --- Gallery API (per-user, authenticated; metadata only) ------------------
  api.get("/gallery", async (req: Request, res: Response) => {
    const userId = getUserIdOr401(req, res);
    if (!userId) return;

    try {
      const rows = await listByUserAsync(userId);
      console.log(
        "[gallery] list for user=%s, count=%d",
        userId,
        Array.isArray(rows) ? rows.length : 0
      );
      res.json({
        ok: true,
        items: (rows || []).map((r: any) => ({
          ...r,
          notes:
            typeof r?.notes === "string"
              ? r.notes
              : typeof r?.note === "string"
              ? r.note
              : "",
        })),
      });
    } catch (err) {
      console.error("Error in GET /api/gallery", err);
      res.status(500).json({ error: "internal_error" });
    }
  });

  api.get("/gallery/:id", async (req: Request, res: Response) => {
    const userId = getUserIdOr401(req, res);
    if (!userId) return;

    try {
      const id = String(req.params.id || "");
      const row = await getByIdAsync(id, userId);

      if (!row) {
        return res.status(404).json({ error: "not_found" });
      }

      const { file_path, ...meta } = row as any;
      meta.notes =
        typeof meta.notes === "string"
          ? meta.notes
          : typeof meta.note === "string"
          ? meta.note
          : "";
      res.json({
        ok: true,
        item: meta,
      });
    } catch (err) {
      console.error("Error in GET /api/gallery/:id", err);
      res.status(500).json({ error: "internal_error" });
    }
  });

  api.post(
    "/gallery/upload",
    requireUser,
    galleryUpload.single("file"),
    async (req: Request, res: Response) => {
      try {
        const user = (req as any).user || res.locals.user;
        if (!user || !user.id) {
          return res.status(401).json({ error: "Unauthorized" });
        }

        const file = req.file;
        if (!file) {
          return res.status(400).json({ error: "file_required" });
        }

        const {
          id,
          name,
          script_id,
          scene_id,
          mime_type,
          size,
          created_at,
          note,
          notes,
          render_id,
        } = (req.body || {}) as any;

        const takeId = id || file.filename;
        const createdAtNumRaw = created_at ? Number(created_at) : Date.now();
        const createdAtNum = Number.isFinite(createdAtNumRaw)
          ? createdAtNumRaw
          : Date.now();
        const sizeNumRaw = size ? Number(size) : file.size;
        const sizeNum = Number.isFinite(sizeNumRaw) ? sizeNumRaw : file.size;
        const mime = mime_type || file.mimetype || "video/webm";

        const baseDir = path.join(
          process.cwd(),
          "uploads",
          "gallery",
          String(user.id)
        );
        fs.mkdirSync(baseDir, { recursive: true });

        const ext = path.extname(file.originalname || "") || ".webm";
        const finalName = `${takeId}${ext}`;
        const finalPath = path.join(baseDir, finalName);

        fs.renameSync(file.path, finalPath);

        const notesVal =
          typeof notes === "string"
            ? notes
            : typeof note === "string"
            ? note
            : "";
        const noteVal =
          typeof note === "string"
            ? note
            : typeof notes === "string"
            ? notes
            : null;
        const readerRenderId =
          typeof render_id === "string" && render_id.trim()
            ? render_id.trim()
            : null;

        // R2 upload if enabled
        let filePath = finalPath;
        let storageInfo: any = undefined;

        if (r2Enabled()) {
          const r2Key = `gallery/${user.id}/${takeId}${ext}`;
          try {
            await r2PutFile(r2Key, finalPath, mime);
            filePath = `r2://${r2Key}`;
            storageInfo = { type: "r2", key: r2Key };
            console.log(
              "[gallery] upload saved to R2: user=%s id=%s key=%s size=%d mime=%s",
              String(user.id),
              String(takeId),
              r2Key,
              sizeNum,
              mime
            );
          } catch (err) {
            console.error("[gallery] R2 upload failed, falling back to local:", err);
            // Keep local file_path on R2 failure
          }
        } else {
          console.log(
            "[gallery] upload saved locally: user=%s id=%s size=%d mime=%s path=%s",
            String(user.id),
            String(takeId),
            sizeNum,
            mime,
            finalPath
          );
        }

        await saveAsync({
          id: String(takeId),
          user_id: String(user.id),
          script_id: script_id || null,
          scene_id: scene_id || null,
          name: name || "Take",
          mime_type: mime,
          size: sizeNum,
          created_at: createdAtNum,
          note: noteVal,
          notes: notesVal,
          reader_render_id: readerRenderId,
          file_path: filePath,
        });

        const response: any = {
          ok: true,
          id: String(takeId),
          created_at: createdAtNum,
        };

        if (storageInfo) {
          response.storage = storageInfo;
        }

        res.json(response);
      } catch (err) {
        console.error("Error in POST /api/gallery/upload", err);
        res.status(500).json({ error: "internal_error" });
      }
    }
  );

  // POST /api/gallery/delete { take_id }
  api.post(
    "/gallery/delete",
    requireUser,
    express.json(),
    async (req: Request, res: Response) => {
      try {
        const user = (req as any).user || res.locals.user;
        if (!user || !user.id) {
          return res.status(401).json({ error: "Unauthorized" });
        }

        const takeId = String((req.body as any)?.take_id || (req.body as any)?.id || "");
        if (!takeId) {
          return res.status(400).json({ error: "take_id_required" });
        }

        const row = await getByIdAsync(takeId, String(user.id));
        if (!row) {
          return res.status(404).json({ error: "not_found" });
        }

        const filePath = (row as any).file_path as string;

        // Delete from R2 if stored there
        if (filePath && filePath.startsWith("r2://")) {
          const r2Key = filePath.substring(5); // Remove "r2://" prefix
          try {
            await r2Delete(r2Key);
            console.log("[gallery] Deleted from R2: key=%s", r2Key);
          } catch (e) {
            console.warn("[gallery] R2 delete failed for", r2Key, e);
          }
        } else {
          // Delete local file
          try {
            if (filePath && fs.existsSync(filePath)) {
              fs.unlinkSync(filePath);
            }
          } catch (e) {
            console.warn("[gallery] unlink failed for", takeId, e);
          }
        }

        await deleteByIdAsync(takeId, String(user.id));
        return res.json({ ok: true });
      } catch (err) {
        console.error("Error in POST /api/gallery/delete", err);
        return res.status(500).json({ error: "internal_error" });
      }
    }
  );

  api.post(
    "/gallery/notes",
    requireUser,
    express.json(),
    async (req: Request, res: Response) => {
      try {
        const user = (req as any).user || res.locals.user;
        if (!user || !user.id) {
          return res.status(401).json({ error: "Unauthorized" });
        }

        const takeId = String((req.body as any)?.take_id || "");
        const notes =
          typeof (req.body as any)?.notes === "string" ? (req.body as any).notes : "";
        if (!takeId) {
          return res.status(400).json({ error: "take_id_required" });
        }

        const row = await getByIdAsync(takeId, String(user.id));
        if (!row) {
          return res.status(404).json({ error: "not_found" });
        }

        await updateNotesAsync(takeId, String(user.id), notes);
        return res.json({ ok: true });
      } catch (err) {
        console.error("Error in POST /api/gallery/notes", err);
        return res.status(500).json({ error: "internal_error" });
      }
    }
  );

  api.get("/gallery/:id/mixed_file", requireUser, async (req: Request, res: Response) => {
    let tempTakeFile: string | null = null;
    let tempReaderFile: string | null = null;
    let tempOutputFile: string | null = null;

    const id = String(req.params.id || "");
    const user = (req as any).user || res.locals.user;

    // Track mixdown event from the start
    lastMixdownEvent = {
      at: new Date().toISOString(),
      stage: "requested",
      takeId: id,
      url: req.originalUrl
    };

    try {
      if (!mixdownEnabled) {
        return res.status(404).json({ error: "mixdown_disabled" });
      }

      if (!user || !user.id) {
        return res.status(401).json({ error: "Unauthorized" });
      }

      if (!id) {
        return res.status(400).json({ error: "id_required" });
      }

      console.log("[mixdown] Processing request for takeId=%s, userId=%s", id, user.id);

      const row = await getByIdAsync(id, String(user.id));
      if (!row) {
        return res.status(404).json({ error: "not_found" });
      }

      const filePath = (row as any).file_path as string;
      const readerId = (row as any).reader_render_id as string | undefined;
      const takeName = (row as any).name || "take";

      if (!filePath) {
        console.log("[mixdown] Missing file_path for takeId=%s", id);
        return res.status(404).json({ error: "file_missing" });
      }

      // Bump this when changing ffmpeg logic to bust cache
      const MIX_VER = "v6";
      const mode = String(req.query.mode || "room");

      // Query parameters
      const wantsDownload = String(req.query?.dl || "") === "1";
      const force = String(req.query?.force || "") === "1";
      const solo = String(req.query?.solo || "");
      const soloReader = solo === "reader";
      const legacyRequested = String(req.query?.legacy || "") === "1";

      // STEMS-FIRST APPROACH: Try to find stems (mic + reader) BEFORE checking reader_render_id
      const stemsDir = path.join(process.cwd(), "uploads", "gallery", String(user.id), "stems");
      fs.mkdirSync(stemsDir, { recursive: true });

      let micStem: string | null = null;
      let readerStem: string | null = null;

      // Look for local stems first
      try {
        const stemFiles = fs.readdirSync(stemsDir);
        micStem = stemFiles.find(f => f.startsWith(`${id}-mic.`)) || null;
        readerStem = stemFiles.find(f => f.startsWith(`${id}-reader.`)) || null;
        if (micStem) micStem = path.join(stemsDir, micStem);
        if (readerStem) readerStem = path.join(stemsDir, readerStem);
      } catch {}

      // If not found locally, try R2
      if ((!micStem || !readerStem) && r2Enabled()) {
        const stemExts = [".m4a", ".webm", ".mp3", ".wav", ".ogg", ".mp4"];
        for (const ext of stemExts) {
          const micKey = `stems/${user.id}/${id}-mic${ext}`;
          const readerKey = `stems/${user.id}/${id}-reader${ext}`;

          try {
            const micHead = await r2Head(micKey);
            const readerHead = await r2Head(readerKey);

            if (micHead.exists && readerHead.exists) {
              // Download both stems to temp
              const tmpDir = path.join(require("os").tmpdir(), "offbook-mix");
              fs.mkdirSync(tmpDir, { recursive: true });

              const micTemp = path.join(tmpDir, `${id}-mic-${Date.now()}${ext}`);
              const readerTemp = path.join(tmpDir, `${id}-reader-${Date.now()}${ext}`);

              const micResult = await r2GetObjectStream(micKey);
              const micWrite = fs.createWriteStream(micTemp);
              await new Promise<void>((resolve, reject) => {
                micResult.stream.pipe(micWrite);
                micWrite.on("finish", () => resolve());
                micWrite.on("error", reject);
              });

              const readerResult = await r2GetObjectStream(readerKey);
              const readerWrite = fs.createWriteStream(readerTemp);
              await new Promise<void>((resolve, reject) => {
                readerResult.stream.pipe(readerWrite);
                readerWrite.on("finish", () => resolve());
                readerWrite.on("error", reject);
              });

              micStem = micTemp;
              readerStem = readerTemp;
              tempReaderFile = readerTemp;
              console.log("[mixed_file] Downloaded stems from R2: mic=%s, reader=%s", micKey, readerKey);
              break;
            }
          } catch {}
        }
      }

      // Check if stems exist
      const useStems = !!(micStem && readerStem && fs.existsSync(micStem) && fs.existsSync(readerStem));

      // Update debug event with stem detection results
      lastMixdownEvent = {
        ...lastMixdownEvent,
        stage: "stems_detected",
        usedStems: useStems,
        legacyRequested,
        micStemPath: micStem || undefined,
        readerStemPath: readerStem || undefined
      };

      // If stems missing and legacy not requested, return error
      if (!useStems && !legacyRequested) {
        console.log("[mixed_file] Stems missing and legacy mode not requested for take %s", id);
        lastMixdownEvent = {
          ...lastMixdownEvent,
          stage: "error",
          errorCode: "stems_missing"
        };
        return res.status(404).json({ error: "stems_missing" });
      }

      // Only enforce reader_render_id when legacy mode is explicitly requested
      if (!useStems && legacyRequested) {
        if (!readerId) {
          console.log("[mixdown] Legacy mode requested but missing reader_render_id for takeId=%s", id);
          lastMixdownEvent = {
            ...lastMixdownEvent,
            stage: "error",
            errorCode: "reader_missing"
          };
          return res.status(404).json({ error: "reader_missing" });
        }
      }

      // Determine output path with versioning
      const outPath = path.join(path.dirname(filePath), `${id}-${mode}-${MIX_VER}.mixed.mp4`);
      const outExists = fs.existsSync(outPath);

      if (useStems) {
        console.log("[mixed_file] Using stems for take %s: mic=%s, reader=%s", id, micStem, readerStem);

        // Check if rebuild needed
        const micStat = fs.statSync(micStem!);
        const readerStat = fs.statSync(readerStem!);
        const takeStat = fs.statSync(filePath);
        const needsRebuild =
          !outExists ||
          fs.statSync(outPath).mtimeMs <
            Math.max(takeStat.mtimeMs, micStat.mtimeMs, readerStat.mtimeMs);

        if (needsRebuild) {
          // 3-input FFmpeg: take video + mic stem + reader stem
          const filter =
            mode === "dry"
              ? "[2:a]highpass=f=180,lowpass=f=6000,volume=0.85[rd];" +
                "[1:a][rd]amix=inputs=2:weights=1 1.35:normalize=0:duration=first:dropout_transition=3,alimiter=limit=0.95[aout]"
              : "[2:a]aecho=0.35:0.25:14|22:0.10|0.06,highpass=f=180,lowpass=f=6000,volume=0.85[room];" +
                "[1:a][room]amix=inputs=2:weights=1 1.35:normalize=0:duration=first:dropout_transition=3,alimiter=limit=0.95[aout]";

          const baseArgs = [
            "-y",
            "-i",
            filePath,      // input 0: take video
            "-i",
            micStem,       // input 1: mic stem
            "-i",
            readerStem,    // input 2: reader stem
            "-filter_complex",
            filter,
            "-map",
            "0:v",         // map video from take
            "-map",
            "[aout]",      // map mixed audio
            "-c:a",
            "aac",
            "-movflags",
            "+faststart",
          ];

          try {
            lastMixdownEvent = { ...lastMixdownEvent, stage: "ffmpeg_stems_copy" };
            await runFfmpeg([...baseArgs, "-c:v", "copy", outPath]);
            console.log("[mixed_file] Stems-based mix complete (copy mode): %s", outPath);
            lastMixdownEvent = { ...lastMixdownEvent, stage: "ffmpeg_stems_ok" };
          } catch (err) {
            console.warn("[mixed_file] Stems copy failed, retrying with transcode", err);
            lastMixdownEvent = { ...lastMixdownEvent, stage: "ffmpeg_stems_transcode" };
            await runFfmpeg([
              ...baseArgs,
              "-c:v",
              "libx264",
              "-preset",
              "veryfast",
              "-crf",
              "22",
              outPath,
            ]);
            console.log("[mixed_file] Stems-based mix complete (transcode mode): %s", outPath);
            lastMixdownEvent = { ...lastMixdownEvent, stage: "ffmpeg_stems_ok" };
          }
        }
      } else {
        // Fallback: use old 2-input path (take + reader MP3) - LEGACY MODE
        console.log("[mixed_file] Using legacy 2-input mix for take %s (legacy=%s)", id, legacyRequested);
        lastMixdownEvent = { ...lastMixdownEvent, stage: "legacy_mode" };

        // Check local reader file first
        const localReader = path.join(ASSETS_DIR, `${readerId!}.mp3`);
        const localReaderExists = fs.existsSync(localReader);

        // STRICT R2 CHECK: Only validate R2 if local file doesn't exist
        // (If render just happened locally, MP3 may exist even if R2 upload pending/failed)
        if (!localReaderExists && r2Enabled()) {
          // Verify reader exists in R2 before attempting mixdown
          try {
            const r2ReaderKey = `renders/${readerId!}.mp3`;
            const r2ReaderHead = await r2Head(r2ReaderKey);
            if (!r2ReaderHead.exists) {
              console.error("[mixed_file] Reader audio missing in R2 and not found locally: readerId=%s", readerId);
              lastMixdownEvent = {
                ...lastMixdownEvent,
                stage: "error",
                errorCode: "reader_audio_missing"
              };
              return res.status(404).json({ error: "reader_audio_missing" });
            }
          } catch (err) {
            console.error("[mixed_file] R2 head check failed for reader: readerId=%s, err=%s", readerId, err);
            lastMixdownEvent = {
              ...lastMixdownEvent,
              stage: "error",
              errorCode: "reader_audio_missing"
            };
            return res.status(404).json({ error: "reader_audio_missing" });
          }
        }

        const readerFile = localReader;
        if (!localReaderExists) {
          lastMixdownEvent = {
            ...lastMixdownEvent,
            stage: "error",
            errorCode: "reader_audio_missing"
          };
          return res.status(404).json({ error: "reader_audio_missing" });
        }

        const takeStat = fs.statSync(filePath);
        const readerStat = fs.statSync(readerFile);
        const needsRebuild =
          !outExists ||
          fs.statSync(outPath).mtimeMs <
            Math.max(takeStat.mtimeMs, readerStat.mtimeMs);

        if (needsRebuild) {
          const filter =
            "[1:a]aecho=0.35:0.25:14|22:0.10|0.06,highpass=f=180,lowpass=f=6000,volume=0.85[room];" +
            "[0:a][room]amix=inputs=2:duration=first:dropout_transition=4[aout]";
          const baseArgs = [
            "-y",
            "-i",
            filePath,
            "-i",
            readerFile,
            "-filter_complex",
            filter,
            "-map",
            "0:v",
            "-map",
            "[aout]",
            "-c:a",
            "aac",
            "-movflags",
            "+faststart",
          ];

          try {
            lastMixdownEvent = { ...lastMixdownEvent, stage: "ffmpeg_legacy_copy" };
            await runFfmpeg([...baseArgs, "-c:v", "copy", outPath]);
            lastMixdownEvent = { ...lastMixdownEvent, stage: "ffmpeg_legacy_ok" };
          } catch (err) {
            console.warn("[gallery] mixed copy failed, retrying with transcode", err);
            lastMixdownEvent = { ...lastMixdownEvent, stage: "ffmpeg_legacy_transcode" };
            await runFfmpeg([
              ...baseArgs,
              "-c:v",
              "libx264",
              "-preset",
              "veryfast",
              "-crf",
              "22",
              outPath,
            ]);
            lastMixdownEvent = { ...lastMixdownEvent, stage: "ffmpeg_legacy_ok" };
          }
        }
      }

      // Send the mixed file
      lastMixdownEvent = { ...lastMixdownEvent, stage: "sending_file" };
      res.type("video/mp4");
      res.setHeader("X-Offbook-Mix-Mode", mode);
      res.setHeader("X-Offbook-Mix-Ver", MIX_VER);
      res.setHeader("X-Offbook-Used-Stems", String(useStems));
      if (wantsDownload) {
        const safeName = takeName.replace(/[^\w.-]+/g, "_").slice(0, 80) || "take";
        res.setHeader("Content-Disposition", `attachment; filename="${safeName}-${mode}.mp4"`);
      }
      return res.sendFile(outPath);
    } catch (err) {
      console.error("[mixdown] Error processing mixed file request, takeId=%s, userId=%s: %s", id, user?.id, err);
      lastMixdownEvent = {
        ...lastMixdownEvent,
        stage: "error",
        errorCode: "internal_error",
        errorMessage: String(err)
      };
      return res.status(500).json({
        error: "internal_error",
        hint: "Check /debug/last_mixdown"
      });
    }
  });

  api.get("/gallery/:id/file", requireUser, async (req: Request, res: Response) => {
    try {
      const user = (req as any).user || res.locals.user;
      if (!user || !user.id) {
        return res.status(401).json({ error: "Unauthorized" });
      }

      const id = req.params.id;
      const row = await getByIdAsync(String(id), String(user.id));
      if (!row) {
        return res.status(404).json({ error: "not_found" });
      }

      const filePath = (row as any).file_path as string;
      if (!filePath) {
        return res.status(404).json({ error: "file_missing" });
      }

      const wantsDownload =
        (typeof req.query?.download === "string" && req.query.download === "1") ||
        (typeof req.query?.dl === "string" && req.query.dl === "1");

      const rawName =
        (row as any)?.name ||
        (row as any)?.label ||
        "download";
      const safeName =
        (rawName &&
          String(rawName)
            .replace(/[\\\/]/g, "_")
            .replace(/[^\w.-]+/g, "_")
            .slice(0, 80)) ||
        "download";

      // Check if file is stored in R2
      if (filePath.startsWith("r2://")) {
        const r2Key = filePath.substring(5); // Remove "r2://" prefix
        const mime = (row as any).mime_type as string | undefined;
        const rangeHeader = req.headers.range;

        try {
          const { stream, contentType, contentLength, contentRange, statusCode } =
            await r2GetObjectStream(r2Key, rangeHeader);

          // Set headers
          res.setHeader("Accept-Ranges", "bytes");

          if (mime && typeof mime === "string") {
            res.setHeader("Content-Type", mime);
          } else if (contentType) {
            res.setHeader("Content-Type", contentType);
          }

          if (contentLength !== undefined) {
            res.setHeader("Content-Length", contentLength);
          }

          if (contentRange) {
            res.setHeader("Content-Range", contentRange);
          }

          if (wantsDownload) {
            res.setHeader("Content-Disposition", `attachment; filename="${safeName}"`);
          }

          res.status(statusCode);
          stream.pipe(res);
        } catch (err) {
          console.error("[gallery] R2 stream failed for key:", r2Key, err);
          return res.status(500).json({ error: "r2_stream_failed" });
        }
      } else {
        // Local file
        if (!fs.existsSync(filePath)) {
          return res.status(404).json({ error: "file_missing" });
        }

        const pathSafeName = path.basename(filePath);

        // Force the correct MIME type for Safari, even if the extension is odd.
        const mime = (row as any).mime_type as string | undefined;
        if (mime && typeof mime === "string") {
          res.type(mime);
        }

        if (wantsDownload) {
          return res.download(filePath, safeName);
        }

        res.sendFile(filePath);
      }
    } catch (err) {
      console.error("Error in GET /api/gallery/:id/file", err);
      res.status(500).json({ error: "internal_error" });
    }
  });

  // --- Profile API ---
  api.get("/profile", secretGuard, async (req: Request, res: Response) => {
    try {
      const { passkeyLoggedIn, userId } = getPasskeySession(req as any);

      if (!passkeyLoggedIn || !userId) {
        return res.json({ user_id: null, display_name: null });
      }

      // Get display_name from users table
      const user = await dbGet<{ display_name?: string }>(
        `SELECT display_name FROM users WHERE id = ?`,
        [userId]
      );

      return res.json({
        user_id: userId,
        display_name: user?.display_name || null,
      });
    } catch (err) {
      console.error("Error in GET /api/profile", err);
      return res.status(500).json({ error: "internal_error" });
    }
  });

  api.post("/profile", secretGuard, express.json(), async (req: Request, res: Response) => {
    try {
      const { passkeyLoggedIn, userId } = getPasskeySession(req as any);

      if (!passkeyLoggedIn || !userId) {
        return res.status(401).json({ error: "not_logged_in" });
      }

      const displayName = String((req.body as any)?.display_name || "").trim();

      // Upsert into users table
      if (USING_POSTGRES) {
        await dbRun(
          `INSERT INTO users (id, display_name) VALUES (?, ?)
           ON CONFLICT(id) DO UPDATE SET display_name = EXCLUDED.display_name`,
          [userId, displayName || null]
        );
      } else {
        await dbRun(
          `INSERT INTO users (id, display_name) VALUES (?, ?)
           ON CONFLICT(id) DO UPDATE SET display_name = excluded.display_name`,
          [userId, displayName || null]
        );
      }

      return res.json({ ok: true });
    } catch (err) {
      console.error("Error in POST /api/profile", err);
      return res.status(500).json({ error: "internal_error" });
    }
  });

  api.get("/assets/:render_id", async (req: Request, res: Response) => {
    try {
      const renderId = String(req.params.render_id);
      const file = path.join(ASSETS_DIR, `${renderId}.mp3`);

      // If local file exists, stream it
      if (fs.existsSync(file)) {
        res.setHeader("Content-Type", "audio/mpeg");
        res.setHeader("Accept-Ranges", "bytes");
        return fs.createReadStream(file).pipe(res);
      }

      // Otherwise, try R2 if enabled
      if (r2Enabled()) {
        const r2Key = `renders/${renderId}.mp3`;
        const rangeHeader = req.headers.range;

        const { stream, contentType, contentLength, contentRange, statusCode } =
          await r2GetObjectStream(r2Key, rangeHeader);

        res.setHeader("Accept-Ranges", "bytes");
        res.setHeader("Content-Type", contentType || "audio/mpeg");

        if (contentLength !== undefined) {
          res.setHeader("Content-Length", contentLength);
        }

        if (contentRange) {
          res.setHeader("Content-Range", contentRange);
        }

        res.status(statusCode);
        return stream.pipe(res);
      }

      // Not found
      return res.status(404).send("Not Found");
    } catch (err) {
      console.error("Error in GET /api/assets/:render_id", err);
      return res.status(500).send("Internal Server Error");
    }
  });

  // Mount routers on the main app
  app.use("/debug", debug);
  app.use("/api", api);
}

export function registerHttpRoutes(app: express.Express): void {
  // Mount the API and debug routers on the main app.
  initHttpRoutes(app as Express);
}
