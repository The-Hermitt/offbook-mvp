// src/http-routes.ts
import type { Express, Request, Response, NextFunction } from "express";
import express from "express";
import multer from "multer";
import * as path from "path";
import * as fs from "fs";
import * as os from "os";
import crypto from "crypto";
import { spawn } from "child_process";
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

// ---------- Silent MP3 stub ----------
function writeSilentMp3(renderId: string): string {
  const safe = renderId.replace(/[^a-zA-Z0-9_-]/g, "_");
  const file = path.join(ASSETS_DIR, `${safe}.mp3`);
  if (!fs.existsSync(file)) fs.writeFileSync(file, Buffer.from([]));
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

  function runFfmpeg(args: string[]): Promise<void> {
    return new Promise((resolve, reject) => {
      const proc = spawn("ffmpeg", args);
      let stderr = "";
      proc.stderr?.on("data", (d) => (stderr += d.toString()));
      proc.on("error", (err) => reject(err));
      proc.on("close", (code) => {
        if (code === 0) return resolve();
        const err = new Error(`ffmpeg exited with code ${code}: ${stderr}`);
        return reject(err);
      });
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
        return res.status(400).json({ ok: false, error: "key_required" });
      }

      if (!r2Enabled()) {
        return res.json({ ok: false, error: "r2_not_enabled" });
      }

      const result = await r2Head(key);
      return res.json({
        ok: true,
        key,
        exists: result.exists,
        contentLength: result.contentLength,
        contentType: result.contentType,
      });
    } catch (err) {
      console.error("[debug/r2_head] error:", err);
      return res.status(500).json({ ok: false, error: "r2_head_failed" });
    }
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

  // POST /debug/render (stub -> silent mp3)
  debug.post("/render", renderLimiter, audit("/debug/render"), async (req: Request, res: Response) => {
    const { userId } = getPasskeySession(req as any);
    if (!userId) {
      return res.status(401).json({ error: "unauthorized" });
    }

    const { script_id, scene_id, role } = req.body || {};
    if (!script_id || !scene_id || !role) {
      return res.status(400).json({ error: "script_id, scene_id, role required" });
    }

    const script = await getOrLoadScript(script_id, userId);
    if (!script) {
      return res.status(404).json({ error: "script not found" });
    }

    const renderId = crypto.randomUUID();
    renders.set(renderId, { status: "working", accounted: false });
    const file = writeSilentMp3(renderId);

    // Upload to R2 if enabled
    if (r2Enabled()) {
      try {
        const r2Key = `renders/${renderId}.mp3`;
        await r2PutFile(r2Key, file, "audio/mpeg");
        console.log("[debug/render] Uploaded to R2: key=%s", r2Key);
      } catch (err) {
        console.warn("[debug/render] R2 upload failed:", err);
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
    res.json({ render_id: renderId, status: "complete" });
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
      if (!readerId) {
        console.log("[mixdown] Missing reader_render_id for takeId=%s", id);
        return res.status(404).json({ error: "reader_missing" });
      }

      // Check if download is requested
      const wantsDownload =
        (typeof req.query?.download === "string" && req.query.download === "1") ||
        (typeof req.query?.dl === "string" && req.query.dl === "1");

      const force = String(req.query?.force || "") === "1";

      // Determine if take is from R2
      const isR2Take = filePath.startsWith("r2://");
      let actualTakeFile = filePath;

      console.log("[mixdown] Take path type: %s, takeId=%s, userId=%s", isR2Take ? "r2" : "local", id, user.id);

      // Check if mixed file already exists in R2 (unless force=1)
      const outKey = `mixed/${user.id}/${id}.mp4`;
      if (!force && r2Enabled()) {
        try {
          const mixHead = await r2Head(outKey);
          if (mixHead.exists) {
            console.log("[mixdown] Found existing cached mix in R2: key=%s, takeId=%s, userId=%s", outKey, id, user.id);
            // Stream from R2
            const { stream, contentType, contentLength } = await r2GetObjectStream(outKey);
            res.setHeader("Content-Type", contentType || "video/mp4");
            if (contentLength !== undefined) {
              res.setHeader("Content-Length", contentLength);
            }
            if (wantsDownload) {
              const safeName = takeName.replace(/[^\w.-]+/g, "_").slice(0, 80) || "take";
              res.setHeader("Content-Disposition", `attachment; filename="${safeName}-room.mp4"`);
            }
            return stream.pipe(res);
          }
        } catch (err) {
          console.warn("[mixdown] R2 cache check failed for takeId=%s: %s", id, err);
        }
      }

      // Handle R2 take - download to temp
      if (isR2Take) {
        const r2Key = filePath.substring(5); // Remove "r2://" prefix

        // Download take from R2 to temp
        const tmpDir = path.join(os.tmpdir(), "offbook-mix");
        fs.mkdirSync(tmpDir, { recursive: true });
        tempTakeFile = path.join(tmpDir, `${id}.mp4`);

        console.log("[mixdown] Downloading R2 take to temp: key=%s, takeId=%s, userId=%s", r2Key, id, user.id);
        const { stream: takeStream } = await r2GetObjectStream(r2Key);
        await new Promise<void>((resolve, reject) => {
          const writeStream = fs.createWriteStream(tempTakeFile!);
          takeStream.pipe(writeStream);
          writeStream.on("finish", () => resolve());
          writeStream.on("error", reject);
        });

        actualTakeFile = tempTakeFile;
        console.log("[mixdown] R2 take downloaded successfully, takeId=%s", id);
      } else {
        // Local take
        console.log("[mixdown] Using local take file: %s, takeId=%s", filePath, id);
        if (!fs.existsSync(filePath)) {
          console.log("[mixdown] Local take file not found: %s, takeId=%s", filePath, id);
          return res.status(404).json({ error: "file_missing" });
        }
      }

      // Handle reader MP3
      const readerFile = path.join(ASSETS_DIR, `${readerId}.mp3`);
      let actualReaderFile = readerFile;

      if (!fs.existsSync(readerFile)) {
        console.log("[mixdown] Local reader not found, attempting R2: readerId=%s, takeId=%s", readerId, id);
        // Try to download from R2
        if (r2Enabled()) {
          const r2Key = `renders/${readerId}.mp3`;
          console.log("[mixdown] Downloading reader from R2 to temp: key=%s, readerId=%s, takeId=%s", r2Key, readerId, id);

          const tmpDir = path.join(os.tmpdir(), "offbook-mix");
          fs.mkdirSync(tmpDir, { recursive: true });
          tempReaderFile = path.join(tmpDir, `${readerId}.mp3`);

          try {
            const { stream: readerStream } = await r2GetObjectStream(r2Key);
            await new Promise<void>((resolve, reject) => {
              const writeStream = fs.createWriteStream(tempReaderFile!);
              readerStream.pipe(writeStream);
              writeStream.on("finish", () => resolve());
              writeStream.on("error", reject);
            });

            actualReaderFile = tempReaderFile;
            console.log("[mixdown] Reader downloaded successfully from R2, readerId=%s, takeId=%s", readerId, id);
          } catch (err) {
            console.log("[mixdown] Reader not found in R2: key=%s, readerId=%s, takeId=%s, error=%s", r2Key, readerId, id, err);
            return res.status(404).json({ error: "reader_audio_missing" });
          }
        } else {
          console.log("[mixdown] R2 not enabled and local reader missing: readerId=%s, takeId=%s", readerId, id);
          return res.status(404).json({ error: "reader_audio_missing" });
        }
      } else {
        console.log("[mixdown] Using local reader file: %s, readerId=%s, takeId=%s", readerFile, readerId, id);
      }

      // Determine output path - always use temp dir to avoid path.dirname(r2://)
      const tmpDir = path.join(os.tmpdir(), "offbook-mix");
      fs.mkdirSync(tmpDir, { recursive: true });
      const outPath = path.join(tmpDir, `${id}.mixed.mp4`);
      tempOutputFile = outPath;

      // Run ffmpeg to create mixed file
      const filter =
        "[1:a]aecho=0.6:0.5:30|45:0.25,highpass=f=160,lowpass=f=7200,volume=0.55[room];" +
        "[0:a][room]amix=inputs=2:duration=first:dropout_transition=4[aout]";
      const baseArgs = [
        "-y",
        "-i",
        actualTakeFile,
        "-i",
        actualReaderFile,
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

      console.log("[mixdown] Running ffmpeg to create mixed file, takeId=%s, userId=%s", id, user.id);
      try {
        await runFfmpeg([...baseArgs, "-c:v", "copy", outPath]);
        console.log("[mixdown] FFmpeg completed successfully (copy mode), takeId=%s", id);
      } catch (err) {
        console.warn("[mixdown] FFmpeg copy mode failed, retrying with transcode, takeId=%s: %s", id, err);
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
        console.log("[mixdown] FFmpeg completed successfully (transcode mode), takeId=%s", id);
      }

      // Upload to R2 if enabled
      if (r2Enabled()) {
        console.log("[mixdown] Uploading mixed file to R2: key=%s, takeId=%s, userId=%s", outKey, id, user.id);
        await r2PutFile(outKey, outPath, "video/mp4");
        console.log("[mixdown] Upload to R2 completed successfully, takeId=%s", id);
      }

      // Send file
      res.type("video/mp4");
      if (wantsDownload) {
        const safeName = takeName.replace(/[^\w.-]+/g, "_").slice(0, 80) || "take";
        res.setHeader("Content-Disposition", `attachment; filename="${safeName}-room.mp4"`);
      }

      console.log("[mixdown] Sending mixed file to client, takeId=%s, userId=%s", id, user.id);

      // Stream file and cleanup after
      res.sendFile(outPath, (err) => {
        // Cleanup temp files after sending (best effort)
        if (tempTakeFile) {
          try {
            fs.unlinkSync(tempTakeFile);
          } catch (e) {
            console.warn("[mixdown] Failed to cleanup temp take file:", e);
          }
        }
        if (tempReaderFile) {
          try {
            fs.unlinkSync(tempReaderFile);
          } catch (e) {
            console.warn("[mixdown] Failed to cleanup temp reader file:", e);
          }
        }
        if (tempOutputFile) {
          try {
            fs.unlinkSync(tempOutputFile);
          } catch (e) {
            console.warn("[mixdown] Failed to cleanup temp output file:", e);
          }
        }
        if (err) {
          console.error("[mixdown] Error sending file, takeId=%s: %s", id, err);
        } else {
          console.log("[mixdown] File sent successfully and temp files cleaned up, takeId=%s", id);
        }
      });
    } catch (err) {
      console.error("[mixdown] Error processing mixed file request, takeId=%s, userId=%s: %s", id, user?.id, err);
      // Cleanup temp files on error (best effort)
      if (tempTakeFile) {
        try {
          fs.unlinkSync(tempTakeFile);
        } catch (e) {
          console.warn("[gallery/mixed_file] Failed to cleanup temp take file:", e);
        }
      }
      if (tempReaderFile) {
        try {
          fs.unlinkSync(tempReaderFile);
        } catch (e) {
          console.warn("[gallery/mixed_file] Failed to cleanup temp reader file:", e);
        }
      }
      if (tempOutputFile) {
        try {
          fs.unlinkSync(tempOutputFile);
        } catch (e) {
          console.warn("[gallery/mixed_file] Failed to cleanup temp output file:", e);
        }
      }
      return res.status(500).json({ error: "internal_error" });
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
