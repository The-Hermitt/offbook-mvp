import express, { Request, Response } from "express";
import cors from "cors";
import path from "path";
import multer from "multer";
import { createRequire } from "module";
import cookieParser from "cookie-parser";

const app = express();
const PORT = Number(process.env.PORT || 3010);
const OPENAI_API_KEY = process.env.OPENAI_API_KEY || "";

// --- tiny helper: safe fetch with timeout ---
async function fetchWithTimeout(input: RequestInfo, init: RequestInit & { timeoutMs?: number } = {}) {
  const { timeoutMs = 15000, ...rest } = init;
  const ac = new AbortController();
  const id = setTimeout(() => ac.abort(), timeoutMs);
  try {
    // @ts-ignore Node 18+ global fetch
    const res = await fetch(input as any, { ...rest, signal: ac.signal } as any);
    return res;
  } finally {
    clearTimeout(id);
  }
}

app.use(cors());
app.use(express.json({ limit: "5mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Static UI
app.use("/public", express.static(path.join(process.cwd(), "public")));
app.use("/", express.static(path.join(process.cwd(), "public")));

function getSharedSecret(): string | undefined {
  const s = process.env.SHARED_SECRET;
  return s && s.trim().length > 0 ? s.trim() : undefined;
}

type RequestWithCookies = import("express").Request & {
  cookies?: Record<string, unknown>;
};

function extractProvidedSecret(req: import("express").Request): string | undefined {
  const h = (req.headers["x-shared-secret"] as string | undefined)?.trim();
  const cookies = (req as RequestWithCookies).cookies;
  const rawCookie = cookies?.["ob_secret"];
  const c = typeof rawCookie === "string" ? rawCookie.trim() : undefined;
  return h || c || undefined;
}

function requireSharedSecret(): import("express").RequestHandler {
  return (req, res, next) => {
    const expected = getSharedSecret();
    if (!expected) return next();
    const provided = extractProvidedSecret(req);
    if (provided === expected) {
      if (!req.headers["x-shared-secret"]) {
        req.headers["x-shared-secret"] = provided;
      }
      return next();
    }
    res.status(401).json({
      error: "unauthorized",
      reason: "missing_or_invalid_secret",
    });
  };
}

const sharedSecretMiddleware = requireSharedSecret();
app.use("/debug", sharedSecretMiddleware);
const requireSecret = sharedSecretMiddleware;

// Health
app.get("/health", (_req, res) =>
  res.json({ ok: true, env: { PORT, has_shared_secret: !!getSharedSecret() } })
);
app.get("/health/tts", (_req, res) =>
  res.json({ engine: "openai", has_key: !!OPENAI_API_KEY })
);

// ---- In-memory store (fallback + rendered assets)
type Line = { speaker: string; text: string };
type Scene = { id: string; title: string; lines: Line[] };
type Script = { id: string; title: string; scenes: Scene[]; voices: Record<string, string> };

const mem = {
  scripts: new Map<string, Script>(),
  renders: new Map<string, { status: "queued" | "complete" | "error"; url?: string; err?: string }>(),
  assets: new Map<string, Buffer>(), // id -> MP3 bytes (for renders and single-line TTS)
};
const upload = multer({ storage: multer.memoryStorage() });

function genId(prefix: string) {
  return prefix + "-" + Math.random().toString(36).slice(2, 10);
}

// ---------- Normalization & parsing ----------
function normalizePdfText(raw: string): string {
  if (!raw) return "";
  let t = raw.replace(/\r\n/g, "\n");
  t = t.replace(/-\n/g, ""); // dehyphenate line breaks
  t = t.replace(/\b(?:[A-Z]\s){2,}[A-Z]\b/g, s => s.replace(/\s+/g, "")); // J A N E -> JANE
  t = t.replace(/[ \t]{2,}/g, " ");
  return t;
}

// Common non-character headings/directions seen in OCR
const NON_CHAR_TOKENS = new Set([
  "INSERT","MORE","HERE","CONTINUED","CONT'D","CONT’D",
  "ANGLE","ANGLE ON","CLOSE","CLOSE ON","WIDER","WIDE",
  "CUT TO","CUT TO:","DISSOLVE TO","SMASH CUT","FADE IN","FADE OUT",
  "CORNER OF THE ROOM","CORNER","ROOM","POV","MOMENTS LATER","LATER",
  "DAY","NIGHT","MORNING","EVENING","DAWN","DUSK",
]);
function looksLikePageNumber(l: string) { return /^\d+\.?$/.test(l.trim()); }
function endsWithPeriodWord(l: string) { return /^[A-Z0-9 .,'\-()]+?\.$/.test(l.trim()); }
function containsHeadingPhrases(l: string) {
  const s = l.trim().toUpperCase();
  if (s.includes(" OF THE ")) return true;
  if (/^(INSERT|ANGLE|CLOSE|WIDER|WIDE)\b/.test(s)) return true;
  return false;
}
function isSceneHeader(l: string) {
  return /^(INT\.|EXT\.|INT\/EXT\.|SCENE|SHOT|MONTAGE|CUT TO:|FADE (IN|OUT):?)/i.test(l);
}
function isNonCharacterLabel(s: string) {
  const trimmed = (s || "").trim();
  const core = trimmed.replace(/[().]/g, "").replace(/\s+/g, " ").trim().toUpperCase();
  if (!core) return true;
  if (NON_CHAR_TOKENS.has(core)) return true;
  if (looksLikePageNumber(core)) return true;
  if (endsWithPeriodWord(trimmed)) return true;
  if (containsHeadingPhrases(core)) return true;
  if (core.split(" ").length >= 3 && /\b(OF|THE|ROOM|INT|EXT|CUT|TO|ON)\b/.test(core)) return true;
  return false;
}
function isAllCapsName(l: string) {
  const s = l.trim();
  if (!s) return false;
  if (!/^[A-Z0-9 .,'\-()]+$/.test(s)) return false;
  if (/[a-z]/.test(s)) return false;
  if (s.length > 40) return false;
  if (isSceneHeader(s)) return false;
  if (isNonCharacterLabel(s)) return false;
  return true;
}
function isTitleCaseName(l: string) {
  const s = l.trim();
  if (containsHeadingPhrases(s)) return false;
  if (/^(Insert|Angle|Close|Wide|Exterior|Interior)\b/.test(s)) return false;
  return /^([A-Z][a-z]+\.?)(\s+[A-Z][a-z]+\.?){0,3}$/.test(s) && !isSceneHeader(s) && s.length <= 40;
}
function isParenthetical(l: string) { return /^\(.*\)$/.test(l.trim()); }
function colonNameMatch(l: string) {
  const m = l.match(/^([A-Za-z][A-Za-z0-9 .&()'\-]+)\s*:\s*(.+)$/);
  if (!m) return null;
  const speakerRaw = m[1].trim();
  if (isNonCharacterLabel(speakerRaw)) return null;
  const speaker = speakerRaw.replace(/[()]/g, "").trim();
  const text = m[2].trim();
  return { speaker, text };
}
function parseTextToScenes(title: string, raw: string): Scene[] {
  const scene: Scene = { id: genId("scn"), title: title || "Scene 1", lines: [] };
  const lines = (raw || "").split(/\n/).map(l => l.replace(/\t/g, " ").trim());
  let i = 0;
  while (i < lines.length) {
    let l = lines[i];
    if (!l || looksLikePageNumber(l) || isSceneHeader(l)) { i++; continue; }
    const colon = colonNameMatch(l);
    if (colon && colon.speaker && colon.text) {
      scene.lines.push({ speaker: colon.speaker.toUpperCase(), text: colon.text });
      i++; continue;
    }
    if (isAllCapsName(l) || isTitleCaseName(l)) {
      let speaker = l.replace(/[()]/g, "").trim();
      if (isNonCharacterLabel(speaker)) { i++; continue; }
      let j = i + 1;
      if (j < lines.length && isParenthetical(lines[j])) j++;
      const buf: string[] = [];
      while (j < lines.length) {
        const nxt = lines[j];
        if (!nxt || isSceneHeader(nxt) || isAllCapsName(nxt) || isTitleCaseName(nxt)) break;
        if (isParenthetical(nxt)) { j++; continue; }
        if (/^[A-Z0-9 .,'\-()]+?\.$/.test(nxt) && !/[a-z]/.test(nxt)) { j++; continue; }
        buf.push(nxt);
        j++;
      }
      const text = buf.join(" ").replace(/\s{2,}/g, " ").trim();
      if (speaker && text) scene.lines.push({ speaker: speaker.toUpperCase(), text });
      i = j + (lines[j] === "" ? 1 : 0);
      continue;
    }
    if (/^[A-Z0-9 .,'\-()]{3,}$/.test(l) && !/[a-z]/.test(l)) { i++; continue; }
    scene.lines.push({ speaker: "NARRATOR", text: l });
    i++;
  }
  return [scene];
}
function uniqueSpeakers(sc: Scene) {
  const set = new Set<string>();
  for (const ln of sc.lines) set.add(ln.speaker);
  set.delete("NARRATOR"); set.delete("SYSTEM");
  return Array.from(set);
}
const isBoilerplate = (txt: string) => {
  const s = (txt || "").trim().toLowerCase();
  if (!s) return true;
  if (/^[-–—]+$/.test(s)) return true;
  if (/^\d{1,4}$/.test(s)) return true;
  if (/^page\s*\d+(\s*of\s*\d+)?$/.test(s)) return true;
  if (/^cont'?d\.?$/.test(s) || /^continued$/.test(s)) return true;
  if (s.includes("sides by breakdown services") || s.includes("actors access") || s.includes("do not share") || s.includes("copyright")) return true;
  return false;
};

// ---------- OpenAI TTS ----------
async function openaiTts(text: string, voice = "alloy", model = "tts-1"): Promise<Buffer> {
  const res = await fetchWithTimeout("https://api.openai.com/v1/audio/speech", {
    method: "POST",
    timeoutMs: 30000,
    headers: {
      "Authorization": `Bearer ${OPENAI_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ model, voice, input: text, format: "mp3" }),
  });
  if (!res.ok) {
    const msg = await res.text().catch(() => res.statusText);
    throw new Error(`OpenAI TTS HTTP ${res.status}: ${msg.slice(0, 200)}`);
  }
  const buf = Buffer.from(await res.arrayBuffer());
  return buf;
}

// Tiny health probe
async function openaiTtsProbe(opts?: { text?: string; voice?: string; model?: string }) {
  if (!OPENAI_API_KEY) return { ok: false, error: "OPENAI_API_KEY not set" };
  try {
    await openaiTts(opts?.text ?? "test", opts?.voice ?? "alloy", opts?.model ?? "tts-1");
    return { ok: true, provider: "openai", model: opts?.model ?? "tts-1", voice: opts?.voice ?? "alloy" };
  } catch (e: any) {
    return { ok: false, error: e?.message || String(e) };
  }
}

// Concatenate MP3 buffers (naive but works for same-encoder MP3)
function concatMp3(parts: Buffer[]): Buffer {
  if (parts.length === 1) return parts[0];
  return Buffer.concat(parts);
}

/* -------------------- ALWAYS-ON ROUTES -------------------- */
// 1) TTS health (safe)
app.get("/debug/tts_check", requireSecret, async (_req: Request, res: Response) => {
  const result = await openaiTtsProbe({ text: "test", voice: "alloy" });
  if (!result.ok) return res.status(500).json(result);
  res.json(result);
});

// 2) Single-line TTS for Rehearse/Diagnostics
app.post("/debug/tts_line", requireSecret, async (req: Request, res: Response) => {
  try {
    if (!OPENAI_API_KEY) return res.status(500).json({ error: "OPENAI_API_KEY not set" });
    const voice = String((req.body as any)?.voice || "alloy");
    const text = String((req.body as any)?.text || "").trim();
    if (!text) return res.status(400).json({ error: "missing text" });

    const buf = await openaiTts(text, voice, "tts-1");
    const id = genId("tts");
    mem.assets.set(id, buf);
    return res.json({ url: `/api/assets/${id}` });
  } catch (e: any) {
    const msg = e?.message || String(e);
    return res.status(500).json({ error: msg.slice(0, 200) });
  }
});
/* ---------------------------------------------------------- */

// ---------- Routes ----------
function mountFallbackDebugRoutes() {
  app.get("/debug/ping", requireSecret, (_req, res) => res.json({ ok: true }));

  app.post("/debug/upload_script_text", requireSecret, (req: Request, res: Response) => {
    const title = String(req.body?.title || "Script");
    const text = String(req.body?.text || "");
    const id = genId("scr");
    const scenes = parseTextToScenes(title, text);
    const speakers = uniqueSpeakers(scenes[0]);
    mem.scripts.set(id, { id, title, scenes, voices: {} });
    res.json({ script_id: id, scene_count: scenes.length, speakers });
  });

  // Robust PDF (text) import
  app.post("/debug/upload_script_upload", requireSecret, upload.single("pdf"), async (req: Request, res: Response) => {
    const title = String((req.body as any)?.title || "PDF");
    const pdfBuf = (req as any).file?.buffer as Buffer | undefined;
    if (!pdfBuf) return res.status(400).json({ error: "missing pdf file" });

    try {
      let pdfParseFn: any = null;
      try { const modA: any = await import("pdf-parse"); pdfParseFn = modA?.default || modA; } catch {}
      if (!pdfParseFn) {
        const reqr = createRequire(import.meta.url);
        const modB: any = reqr("pdf-parse");
        pdfParseFn = modB?.default || modB;
      }
      if (typeof pdfParseFn !== "function") throw new Error("pdf-parse load failed (no function export)");

      const data = await pdfParseFn(pdfBuf);
      let text = String(data?.text || "");
      const textLenRaw = text.length;

      if (textLenRaw < 20) {
        const id = genId("scr");
        const scenes: Scene[] = [{ id: genId("scn"), title, lines: [{ speaker: "SYSTEM", text: "PDF appears to be image-only. Paste script text for best parsing (OCR later)." }] }];
        mem.scripts.set(id, { id, title, scenes, voices: {} });
        return res.json({ script_id: id, scene_count: scenes.length, note: "image-only", textLen: textLenRaw });
      }

      text = normalizePdfText(text);
      const scenes = parseTextToScenes(title, text);
      const speakers = uniqueSpeakers(scenes[0]);

      const id = genId("scr");
      mem.scripts.set(id, { id, title, scenes, voices: {} });
      return res.json({ script_id: id, scene_count: scenes.length, speakers, textLen: text.length });
    } catch (e: any) {
      const msg = (e?.message || String(e)).slice(0, 200);
      console.error("[pdf] extract failed:", msg);
      const id = genId("scr");
      const scenes: Scene[] = [{ id: genId("scn"), title, lines: [{ speaker: "SYSTEM", text: "Could not parse PDF text. Please paste script text. (Error logged on server.)" }] }];
      mem.scripts.set(id, { id, title, scenes, voices: {} });
      return res.json({ script_id: id, scene_count: scenes.length, note: "parse-error", error: msg });
    }
  });

  app.get("/debug/scenes", requireSecret, (req: Request, res: Response) => {
    const script_id = String(req.query.script_id || "");
    const s = mem.scripts.get(script_id);
    if (!s) return res.status(404).json({ error: "not found" });
    res.json({ script_id, scenes: s.scenes });
  });

  app.post("/debug/set_voice", requireSecret, (req: Request, res: Response) => {
    const script_id = String((req.body as any)?.script_id || "");
    const voice_map = (req.body as any)?.voice_map || {};
    const s = mem.scripts.get(script_id);
    if (!s) return res.status(404).json({ error: "not found" });
    Object.assign(s.voices, voice_map);
    res.json({ ok: true });
  });

  // REAL: Render partner-only reader MP3 with OpenAI
  app.post("/debug/render", requireSecret, async (req: Request, res: Response) => {
    const script_id = String((req.body as any)?.script_id || "");
    const myRole = String((req.body as any)?.my_role || "").toUpperCase();
    const paceMs = Number((req.body as any)?.pace_ms || 0);
    const s = mem.scripts.get(script_id);
    if (!s) return res.status(404).json({ error: "script not found" });
    if (!OPENAI_API_KEY) return res.status(500).json({ error: "OPENAI_API_KEY not set" });

    const rid = genId("rnd");
    mem.renders.set(rid, { status: "queued" });

    (async () => {
      try {
        const scene = s.scenes[0];
        const items = scene.lines
          .filter(ln => ln && ln.speaker && ln.speaker !== "NARRATOR" && ln.speaker !== "SYSTEM")
          .filter(ln => ln.speaker !== myRole)
          .filter(ln => !isBoilerplate(ln.text));

        const voiceFor = (name: string) => (s.voices[name] || "alloy");

        const chunks: Buffer[] = [];
        for (const ln of items) {
          const voice = voiceFor(ln.speaker);
          const b = await openaiTts(ln.text, voice, "tts-1");
          chunks.push(b);
          if (paceMs > 0) {
            // optional silence could be inserted later
          }
        }

        const mp3 = concatMp3(chunks.length ? chunks : [await openaiTts(" ", "alloy", "tts-1")]);
        mem.assets.set(rid, mp3);
        mem.renders.set(rid, { status: "complete", url: `/api/assets/${rid}` });
      } catch (e: any) {
        const msg = e?.message || String(e);
        mem.renders.set(rid, { status: "error", err: msg });
      }
    })();

    res.json({ render_id: rid, status: "queued" });
  });

  app.get("/debug/render_status", requireSecret, (req: Request, res: Response) => {
    const rid = String(req.query.render_id || "");
    const r = mem.renders.get(rid);
    if (!r) return res.status(404).json({ error: "not found" });
    res.json({ status: r.status, download_url: r.url, error: r.err });
  });

  app.get("/api/assets/:render_id", (req: Request, res: Response) => {
    const rid = String(req.params.render_id || "");
    const buf = mem.assets.get(rid);
    if (!buf) return res.status(404).json({ error: "asset not found" });
    res.setHeader("Content-Type", "audio/mpeg");
    res.setHeader("Cache-Control", "no-store");
    res.send(buf);
  });

  console.log("[fallback] /debug/* routes active (in-memory, robust PDF import + strict speaker guard)");
}

// Prefer real project routes if present
async function tryMountProjectHttpRoutes() {
  try {
    const mod =
      (await import("./http-routes.js").catch(() => null)) ||
      (await import("./http-routes").catch(() => null));
    if (mod && (typeof (mod as any).registerHttpRoutes === "function" || typeof (mod as any).default === "function")) {
      const fn = ((mod as any).registerHttpRoutes || (mod as any).default) as (app: express.Express) => void;
      fn(app);
      console.log("[http-routes] mounted real handlers");
      return true;
    }
    if (mod) console.warn("[http-routes] present but no handler export detected");
  } catch (e) {
    console.warn("[http-routes] failed to import, using fallback:", e);
  }
  return false;
}

await tryMountProjectHttpRoutes().then((mounted) => { if (!mounted) mountFallbackDebugRoutes(); });

// Start
app.listen(PORT, () => {
  console.log(`OffBook MVP listening on http://localhost:${PORT}`);
  const shared = getSharedSecret();
  if (shared) console.log(`Debug routes require header X-Shared-Secret: ${shared}`);
  console.log("UI tip: open /app-tabs.html?secret=" + (shared || "(none)"));
});
