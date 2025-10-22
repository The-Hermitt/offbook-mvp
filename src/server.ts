import express, { Request, Response, NextFunction } from "express";
import cors from "cors";
import path from "path";
import multer from "multer";
import { createRequire } from "module";

const app = express();
const PORT = Number(process.env.PORT || 3010);
const SHARED = process.env.SHARED_SECRET || "";

app.use(cors());
app.use(express.json({ limit: "5mb" }));
app.use(express.urlencoded({ extended: true }));

// Static UI
app.use("/public", express.static(path.join(process.cwd(), "public")));
app.use("/", express.static(path.join(process.cwd(), "public")));

function requireSecret(req: Request, res: Response, next: NextFunction) {
  if (!SHARED) return next();
  const header = req.get("X-Shared-Secret");
  if (header === SHARED) return next();
  res.status(401).json({ error: "unauthorized" });
}

// Health
app.get("/health", (_req, res) =>
  res.json({ ok: true, env: { PORT, has_shared_secret: !!SHARED } })
);
app.get("/health/tts", (_req, res) =>
  res.json({ engine: "openai", has_key: !!process.env.OPENAI_API_KEY })
);

// ---- In-memory fallback store
type Line = { speaker: string; text: string };
type Scene = { id: string; title: string; lines: Line[] };
type Script = { id: string; title: string; scenes: Scene[]; voices: Record<string, string> };

const mem = {
  scripts: new Map<string, Script>(),
  renders: new Map<string, { status: "queued" | "complete"; url?: string }>(),
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
  "INSERT", "MORE", "HERE", "CONTINUED", "CONT'D", "CONT’D",
  "ANGLE", "ANGLE ON", "CLOSE", "CLOSE ON", "WIDER", "WIDE",
  "CUT TO", "CUT TO:", "DISSOLVE TO", "SMASH CUT", "FADE IN", "FADE OUT",
  "CORNER OF THE ROOM", "CORNER", "ROOM", "POV", "MOMENTS LATER", "LATER",
  "DAY", "NIGHT", "MORNING", "EVENING", "DAWN", "DUSK",
]);

function looksLikePageNumber(l: string) { return /^\d+\.?$/.test(l.trim()); }
function endsWithPeriodWord(l: string) { return /^[A-Z0-9 .,'\-()]+?\.$/.test(l.trim()); }
function containsHeadingPhrases(l: string) {
  const s = l.trim().toUpperCase();
  if (s.includes(" OF THE ")) return true; // e.g., CORNER OF THE ROOM
  if (/^(INSERT|ANGLE|CLOSE|WIDER|WIDE)\b/.test(s)) return true;
  return false;
}
function isSceneHeader(l: string) {
  return /^(INT\.|EXT\.|INT\/EXT\.|SCENE|SHOT|MONTAGE|CUT TO:|FADE (IN|OUT):?)/i.test(l);
}

// Normalize a would-be label and decide if it's a non-character note
function isNonCharacterLabel(s: string) {
  const trimmed = (s || "").trim();
  const core = trimmed.replace(/[().]/g, "").replace(/\s+/g, " ").trim().toUpperCase();
  if (!core) return true;
  if (NON_CHAR_TOKENS.has(core)) return true;
  if (looksLikePageNumber(core)) return true;
  if (endsWithPeriodWord(trimmed)) return true;     // e.g., "HERE."
  if (containsHeadingPhrases(core)) return true;    // e.g., "... OF THE ..."
  // 3+ words containing OF/THE/etc. → likely location/camera
  if (core.split(" ").length >= 3 && /\b(OF|THE|ROOM|INT|EXT|CUT|TO|ON)\b/.test(core)) return true;
  return false;
}

// Strict ALL-CAPS name detector with heuristics to avoid directions/page junk
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

// e.g. "Jane", "Mr. Smith", "Dr. Adams", "The Clerk"
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

    // Skip obvious junk / headings
    if (!l || looksLikePageNumber(l) || isSceneHeader(l)) { i++; continue; }

    // CASE A: "Name: line" (mixed case allowed)
    const colon = colonNameMatch(l);
    if (colon && colon.speaker && colon.text) {
      scene.lines.push({ speaker: colon.speaker.toUpperCase(), text: colon.text });
      i++; continue;
    }

    // CASE B: Screenplay block (NAME on its own line)
    if (isAllCapsName(l) || isTitleCaseName(l)) {
      let speaker = l.replace(/[()]/g, "").trim();

      // *** HARD GUARD: drop non-character labels (kills HERE., INSERT, MORE, etc.) ***
      if (isNonCharacterLabel(speaker)) { i++; continue; }

      let j = i + 1;
      if (j < lines.length && isParenthetical(lines[j])) j++; // ignore one parenthetical

      const buf: string[] = [];
      while (j < lines.length) {
        const nxt = lines[j];
        if (!nxt || isSceneHeader(nxt) || isAllCapsName(nxt) || isTitleCaseName(nxt)) break;
        if (isParenthetical(nxt)) { j++; continue; }
        // Ignore pure all-caps action fragments that end with a period
        if (/^[A-Z0-9 .,'\-()]+?\.$/.test(nxt) && !/[a-z]/.test(nxt)) { j++; continue; }
        buf.push(nxt);
        j++;
      }
      const text = buf.join(" ").replace(/\s{2,}/g, " ").trim();
      if (speaker && text) scene.lines.push({ speaker: speaker.toUpperCase(), text });
      i = j + (lines[j] === "" ? 1 : 0);
      continue;
    }

    // Ignore ALL-CAPS action lines & leftover camera notes
    if (/^[A-Z0-9 .,'\-()]{3,}$/.test(l) && !/[a-z]/.test(l)) { i++; continue; }

    // Otherwise treat as narration
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

  // Robust PDF (text) extraction with multi-strategy import + diagnostics
  app.post("/debug/upload_script_upload", requireSecret, upload.single("pdf"), async (req: Request, res: Response) => {
    const title = String((req.body as any)?.title || "PDF");
    const pdfBuf = (req as any).file?.buffer as Buffer | undefined;
    if (!pdfBuf) return res.status(400).json({ error: "missing pdf file" });

    try {
      let pdfParseFn: any = null;

      // Strategy A: dynamic ESM import
      try {
        const modA: any = await import("pdf-parse");
        pdfParseFn = modA?.default || modA;
      } catch {}

      // Strategy B: CommonJS require via createRequire
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
        const scenes: Scene[] = [{
          id: genId("scn"),
          title,
          lines: [{ speaker: "SYSTEM", text: "PDF appears to be image-only. Paste script text for best parsing (OCR later)." }],
        }];
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
      const scenes: Scene[] = [{
        id: genId("scn"),
        title,
        lines: [{ speaker: "SYSTEM", text: "Could not parse PDF text. Please paste script text. (Error logged on server.)" }],
      }];
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

  app.post("/debug/render", requireSecret, (_req: Request, res: Response) => {
    const rid = genId("rnd");
    mem.renders.set(rid, { status: "queued" });
    setTimeout(() => { mem.renders.set(rid, { status: "complete", url: `/api/assets/${rid}` }); }, 600);
    res.json({ render_id: rid, status: "queued" });
  });

  app.get("/debug/render_status", requireSecret, (req: Request, res: Response) => {
    const rid = String(req.query.render_id || "");
    const r = mem.renders.get(rid);
    if (!r) return res.status(404).json({ error: "not found" });
    res.json({ status: r.status, download_url: r.url });
  });

  app.get("/api/assets/:render_id", (_req: Request, res: Response) => {
    res.setHeader("Content-Type", "audio/mpeg");
    res.send(Buffer.from([])); // 0-byte placeholder
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
  if (SHARED) console.log(`Debug routes require header X-Shared-Secret: ${SHARED}`);
  console.log("UI tip: open /app-tabs.html?secret=" + (SHARED || "(none)"));
});
