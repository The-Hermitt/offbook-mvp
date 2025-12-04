import "dotenv/config";
import express, { Request, Response } from "express";
import cors from "cors";
import path from "path";
import multer from "multer";
import { createRequire } from "module";
import cookieParser from "cookie-parser";
import cookieSession from "cookie-session";
import Stripe from "stripe";
import authRouter, { getPasskeySession, noteRenderComplete } from "./routes/auth";
import db from "./lib/db";
import { addUserCredits, getAvailableCredits } from "./lib/credits";
import { ensureAuditTable, makeAuditMiddleware } from "./lib/audit";
import { makeRateLimiters } from "./middleware/rateLimit";

const app = express();
const PORT = Number(process.env.PORT || 3010);
const OPENAI_API_KEY = process.env.OPENAI_API_KEY || "";
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || "";
const stripe =
  STRIPE_SECRET_KEY
    ? new Stripe(STRIPE_SECRET_KEY)
    : null;
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || "";

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

// Use JSON for most routes, but skip it for the Stripe webhook so we can
// access the raw request body for signature verification.
const jsonParser = express.json({ limit: "5mb" });
app.use((req, res, next) => {
  if (req.originalUrl === "/billing/webhook") {
    return next();
  }
  return jsonParser(req, res, next);
});

app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Static UI
app.use("/public", express.static(path.join(process.cwd(), "public")));
app.use("/", express.static(path.join(process.cwd(), "public")));

if (typeof app?.set === "function") { app.set("trust proxy", 1); }

app.use(cookieSession({
  name: "ob_sess",
  secret: process.env.SESSION_SECRET || "dev-secret-change-me",
  sameSite: "lax",
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  maxAge: 1000 * 60 * 60 * 24 * 30, // 30 days
}));

app.use("/auth", authRouter);

ensureAuditTable(db);
const audit = makeAuditMiddleware(db);
const { debugLimiter, renderLimiter } = makeRateLimiters();

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
app.use("/debug", sharedSecretMiddleware, debugLimiter);
const requireSecret = sharedSecretMiddleware;

// Health
app.get("/health", (_req, res) =>
  res.json({ ok: true, env: { PORT, has_shared_secret: !!getSharedSecret() } })
);
app.get("/health/tts", (_req, res) =>
  res.json({ engine: "openai", has_key: !!OPENAI_API_KEY })
);

// Billing — Phase 1: real Stripe Checkout (test mode)
app.post("/billing/create_checkout", express.json(), async (req: Request, res: Response) => {
  try {
    if (!stripe) {
      return res.status(500).json({
        ok: false,
        error: "stripe_not_configured",
      });
    }

    const body = (req.body || {}) as { planId?: string };
    const planId = body.planId || "credits-100";

    const priceId = process.env.STRIPE_PRICE_TOPUP_100;
    if (!priceId) {
      return res.status(500).json({
        ok: false,
        error: "missing_price_id",
      });
    }

    const { passkeyLoggedIn, userId } = getPasskeySession(req);
    if (!passkeyLoggedIn || !userId) {
      return res.status(401).json({
        error: "Sign in with a passkey before purchasing credits.",
      });
    }

    const successUrl =
      process.env.STRIPE_SUCCESS_URL ||
      "https://example.com/offbook-success";
    const cancelUrl =
      process.env.STRIPE_CANCEL_URL ||
      "https://example.com/offbook-cancel";

    const session = await stripe.checkout.sessions.create({
      mode: "payment",
      line_items: [
        {
          price: priceId,
          quantity: 1,
        },
      ],
      success_url: successUrl,
      cancel_url: cancelUrl,
      client_reference_id: userId,
      metadata: {
        userId,
        planId,
      },
    });

    console.log("[billing] stripe checkout session=%s plan=%s", session.id, planId);

    return res.json({
      ok: true,
      checkout_url: session.url,
      mode: "stripe_test",
    });
  } catch (e: any) {
    console.error("[billing] create_checkout error", e);
    const msg = e?.message || String(e);
    return res.status(500).json({
      ok: false,
      error: msg.slice(0, 200),
    });
  }
});

// Billing — Stripe webhook (test mode, signature-verified)
app.post(
  "/billing/webhook",
  // Stripe requires the raw request body for signature verification.
  express.raw({ type: "application/json" }),
  async (req: Request, res: Response) => {
    try {
      if (!stripe || !STRIPE_WEBHOOK_SECRET) {
        console.warn(
          "[billing] webhook misconfigured (missing stripe or STRIPE_WEBHOOK_SECRET)"
        );
        // Return 200 so Stripe does not endlessly retry in dev.
        return res.status(200).json({
          ok: true,
          ignored: true,
          reason: "billing_not_configured",
        });
      }

      const sig = req.header("stripe-signature") || "";
      const rawBody = req.body as Buffer;

      let event: Stripe.Event;
      try {
        event = stripe.webhooks.constructEvent(
          rawBody,
          sig,
          STRIPE_WEBHOOK_SECRET
        );
      } catch (err: any) {
        console.error(
          "[billing] webhook signature verification failed",
          err?.message || err
        );
        return res.status(400).send("Webhook signature verification failed");
      }

      const eventType = event.type;
      const eventId = event.id;

      console.log("[billing] webhook raw hit", {
        path: req.path,
        stripeSignature: sig,
        eventType,
        eventId,
      });

      // For now we treat any successful checkout as a 100-credit top-up
      // for the single dev user. Later this will map to the real user id.
      if (eventType === "checkout.session.completed") {
        const session = event.data.object as Stripe.Checkout.Session;

        const userIdFromClientRef = session.client_reference_id;
        const userIdFromMetadata =
          (session.metadata && (session.metadata as any).userId) || null;
        const userId = (userIdFromClientRef || userIdFromMetadata || "").toString().trim();

        if (!userId) {
          console.warn("Stripe webhook: missing userId on session", session.id);
          return res.json({ received: true });
        }

        // For now we hard-code the plan → credits mapping.
        // "credits-100" → 100 credits; adjust later if we add more plans.
        const creditsToGrant = 100;

        const updated = await addUserCredits(userId, creditsToGrant);

        const totalCredits = updated.total_credits;
        const usedCredits = updated.used_credits;
        const availableCredits = getAvailableCredits(updated);

        console.log("[billing] webhook credited", {
          userId,
          creditsAdded: creditsToGrant,
          totalCredits,
          usedCredits,
          availableCredits,
          stripeEventId: eventId,
        });
      }

      return res.json({ received: true });
    } catch (e: any) {
      console.error("[billing] webhook error", e);
      return res.status(500).json({ ok: false, error: "webhook_error" });
    }
  }
);

// ---- In-memory store (fallback + rendered assets)
type Line = { speaker: string; text: string };
type Scene = { id: string; title: string; lines: Line[] };
type Script = { id: string; title: string; scenes: Scene[]; voices: Record<string, string> };

type RenderJob = {
  status: "queued" | "complete" | "error";
  url?: string;
  err?: string;
  accounted?: boolean;
};

const mem = {
  scripts: new Map<string, Script>(),
  renders: new Map<string, RenderJob>(),
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

function getUserIdForRequest(req: Request): string {
  try {
    const { passkeyLoggedIn, userId } = getPasskeySession(req as any);
    if (passkeyLoggedIn && userId && typeof userId === "string" && userId.trim()) {
      return userId.trim();
    }
  } catch (e) {
    console.warn("[auth] getUserIdForRequest: falling back to solo-tester", (e as any)?.message || e);
  }
  return "solo-tester";
}

function persistScriptToDb(
  id: string,
  userId: string,
  title: string,
  scenes: Scene[]
): void {
  try {
    const cleanId = (id || "").trim();
    if (!cleanId) return;

    const cleanTitle = (title || "Sides").trim();
    const safeScenes = Array.isArray(scenes) ? scenes : [];
    const scenesJson = JSON.stringify(safeScenes);
    const sceneCount = safeScenes.length;

    const stmt = db.prepare(
      `INSERT INTO scripts (id, user_id, title, scene_count, scenes_json, created_at, updated_at)
       VALUES (@id, @user_id, @title, @scene_count, @scenes_json, datetime('now'), datetime('now'))
       ON CONFLICT(id) DO UPDATE SET
         user_id = excluded.user_id,
         title = excluded.title,
         scene_count = excluded.scene_count,
         scenes_json = excluded.scenes_json,
         updated_at = datetime('now')`
    );

    stmt.run({
      id: cleanId,
      user_id: userId,
      title: cleanTitle,
      scene_count: sceneCount,
      scenes_json: scenesJson,
    });

    console.log("[scripts] persisted script", {
      id: cleanId,
      userId,
      title: cleanTitle,
      sceneCount,
    });
  } catch (e: any) {
    console.error("[scripts] failed to persist script", {
      id,
      title,
      error: e?.message || e,
    });
  }
}

type ScriptRow = {
  id: string;
  user_id: string | null;
  title: string | null;
  scene_count: number | null;
  scenes_json: string | null;
  created_at?: string;
  updated_at?: string;
};

const loadScriptByIdStmt = db.prepare<Pick<ScriptRow, "id">, ScriptRow>(`
  SELECT id, user_id, title, scene_count, scenes_json, created_at, updated_at
  FROM scripts
  WHERE id = @id
`);

function loadScriptFromDb(id: string): ScriptRow | null {
  if (!id || !id.trim()) return null;
  try {
    return loadScriptByIdStmt.get({ id: id.trim() }) ?? null;
  } catch (e) {
    console.error("[scripts] failed to load script from DB", {
      id,
      error: (e as any)?.message || e,
    });
    return null;
  }
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

// STT stub: accept a small audio chunk and return a dummy transcript.
// This does NOT call OpenAI yet; it's only to prove wiring.
app.post(
  "/debug/stt_transcribe_chunk",
  requireSecret,
  express.json({ limit: "2mb" }),
  async (req: Request, res: Response) => {
    try {
      const body = (req.body || {}) as {
        audio_b64?: string;
        mime?: string;
      };

      const { audio_b64, mime } = body;

      if (!audio_b64 || typeof audio_b64 !== "string") {
        return res
          .status(400)
          .json({ ok: false, error: "missing_audio" });
      }

      const buf = Buffer.from(audio_b64, "base64");

      console.log("[stt] stub received chunk", {
        bytes: buf.length,
        mime: mime || null,
      });

      // Dummy response; client won’t rely on this yet.
      return res.json({
        ok: true,
        transcript: "",
        confidence: 0,
        isGoodCue: false,
      });
    } catch (err) {
      console.error("[stt] stub error", err);
      return res.status(500).json({ ok: false, error: "stt_failed" });
    }
  }
);
/* ---------------------------------------------------------- */

app.get("/api/my_scripts", async (req: Request, res: Response) => {
  try {
    const userId = getUserIdForRequest(req);

    const stmt = db.prepare(
      `SELECT id, user_id, title, scene_count, updated_at
       FROM scripts
       ORDER BY datetime(updated_at) DESC`
    );

    const rows = stmt.all({}) as any[];

    const seen = new Set<string>();
    const scripts = rows
      .filter((row) => {
        if (!row || !row.id) return false;
        if (seen.has(row.id)) return false;
        seen.add(row.id);
        return true;
      })
      .map((row) => ({
        id: row.id,
        title: row.title,
        sceneCount:
          typeof row.scene_count === "number" ? row.scene_count : 0,
        updatedAt: row.updated_at,
      }));

    console.log("[scripts] /api/my_scripts", {
      userId,
      count: scripts.length,
    });

    res.json({ scripts });
  } catch (e: any) {
    console.error("[scripts] /api/my_scripts failed:", e?.message || e);
    res.status(500).json({ error: "failed_to_list_scripts" });
  }
});

app.get("/api/scripts/:id", (req: Request, res: Response) => {
  const id = (req.params.id || "").trim();
  if (!id) {
    return res.status(400).json({ error: "missing_id" });
  }

  const row = loadScriptFromDb(id);
  let script = mem.scripts.get(id);

  if (!script && row) {
    let scenes: Scene[] = [];
    if (row.scenes_json) {
      try {
        scenes = JSON.parse(row.scenes_json) as Scene[];
      } catch (e) {
        console.error("[scripts] failed to parse scenes_json from DB", {
          id,
          error: (e as any)?.message || e,
        });
      }
    }

    script = {
      id: row.id,
      title: row.title || "Sides",
      scenes,
      voices: {},
    };

    mem.scripts.set(id, script);
  }

  if (!script) {
    return res.status(404).json({ error: "not_found" });
  }

  return res.json({
    id: script.id,
    title: script.title,
    scenes: script.scenes,
    voices: script.voices || {},
  });
});

app.post("/api/scripts/:id/save", async (req: Request, res: Response) => {
  try {
    const userId = getUserIdForRequest(req);
    const id = (req.params.id || "").trim();
    if (!id) {
      return res.status(400).json({ error: "missing_script_id" });
    }

    const body = req.body || {};
    const rawTitle =
      typeof body.title === "string" ? (body.title as string).trim() : "";
    const scenesRaw = body.scenes;
    const scenes = Array.isArray(scenesRaw) ? (scenesRaw as Scene[]) : [];

    let existingTitle = "";

    try {
      const row = db
        .prepare("SELECT id, title FROM scripts WHERE id = @id AND user_id = @user_id")
        .get({ id, user_id: userId }) as any;
      if (!row) {
        // If there is no existing row for this user+id, treat as not found.
        return res.status(404).json({ error: "script_not_found" });
      }
      existingTitle = (row.title as string) || "";
    } catch (e: any) {
      console.error("[scripts] /api/scripts/:id/save ownership check failed:", e?.message || e);
      // Continue; we still try to persist as a best-effort.
    }

    const finalTitle = rawTitle || existingTitle || "Sides";

    // Persist new title + scenes to DB
    persistScriptToDb(id, userId, finalTitle, scenes);

    return res.json({ ok: true });
  } catch (e: any) {
    console.error("[scripts] POST /api/scripts/:id/save failed:", e?.message || e);
    return res.status(500).json({ error: "failed_to_save_script" });
  }
});

app.delete("/api/scripts/:id", async (req: Request, res: Response) => {
  try {
    const userId = getUserIdForRequest(req); // keep this for logging if needed later
    const id = (req.params.id || "").trim();

    if (!id) {
      return res.status(400).json({ error: "missing_script_id" });
    }

    const stmt = db.prepare("DELETE FROM scripts WHERE id = @id");
    const info = stmt.run({ id });

    if (info.changes === 0) {
      // Nothing deleted: either it never existed or was already removed.
      return res.status(404).json({ ok: false, error: "script_not_found" });
    }

    return res.json({ ok: true });
  } catch (e: any) {
    console.error("[scripts] DELETE /api/scripts/:id failed:", e?.message || e);
    return res.status(500).json({ error: "failed_to_delete_script" });
  }
});

// ---------- Routes ----------
function mountFallbackDebugRoutes() {
  app.get("/debug/ping", requireSecret, (_req, res) => res.json({ ok: true }));
  app.get("/debug/whoami", requireSecret, (req: Request, res: Response) => {
    res.json({ ok: true, marker: "fallback/server.ts" });
  });

  app.post(
    "/debug/upload_script_text",
    requireSecret,
    audit("/debug/upload_script_text"),
    (req: Request, res: Response) => {
      const userId = getUserIdForRequest(req);
      const title = String(req.body?.title || "Script");
      const text = String(req.body?.text || "");
      const id = genId("scr");
      const scenes = parseTextToScenes(title, text);
      const speakers = uniqueSpeakers(scenes[0]);

      mem.scripts.set(id, { id, title, scenes, voices: {} });
      persistScriptToDb(id, userId, title, scenes);

      res.json({ script_id: id, scene_count: scenes.length, speakers });
    }
  );

  // Robust PDF (text) import
  app.post(
    "/debug/upload_script_upload",
    requireSecret,
    audit("/debug/upload_script_upload"),
    upload.single("pdf"),
    async (req: Request, res: Response) => {
      const userId = getUserIdForRequest(req);
      const title = String((req.body as any)?.title || "PDF");
      const pdfBuf = (req as any).file?.buffer as Buffer | undefined;
      if (!pdfBuf) return res.status(400).json({ error: "missing pdf file" });

      try {
        let pdfParseFn: any = null;
        try {
          const modA: any = await import("pdf-parse");
          pdfParseFn = modA?.default || modA;
        } catch {}
        if (!pdfParseFn) {
          const reqr = createRequire(import.meta.url);
          const modB: any = reqr("pdf-parse");
          pdfParseFn = modB?.default || modB;
        }
        if (typeof pdfParseFn !== "function") {
          throw new Error("pdf-parse load failed (no function export)");
        }

        const data = await pdfParseFn(pdfBuf);
        let text = String(data?.text || "");
        const textLenRaw = text.length;

        if (textLenRaw < 20) {
          const id = genId("scr");
          const scenes: Scene[] = [
            {
              id: genId("scn"),
              title,
              lines: [
                {
                  speaker: "SYSTEM",
                  text: "PDF appears to be image-only. Paste script text for best parsing (OCR later).",
                },
              ],
            },
          ];
          mem.scripts.set(id, { id, title, scenes, voices: {} });
          persistScriptToDb(id, userId, title, scenes);
          return res.json({
            script_id: id,
            scene_count: scenes.length,
            note: "image-only",
            textLen: textLenRaw,
          });
        }

        text = normalizePdfText(text);
        const scenes = parseTextToScenes(title, text);
        const speakers = uniqueSpeakers(scenes[0]);

        const id = genId("scr");
        mem.scripts.set(id, { id, title, scenes, voices: {} });
        persistScriptToDb(id, userId, title, scenes);
        return res.json({
          script_id: id,
          scene_count: scenes.length,
          speakers,
          textLen: text.length,
        });
      } catch (e: any) {
        const msg = (e?.message || String(e)).slice(0, 200);
        console.error("[pdf] extract failed:", msg);
        const id = genId("scr");
        const scenes: Scene[] = [
          {
            id: genId("scn"),
            title,
            lines: [
              {
                speaker: "SYSTEM",
                text: "Could not parse PDF text. Please paste script text. (Error logged on server.)",
              },
            ],
          },
        ];
        mem.scripts.set(id, { id, title, scenes, voices: {} });
        persistScriptToDb(id, userId, title, scenes);
        return res.json({
          script_id: id,
          scene_count: scenes.length,
          note: "parse-error",
          error: msg,
        });
      }
    }
  );

  app.get(
    "/debug/scenes",
    requireSecret,
    audit("/debug/scenes"),
    async (req: Request, res: Response) => {
      const script_id = String(req.query.script_id || "").trim();
      if (!script_id) {
        return res.status(400).json({ error: "missing_script_id" });
      }

      let script = mem.scripts.get(script_id);
      const row = loadScriptFromDb(script_id);

      if (!script && row) {
        let scenes: Scene[] = [];
        if (row.scenes_json) {
          try {
            scenes = JSON.parse(row.scenes_json) as Scene[];
          } catch (e) {
            console.error("[scripts] failed to parse scenes_json from DB", {
              id: script_id,
              error: (e as any)?.message || e,
            });
          }
        }

        script = {
          id: row.id,
          title: row.title || "Sides",
          scenes,
          voices: {},
        };

        mem.scripts.set(script_id, script);
      }

      if (!script) {
        return res.status(404).json({ error: "not_found" });
      }

      return res.json({ script_id, scenes: script.scenes });
    }
  );

  app.post(
    "/debug/stt",
    requireSecret,
    audit("/debug/stt"),
    (req: Request, res: Response) => {
      try {
        const body = (req.body || {}) as any;
        const script_id =
          typeof body.script_id === "string" ? body.script_id.trim() : "";
        const scene_id =
          typeof body.scene_id === "string" ? body.scene_id.trim() : "";
        const line_id =
          typeof body.line_id === "string" ? body.line_id.trim() : "";
        const text = typeof body.text === "string" ? body.text : "";
        const audio_ms =
          typeof body.audio_ms === "number" && Number.isFinite(body.audio_ms)
            ? body.audio_ms
            : null;

        // For now, pretend STT heard exactly the provided text, or a stub.
        const transcript = text.trim() || "stub transcript";

        return res.json({
          ok: true,
          script_id,
          scene_id,
          line_id,
          transcript,
          confidence: 0.9,
          received_ms: audio_ms,
          decided_at: Date.now(),
        });
      } catch (err) {
        console.error("[debug/stt] error:", err);
        return res.status(500).json({ ok: false, error: "stt_stub_failed" });
      }
    }
  );

  app.post("/debug/set_voice", requireSecret, audit("/debug/set_voice"), (req: Request, res: Response) => {
    const script_id = String((req.body as any)?.script_id || "");
    const voice_map = (req.body as any)?.voice_map || {};
    const s = mem.scripts.get(script_id);
    if (!s) return res.status(404).json({ error: "not found" });
    Object.assign(s.voices, voice_map);
    res.json({ ok: true });
  });

  // REAL: Render partner-only reader MP3 with OpenAI
  app.post("/debug/render", requireSecret, renderLimiter, audit("/debug/render"), async (req: Request, res: Response) => {
    const script_id = String((req.body as any)?.script_id || "");
    const myRole = String((req.body as any)?.my_role || "").toUpperCase();
    const paceMs = Number((req.body as any)?.pace_ms || 0);
    const s = mem.scripts.get(script_id);
    if (!s) return res.status(404).json({ error: "script not found" });
    if (!OPENAI_API_KEY) return res.status(500).json({ error: "OPENAI_API_KEY not set" });

    const rid = genId("rnd");
    const job: RenderJob = { status: "queued", accounted: false };
    mem.renders.set(rid, job);

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

        job.status = "complete";
        job.url = `/api/assets/${rid}`;
      } catch (e: any) {
        const msg = e?.message || String(e);
        job.status = "error";
        job.err = msg;
      }
    })();

    res.json({ render_id: rid, status: "queued" });
  });

  app.get("/debug/render_status", requireSecret, audit("/debug/render_status"), (req: Request, res: Response) => {
    const render_id = String(req.query.render_id || "");

    // DEBUG: see if this route is being hit and what cookies we have
    console.log("[debug] /debug/render_status request:", {
      render_id,
      cookies: (req as any).cookies || null,
      hasSidCookie: Boolean((req as any).cookies?.ob_sid),
    });

    const job = mem.renders.get(render_id);
    if (!job) {
      return res.status(404).json({ error: "not found" });
    }

    console.log(
      "[debug] fallback render_status hit: rid=%s status=%s accounted=%s",
      render_id,
      job.status,
      (job as any).accounted
    );

    // When a render first reaches "complete", account for it exactly once.
    if (job.status === "complete" && !job.accounted) {
      try {
        console.log("[credits] render complete: accounting usage; rid=%s", render_id);
        noteRenderComplete(req);
        job.accounted = true;
      } catch (err) {
        console.error("[credits] noteRenderComplete failed:", err);
      }
    }

    // Return a minimal, stable shape
    res.json({
      status: job.status,
      url: job.url,
      err: job.err,
    });
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
