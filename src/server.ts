import "dotenv/config";
import express, { Request, Response } from "express";
import cors from "cors";
import path from "path";
import * as fs from "fs";
import multer from "multer";
import { createRequire } from "module";
import cookieParser from "cookie-parser";
import cookieSession from "cookie-session";
import Stripe from "stripe";
import authRouter, { getPasskeySession, noteRenderComplete, ensureSid } from "./routes/auth";
import db, { ensureSchema, dbGet, dbAll, dbRun, USING_POSTGRES } from "./lib/db";
import { addUserCredits, getAvailableCredits } from "./lib/credits";
import { isSttEnabled, transcribeChunk } from "./lib/stt";
import { makeAuditMiddleware } from "./lib/audit";
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

function stripDataUrlPrefix(data: string): { base64: string; mimeFromHeader?: string } {
  const trimmed = data.trim();
  if (!trimmed.startsWith("data:")) {
    return { base64: trimmed };
  }

  const commaIndex = trimmed.indexOf(",");
  if (commaIndex === -1) {
    // Malformed data URL; just return as-is
    return { base64: trimmed };
  }

  const header = trimmed.slice(5, commaIndex); // between "data:" and ","
  // header example: "audio/webm;codecs=opus;base64"
  const parts = header.split(";");
  const mimePart = parts[0]?.trim();
  const mimeFromHeader = mimePart && mimePart.length > 0 ? mimePart : undefined;

  const base64 = trimmed.slice(commaIndex + 1);
  return { base64, mimeFromHeader };
}

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

const audit = makeAuditMiddleware();
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
  const q = typeof req.query.secret === "string" ? req.query.secret.trim() : undefined;
  return h || c || q || undefined;
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
const ASSETS_DIR = path.join(process.cwd(), "assets");
if (!fs.existsSync(ASSETS_DIR)) fs.mkdirSync(ASSETS_DIR, { recursive: true });
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

function getUserIdForRequest(req: Request): string | null {
  try {
    const { userId } = getPasskeySession(req as any);
    if (userId && typeof userId === "string" && userId.trim()) {
      return userId.trim();
    }
  } catch (e) {
    console.warn("[auth] getUserIdForRequest: error getting session", (e as any)?.message || e);
  }
  return null;
}

// Helper that ensures anon userId exists for script uploads
function getEffectiveUserId(req: Request): string | null {
  try {
    const { passkeyLoggedIn, userId } = getPasskeySession(req as any);

    // If passkey user, return it
    if (passkeyLoggedIn && userId) {
      return userId;
    }

    // Check if anon is allowed (ENFORCE_AUTH_GATE not set or false)
    const ENFORCE_AUTH_GATE = /^true$/i.test(process.env.ENFORCE_AUTH_GATE || "");
    if (!ENFORCE_AUTH_GATE) {
      // Ensure session.sid exists
      ensureSid(req, null as any);

      // Get session userId (should be anon:<sid> from ensureSessionDefaults)
      const sess = (req as any).session;
      if (sess?.userId) {
        return sess.userId;
      }
    }
  } catch (e) {
    console.warn("[auth] getEffectiveUserId: error getting session", (e as any)?.message || e);
  }
  return null;
}

async function persistScriptToDb(
  id: string,
  userId: string,
  title: string,
  scenes: Scene[]
): Promise<void> {
  try {
    const cleanId = (id || "").trim();
    if (!cleanId) return;

    const cleanTitle = (title || "Sides").trim();
    const safeScenes = Array.isArray(scenes) ? scenes : [];
    const scenesJson = JSON.stringify(safeScenes);
    const sceneCount = safeScenes.length;

    // Check if script exists
    const existing = await dbGet<{ id: string }>(
      "SELECT id FROM scripts WHERE id = ?",
      [cleanId]
    );

    if (existing) {
      // Update existing script
      await dbRun(
        "UPDATE scripts SET user_id = ?, title = ?, scene_count = ?, scenes_json = ? WHERE id = ?",
        [userId, cleanTitle, sceneCount, scenesJson, cleanId]
      );
    } else {
      // Insert new script
      await dbRun(
        "INSERT INTO scripts (id, user_id, title, scene_count, scenes_json) VALUES (?, ?, ?, ?, ?)",
        [cleanId, userId, cleanTitle, sceneCount, scenesJson]
      );
    }

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

async function loadScriptFromDb(id: string, userId: string): Promise<ScriptRow | null> {
  if (!id || !id.trim() || !userId || !userId.trim()) return null;
  try {
    const row = await dbGet<ScriptRow>(
      "SELECT id, user_id, title, scene_count, scenes_json, created_at, updated_at FROM scripts WHERE id = ? AND user_id = ?",
      [id.trim(), userId.trim()]
    );
    return row ?? null;
  } catch (e) {
    console.error("[scripts] failed to load script from DB", {
      id,
      userId,
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

// 2) Voices probe for UI (curated list; UI will accept any entries)
app.get("/debug/voices_probe", requireSecret, (_req: Request, res: Response) => {
  res.json({
    ok: true,
    voices: ["alloy", "ash", "ballad", "coral", "echo", "fable", "onyx", "nova", "sage", "shimmer", "verse"],
  });
});

// 2.5) Admin scripts diagnostics
app.get("/debug/admin_scripts_diag", requireSecret, async (req: Request, res: Response) => {
  try {
    const userId = getUserIdForRequest(req);

    // Get script count by user
    const byUserRows = await dbAll<{ user_id: string; count: number }>(
      "SELECT user_id, COUNT(*) as count FROM scripts GROUP BY user_id"
    );
    const by_user = byUserRows.map((row) => ({
      user_id: row.user_id,
      count: typeof row.count === "number" ? row.count : 0,
    }));

    // Get recent scripts
    const orderClause = USING_POSTGRES
      ? "ORDER BY updated_at DESC"
      : "ORDER BY datetime(updated_at) DESC";

    const recentRows = await dbAll<{ id: string; user_id: string; title: string; updated_at: string }>(
      `SELECT id, user_id, title, updated_at FROM scripts ${orderClause} LIMIT 25`
    );
    const recent = recentRows.map((row) => ({
      id: row.id,
      user_id: row.user_id,
      title: row.title,
      updated_at: row.updated_at,
    }));

    res.json({
      using_postgres: USING_POSTGRES,
      current_user_id: userId,
      by_user,
      recent,
    });
  } catch (err) {
    console.error("[debug/admin_scripts_diag] failed", err);
    res.status(500).json({ error: "diagnostics_failed" });
  }
});

// 2.6) Admin merge scripts between users
app.post("/debug/admin_merge_scripts", requireSecret, express.json(), async (req: Request, res: Response) => {
  try {
    const from_user_id = String(req.body?.from_user_id || "").trim();
    const to_user_id = String(req.body?.to_user_id || "").trim();
    const dry_run = Boolean(req.body?.dry_run);

    // Validate
    if (!from_user_id || !to_user_id) {
      return res.status(400).json({ error: "from_user_id and to_user_id are required" });
    }
    if (from_user_id === to_user_id) {
      return res.status(400).json({ error: "from_user_id and to_user_id must be different" });
    }

    // Count scripts before
    const countRow = await dbGet<{ n: number }>(
      "SELECT COUNT(*) AS n FROM scripts WHERE user_id = ?",
      [from_user_id]
    );
    const scripts_before = countRow?.n ?? 0;

    let scripts_moved = 0;

    if (!dry_run) {
      // Perform the merge
      const result = await dbRun(
        "UPDATE scripts SET user_id = ? WHERE user_id = ?",
        [to_user_id, from_user_id]
      );
      scripts_moved = result.changes ?? 0;
    } else {
      // Dry run: scripts_moved would be the same as scripts_before
      scripts_moved = scripts_before;
    }

    res.json({
      ok: true,
      using_postgres: USING_POSTGRES,
      from_user_id,
      to_user_id,
      scripts_before,
      scripts_moved,
    });
  } catch (err) {
    console.error("[debug/admin_merge_scripts] failed", err);
    res.status(500).json({ error: "merge_failed" });
  }
});

// 2.7) Admin orphan scripts diagnostics
app.get("/debug/admin_orphan_scripts", requireSecret, async (req: Request, res: Response) => {
  try {
    // Count orphan scripts (user_id IS NULL OR user_id = '')
    const countRow = await dbGet<{ n: number }>(
      "SELECT COUNT(*) AS n FROM scripts WHERE user_id IS NULL OR user_id = ''"
    );
    const orphan_count = countRow?.n ?? 0;

    // Get recent orphan scripts
    const orderClause = USING_POSTGRES
      ? "ORDER BY updated_at DESC"
      : "ORDER BY datetime(updated_at) DESC";

    const recentRows = await dbAll<{ id: string; user_id: string | null; title: string; updated_at: string }>(
      `SELECT id, user_id, title, updated_at FROM scripts WHERE user_id IS NULL OR user_id = '' ${orderClause} LIMIT 25`
    );
    const recent = recentRows.map((row) => ({
      id: row.id,
      user_id: row.user_id,
      title: row.title,
      updated_at: row.updated_at,
    }));

    res.json({
      ok: true,
      orphan_count,
      recent,
    });
  } catch (err) {
    console.error("[debug/admin_orphan_scripts] failed", err);
    res.status(500).json({ error: "diagnostics_failed" });
  }
});

// 3) Single-line TTS for Rehearse/Diagnostics
app.post("/debug/tts_line", requireSecret, async (req: Request, res: Response) => {
  try {
    if (!OPENAI_API_KEY) return res.status(500).json({ error: "OPENAI_API_KEY not set" });
    const VOICES = ["alloy", "ash", "ballad", "coral", "echo", "fable", "onyx", "nova", "sage", "shimmer", "verse"];
    const LEGACY_VOICES = new Set(["alloy", "echo", "fable", "onyx", "nova", "shimmer"]);
    const voiceRaw = String((req.body as any)?.voice || "alloy").trim();
    const voice = VOICES.includes(voiceRaw) ? voiceRaw : "alloy";
    const modelRaw = String((req.body as any)?.model || "tts-1");
    const allowedModels = new Set(["tts-1", "tts-1-hd", "gpt-4o-mini-tts"]);
    let model = allowedModels.has(modelRaw) ? modelRaw : "tts-1";
    if (VOICES.includes(voice) && !LEGACY_VOICES.has(voice)) {
      model = "gpt-4o-mini-tts";
    }
    const text = String((req.body as any)?.text || "").trim();
    if (!text) return res.status(400).json({ error: "missing text" });

    const buf = await openaiTts(text, voice, model);
    const id = genId("tts");
    mem.assets.set(id, buf);
    return res.json({ ok: true, url: `/api/assets/${id}` });
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
  audit("/debug/stt_transcribe_chunk"),
  express.json({ limit: "2mb" }),
  async (req: Request, res: Response) => {
    try {
      const body = (req as any).body || {};
      const rawAudioB64 = typeof body.audio_b64 === "string" ? body.audio_b64.trim() : "";

      if (!rawAudioB64) {
        return res.status(400).json({
          ok: false,
          error: "missing_audio",
        });
      }

      const { base64: cleanBase64, mimeFromHeader } = stripDataUrlPrefix(rawAudioB64);

      const mimeRaw =
        typeof body.mime === "string" && body.mime.trim() ? (body.mime as string) : mimeFromHeader;

      const mime = mimeRaw && mimeRaw.trim().length > 0 ? mimeRaw.trim() : "audio/webm";

      const audioBuffer = Buffer.from(cleanBase64, "base64");
      if (!audioBuffer || audioBuffer.length === 0) {
        return res.status(400).json({
          ok: false,
          error: "invalid_audio",
        });
      }

      console.log("[stt] /stt_transcribe_chunk request:", {
        rawMime: body.mime || null,
        headerMime: mimeFromHeader || null,
        effectiveMime: mime,
        hasDataUrlPrefix: rawAudioB64.startsWith("data:"),
        base64Length: cleanBase64.length,
        bytes: audioBuffer.length,
      });

      if (!isSttEnabled()) {
        return res.status(200).json({
          ok: false,
          error: "stt_disabled",
        });
      }

      const script_id =
        typeof body.script_id === "string" ? body.script_id.trim() : "";
      const scene_id =
        typeof body.scene_id === "string" ? body.scene_id.trim() : "";
      const line_id =
        typeof body.line_id === "string" ? body.line_id.trim() : "";
      void script_id;
      void scene_id;
      void line_id;

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
    } catch (err: any) {
      console.error("[stt] transcribe_chunk error:", err);
      const code =
        err?.code ||
        err?.error?.code ||
        err?.status ||
        "stt_failed";
      const message =
        err?.error?.message || err?.message || "Audio file might be corrupted or unsupported";

      res.json({
        ok: false,
        error: code,
        message,
      });
    }
  }
);
/* ---------------------------------------------------------- */

app.get("/api/my_scripts", async (req: Request, res: Response) => {
  try {
    const userId = getUserIdForRequest(req);
    if (!userId) {
      return res.status(401).json({ error: "unauthorized" });
    }

    // Dev-only override: ?all=1 with SHARED_SECRET shows all users' scripts
    const sharedSecret = getSharedSecret();
    const showAll = String(req.query.all || "") === "1" && sharedSecret && req.headers["x-shared-secret"] === sharedSecret;

    const orderClause = USING_POSTGRES
      ? "ORDER BY updated_at DESC"
      : "ORDER BY datetime(updated_at) DESC";

    let query: string;
    let params: any[];

    if (showAll) {
      query = `SELECT id, user_id, title, scene_count, updated_at FROM scripts WHERE is_deleted = 0 ${orderClause}`;
      params = [];
    } else {
      query = `SELECT id, user_id, title, scene_count, updated_at FROM scripts WHERE user_id = ? AND is_deleted = 0 ${orderClause}`;
      params = [userId];
    }

    const rows = await dbAll<{ id: string; user_id: string; title: string; scene_count: number; updated_at: string }>(
      query,
      params
    );

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
      showAll,
      count: scripts.length,
    });

    res.json({ scripts });
  } catch (e: any) {
    console.error("[scripts] /api/my_scripts failed:", e?.message || e);
    res.status(500).json({ error: "failed_to_list_scripts" });
  }
});

app.get("/api/scripts/:id", async (req: Request, res: Response) => {
  const id = (req.params.id || "").trim();
  if (!id) {
    return res.status(400).json({ error: "missing_id" });
  }

  const userId = getUserIdForRequest(req);
  if (!userId) {
    return res.status(401).json({ error: "unauthorized" });
  }

  const cacheKey = `${userId}:${id}`;
  const row = await loadScriptFromDb(id, userId);
  let script = mem.scripts.get(cacheKey);

  if (!script && row) {
    let scenes: Scene[] = [];
    if (row.scenes_json) {
      try {
        scenes = JSON.parse(row.scenes_json) as Scene[];
      } catch (e) {
        console.error("[scripts] failed to parse scenes_json from DB", {
          id,
          userId,
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

    mem.scripts.set(cacheKey, script);
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
    if (!userId) {
      return res.status(401).json({ error: "unauthorized" });
    }

    const id = (req.params.id || "").trim();
    if (!id) {
      return res.status(400).json({ error: "missing_script_id" });
    }

    const body = req.body || {};
    const rawTitle =
      typeof body.title === "string" ? (body.title as string).trim() : "";
    const scenesRaw = body.scenes;
    const scenes = Array.isArray(scenesRaw) ? (scenesRaw as Scene[]) : [];

    // Check if script exists with a different user_id
    const existingRow = await dbGet<{ id: string; user_id: string; title: string }>(
      "SELECT id, user_id, title FROM scripts WHERE id = ?",
      [id]
    );

    if (existingRow && existingRow.user_id !== userId) {
      return res.status(403).json({ error: "not_owner" });
    }

    const existingTitle = existingRow?.title || "";
    const finalTitle = rawTitle || existingTitle || "Sides";

    // Persist new title + scenes to DB
    await persistScriptToDb(id, userId, finalTitle, scenes);

    return res.json({ ok: true });
  } catch (e: any) {
    console.error("[scripts] POST /api/scripts/:id/save failed:", e?.message || e);
    return res.status(500).json({ error: "failed_to_save_script" });
  }
});

app.delete("/api/scripts/:id", async (req: Request, res: Response) => {
  try {
    const userId = getUserIdForRequest(req);
    if (!userId) {
      return res.status(401).json({ error: "unauthorized" });
    }

    const id = (req.params.id || "").trim();
    if (!id) {
      return res.status(400).json({ error: "missing_script_id" });
    }

    const result = await dbRun("DELETE FROM scripts WHERE id = ? AND user_id = ?", [id, userId]);

    if ((result.changes || 0) === 0) {
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
    async (req: Request, res: Response) => {
      const userId = getEffectiveUserId(req);
      if (!userId) {
        return res.status(401).json({ error: "unauthorized" });
      }

      const title = String(req.body?.title || "Script");
      const text = String(req.body?.text || "");
      const id = genId("scr");
      const scenes = parseTextToScenes(title, text);
      const speakers = uniqueSpeakers(scenes[0]);

      mem.scripts.set(id, { id, title, scenes, voices: {} });
      await persistScriptToDb(id, userId, title, scenes);

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
      const userId = getEffectiveUserId(req);
      if (!userId) {
        return res.status(401).json({ error: "unauthorized" });
      }

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
          await persistScriptToDb(id, userId, title, scenes);
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
        await persistScriptToDb(id, userId, title, scenes);
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
        await persistScriptToDb(id, userId, title, scenes);
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
      const userId = getUserIdForRequest(req);
      if (!userId) {
        return res.status(401).json({ error: "unauthorized" });
      }

      const script_id = String(req.query.script_id || "").trim();
      if (!script_id) {
        return res.status(400).json({ error: "missing_script_id" });
      }

      const cacheKey = `${userId}:${script_id}`;
      let script = mem.scripts.get(cacheKey);
      const row = await loadScriptFromDb(script_id, userId);

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

        mem.scripts.set(cacheKey, script);
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

  app.get("/debug/render_status", requireSecret, audit("/debug/render_status"), async (req: Request, res: Response) => {
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
        await noteRenderComplete(req);
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

// Always-on assets route (in-memory first, then disk)
app.get("/api/assets/:render_id", (req: Request, res: Response) => {
  const rid = String(req.params.render_id || "");
  const range = req.headers.range;

  const sendBuffer = (buf: Buffer) => {
    const total = buf.length;
    if (range && range.startsWith("bytes=")) {
      const parts = range.replace(/bytes=/, "").split("-");
      const start = Number(parts[0]) || 0;
      const end = parts[1] ? Number(parts[1]) : total - 1;
      if (start >= total || start < 0 || start > end) {
        res.status(416).set("Content-Range", `bytes */${total}`).end();
        return;
      }
      const clampedEnd = Math.min(end, total - 1);
      const chunk = buf.subarray(start, clampedEnd + 1);
      res.status(206);
      res.setHeader("Content-Range", `bytes ${start}-${clampedEnd}/${total}`);
      res.setHeader("Accept-Ranges", "bytes");
      res.setHeader("Content-Length", chunk.length);
      res.setHeader("Content-Type", "audio/mpeg");
      res.setHeader("Cache-Control", "no-store");
      return res.end(chunk);
    }
    res.setHeader("Content-Type", "audio/mpeg");
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("Content-Length", total);
    return res.end(buf);
  };

  const inMem = mem.assets.get(rid);
  if (inMem) return sendBuffer(inMem);

  const filePath = path.join(ASSETS_DIR, `${rid}.mp3`);
  if (fs.existsSync(filePath)) {
    const stat = fs.statSync(filePath);
    const total = stat.size;
    res.setHeader("Content-Type", "audio/mpeg");
    res.setHeader("Cache-Control", "no-store");
    if (range && range.startsWith("bytes=")) {
      const parts = range.replace(/bytes=/, "").split("-");
      const start = Number(parts[0]) || 0;
      const end = parts[1] ? Number(parts[1]) : total - 1;
      if (start >= total || start < 0 || start > end) {
        res.status(416).set("Content-Range", `bytes */${total}`).end();
        return;
      }
      const clampedEnd = Math.min(end, total - 1);
      res.status(206);
      res.setHeader("Content-Range", `bytes ${start}-${clampedEnd}/${total}`);
      res.setHeader("Accept-Ranges", "bytes");
      res.setHeader("Content-Length", clampedEnd - start + 1);
      return fs.createReadStream(filePath, { start, end: clampedEnd }).pipe(res);
    }
    res.setHeader("Content-Length", total);
    return fs.createReadStream(filePath).pipe(res);
  }

  return res.status(404).json({ error: "asset not found" });
});

// Ensure database schema before starting server
await ensureSchema();

await tryMountProjectHttpRoutes().then((mounted) => { if (!mounted) mountFallbackDebugRoutes(); });

// Start
app.listen(PORT, () => {
  console.log(`OffBook MVP listening on http://localhost:${PORT}`);
  const shared = getSharedSecret();
  if (shared) console.log(`Debug routes require header X-Shared-Secret: ${shared}`);
  console.log("UI tip: open /app-tabs.html?secret=" + (shared || "(none)"));
});
