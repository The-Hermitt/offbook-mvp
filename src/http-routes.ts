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
import { generateReaderMp3, ttsProvider, type RenderResult } from "./lib/tts";
import { isSttEnabled, transcribeChunk } from "./lib/stt";
import { makeAuditMiddleware } from "./lib/audit";
import { makeRateLimiters } from "./middleware/rateLimit";
import { getPasskeySession, ensureSid, noteRenderComplete } from "./routes/auth";
import { r2Enabled, r2PutFile, r2GetObjectStream, r2Head, r2Delete } from "./lib/r2";
import { addUserCredits, getAvailableCredits, getUserCredits } from "./lib/credits";
import { getUserBilling, upsertUserBilling } from "./lib/db";
import Stripe from "stripe";

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

// ---------- Stripe client ----------
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || "";
const stripe = STRIPE_SECRET_KEY ? new Stripe(STRIPE_SECRET_KEY) : null;

// ---------- Billing helper ----------
async function recordBillingEventOnce(
  eventId: string,
  eventType: string,
  userId: string
): Promise<boolean> {
  try {
    if (USING_POSTGRES) {
      const result = await dbRun(
        "INSERT INTO billing_events (event_id, event_type, user_id) VALUES ($1, $2, $3) ON CONFLICT (event_id) DO NOTHING",
        [eventId, eventType, userId]
      );
      return (result.rowCount || 0) > 0;
    } else {
      const result = await dbRun(
        "INSERT OR IGNORE INTO billing_events (event_id, event_type, user_id) VALUES (?, ?, ?)",
        [eventId, eventType, userId]
      );
      return (result.changes || 0) > 0;
    }
  } catch (err) {
    console.error("[billing] failed to record billing event", err);
    throw err;
  }
}

// ---------- In-memory state ----------
const scripts = new Map<string, Script>();
const renders = new Map<string, {
  status: "queued" | "working" | "complete" | "error";
  file?: string;
  err?: string;
  accounted?: boolean;
  chargedChars?: number;
  chargedCredits?: number;
  scriptId?: string;
  sceneId?: string;
  startedAt?: number;
  updatedAt?: number;
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

// ---------- LLM Import Cleanup (auto, env-gated) ----------

const SCENE_HEADING_RE = /\b(?:INT\.|EXT\.|INT\/EXT\.|I\/E\.)\s/i;
const TRANSITION_RE = /\b(?:CUT TO|FADE IN|FADE OUT|DISSOLVE TO|SMASH CUT|MATCH CUT)\b/i;
const SCENE_KEYWORD_RE = /\bSCENE\b/;
const PDF_GIBBERISH_TOKENS = ["endobj", "xref", "obj", "stream", "/type", "/font", "/length", "/filter", "flatedecode"];
const EMBEDDED_SPEAKER_RE = /\b[A-Z][A-Z0-9 ]{1,24}:\s/;

function shouldUseImportCleanup(
  extractedText: string,
  scenes: Scene[]
): { use: boolean; reason: string; metrics: any } {
  if (!process.env.IMPORT_CLEANUP_ENABLED || process.env.IMPORT_CLEANUP_ENABLED !== "1") {
    return { use: false, reason: "disabled", metrics: {} };
  }
  if (!process.env.OPENAI_API_KEY || !process.env.IMPORT_CLEANUP_MODEL) {
    return { use: false, reason: "missing_env", metrics: {} };
  }

  // Force mode for debugging
  if (process.env.IMPORT_CLEANUP_FORCE === "1") {
    return { use: true, reason: "force", metrics: {} };
  }

  const allLines = scenes.flatMap(sc => Array.isArray(sc.lines) ? sc.lines : []);
  const totalLines = allLines.length;

  // Too few lines — parse probably failed
  if (scenes.length === 0 || totalLines < 4) {
    return { use: true, reason: "too_few_lines", metrics: { scenes: scenes.length, totalLines } };
  }

  // Check line contents for quality problems
  let headingLeaks = 0;
  let actionLeaks = 0;
  let speakerMixes = 0;

  for (const ln of allLines) {
    const t = ln.text || "";
    if (SCENE_HEADING_RE.test(t) || TRANSITION_RE.test(t) || SCENE_KEYWORD_RE.test(t)) {
      headingLeaks++;
    }
    // Long multi-sentence text with description cues
    if (t.length > 240) {
      const sentenceCount = (t.match(/[.!?]\s+[A-Z]/g) || []).length + 1;
      if (sentenceCount >= 3) actionLeaks++;
    }
    // Location/time description cues in line text
    if (/\s-\s/.test(t) && /\b(?:DAY|NIGHT|MORNING|EVENING|LATER|CONTINUOUS)\b/i.test(t)) {
      headingLeaks++;
    }
    // Embedded speaker label in dialogue text
    if (EMBEDDED_SPEAKER_RE.test(t)) {
      speakerMixes++;
    }
  }

  if (headingLeaks > 0) {
    return { use: true, reason: "heading_leaks", metrics: { headingLeaks, totalLines } };
  }
  if (actionLeaks > 0) {
    return { use: true, reason: "action_leaks", metrics: { actionLeaks, totalLines } };
  }
  if (speakerMixes >= 2) {
    return { use: true, reason: "speaker_mixing", metrics: { speakerMixes, totalLines } };
  }

  // PDF-object gibberish in raw text
  const lower = extractedText.toLowerCase();
  let gibberishHits = 0;
  for (const tok of PDF_GIBBERISH_TOKENS) {
    if (lower.includes(tok)) gibberishHits++;
  }
  if (gibberishHits >= 3) {
    return { use: true, reason: "pdf_gibberish", metrics: { gibberishHits } };
  }

  return { use: false, reason: "quality_ok", metrics: { totalLines, headingLeaks, actionLeaks, speakerMixes, gibberishHits } };
}

async function llmCleanupToScenes(
  rawText: string,
  title: string
): Promise<{ scenes: Scene[] } | null> {
  const apiKey = process.env.OPENAI_API_KEY;
  const model = process.env.IMPORT_CLEANUP_MODEL;
  if (!apiKey || !model) return null;

  const systemPrompt = [
    "You are a screenplay dialogue extractor. Given raw script text (possibly from OCR), extract ONLY spoken dialogue lines as structured JSON.",
    "Rules:",
    "- Keep ONLY spoken dialogue lines with their speaker names.",
    "- Remove ALL scene headings (INT./EXT./SCENE), action/description paragraphs, transitions (CUT TO, FADE IN, DISSOLVE TO, etc.), parentheticals, page numbers, headers, and footers.",
    "- Merge broken dialogue lines that clearly belong to the same speaker's speech.",
    "- Preserve the original order of dialogue.",
    "- DO NOT invent or add any dialogue not present in the source text.",
    "- If a speaker cannot be determined, use \"UNKNOWN\".",
    "- Prefer speaker names in ALL CAPS.",
    "- Group lines into scenes. If scene breaks are unclear, put all lines in one scene titled \"Scene 1\".",
  ].join("\n");

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 25_000);
  const t0 = Date.now();

  try {
    const resp = await fetch("https://api.openai.com/v1/responses", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model,
        input: [
          { role: "system", content: systemPrompt },
          { role: "user", content: `TITLE: ${title}\n\nSCRIPT:\n${rawText}` },
        ],
        temperature: 0,
        max_output_tokens: 12000,
        text: {
          format: {
            type: "json_schema",
            name: "offbook_dialogue_extract",
            strict: true,
            schema: {
              type: "object",
              additionalProperties: false,
              properties: {
                scenes: {
                  type: "array",
                  items: {
                    type: "object",
                    additionalProperties: false,
                    properties: {
                      title: { type: "string" },
                      lines: {
                        type: "array",
                        items: {
                          type: "object",
                          additionalProperties: false,
                          properties: {
                            speaker: { type: "string" },
                            text: { type: "string" },
                          },
                          required: ["speaker", "text"],
                        },
                      },
                    },
                    required: ["title", "lines"],
                  },
                },
              },
              required: ["scenes"],
            },
          },
        },
      }),
      signal: controller.signal,
    });

    if (!resp.ok) {
      const body = await resp.text().catch(() => "");
      console.error("[import-cleanup] API error status=%d body=%s", resp.status, body.slice(0, 300));
      return null;
    }

    const json: any = await resp.json();

    // Extract text from response.output[] -> message items -> output_text content
    let outputText = "";
    if (Array.isArray(json.output)) {
      for (const item of json.output) {
        if (item.type === "message" && Array.isArray(item.content)) {
          for (const part of item.content) {
            if (part.type === "output_text" && typeof part.text === "string") {
              outputText += part.text;
            }
          }
        }
      }
    }

    if (!outputText) {
      console.error("[import-cleanup] no output_text found in response");
      return null;
    }

    const parsed = JSON.parse(outputText);
    if (!Array.isArray(parsed.scenes)) return null;

    // Validate and build Scene[] with IDs
    const validScenes: Scene[] = [];
    for (const sc of parsed.scenes) {
      if (!Array.isArray(sc.lines)) continue;
      const validLines = sc.lines.filter(
        (ln: any) =>
          typeof ln.speaker === "string" &&
          typeof ln.text === "string" &&
          ln.speaker.trim().length > 0 &&
          ln.text.trim().length > 0
      );
      if (validLines.length > 0) {
        validScenes.push({
          id: crypto.randomUUID(),
          title: typeof sc.title === "string" && sc.title.trim() ? sc.title.trim() : `Scene ${validScenes.length + 1}`,
          lines: validLines,
        });
      }
    }

    if (validScenes.length === 0) return null;

    return { scenes: validScenes };
  } catch (err: any) {
    if (err.name !== "AbortError") {
      console.error("[import-cleanup] error:", err.message || err);
    } else {
      console.error("[import-cleanup] timeout after 25s");
    }
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

// ---------- Parser: supports `NAME: line` and screenplay blocks ----------
function parseScenesFromText(text: string, scriptTitle?: string): Scene[] {
  const debugParse = process.env.DEBUG_PDF_PARSE === "1";
  let inlineCueSplits = 0;
  let continuationAppends = 0;

  const rawLines = text.split(/\r?\n/);

  const isAllCapsWordy = (s: string) =>
    /^[A-Z0-9 ,.'"?!\-:;()]+$/.test(s) &&
    s === s.toUpperCase() &&
    s.replace(/\s+/g, "").length > 3;

  const isSceneHeading = (s: string) => /^\s*(INT\.|EXT\.|SCENE\b)/i.test(s.trim());
  const isLikelyHeaderFooter = (s: string) => /(page \d+|actors access|breakdown services|http|https|www\.)/i.test(s);
  const isOnlyParen = (s: string) => /^\s*\([^)]*\)\s*$/.test(s);
  const colonLine = (s: string) => s.match(/^\s*([A-Z][A-Z0-9 _&'.-]{1,30})\s*:\s*(.*)$/);

  // Helpers for noise removal
  const isNumericOnlyLine = (s: string) => /^\s*\d+(\s+\d+)*\s*$/.test(s);
  const titleUpper = (scriptTitle || "").trim().toUpperCase();
  const isTitleHeaderLine = (s: string) => titleUpper.length > 0 && s.trim().toUpperCase() === titleUpper;
  const isSkippable = (s: string) => isNumericOnlyLine(s) || isTitleHeaderLine(s);

  const stripParens = (s: string) => s.replace(/\([^)]*\)/g, "").replace(/\s{2,}/g, " ").trim();
  const stripInlineSceneHeading = (s: string) => {
    const idx = s.search(/\b(INT\.|EXT\.|SCENE\b|CONTINUOUS\b)/i);
    if (idx > 0) return s.slice(0, idx).replace(/\s+$/, "");
    return s;
  };
  const cleanDialogue = (s: string) => stripInlineSceneHeading(stripParens(s));

  // Standalone speaker cue: SPEAKER on its own line (no colon)
  const isStandaloneSpeaker = (s: string) => {
    const candidate = s.trim();
    if (!/^[A-Z][A-Z0-9 '&.-]{1,29}$/.test(candidate)) return false;
    if (!isAllCapsWordy(candidate)) return false;
    if (isSceneHeading(candidate) || isLikelyHeaderFooter(candidate) || isSkippable(candidate)) return false;
    if (candidate === "CONTINUED" || candidate === "CONT'D" || candidate === "CONT\u2019D") return false;
    return true;
  };

  const inlineCueRegex = /[A-Z][A-Z0-9 _&'.-]{1,25}:/g;
  const lines: string[] = [];
  for (const raw of rawLines) {
    const line = raw.replace(/\t/g, " ");
    const matches = Array.from(line.matchAll(inlineCueRegex));
    if (matches.length > 1) {
      inlineCueSplits += matches.length - 1;
      const firstIdx = matches[0].index ?? 0;
      const prefix = line.slice(0, firstIdx).trimRight();
      if (prefix.trim()) lines.push(prefix);
      for (let i = 0; i < matches.length; i++) {
        const start = matches[i].index ?? 0;
        const end = i + 1 < matches.length ? (matches[i + 1].index ?? line.length) : line.length;
        const piece = line.slice(start, end).trimRight();
        if (piece.trim()) lines.push(piece);
      }
      continue;
    }
    lines.push(line);
  }

  const logDebugCounts = () => {
    if (!debugParse) return;
    console.log("[parseScenes] inlineCueSplits=%d continuationAppends=%d", inlineCueSplits, continuationAppends);
  };

  const scene: Scene = { id: crypto.randomUUID(), title: "Scene 1", lines: [] };

  // IMPORTANT: OCR sometimes produces mixed formats (some NAME: lines + some screenplay blocks).
  // If we return early after Pass 1, we drop the screenplay blocks and can mis-assign continuations.
  // So we run both passes, track which source lines were consumed, then sort by original position.
  type Parsed = { pos: number; speaker: string; text: string };
  const parsed: Parsed[] = [];
  const consumed = new Array(lines.length).fill(false);

  // Pass 1: NAME: dialogue
  let i = 0;
  while (i < lines.length) {
    const startPos = i;
    const s = lines[i].trimRight();
    i++;
    if (!s.trim()) continue;
    if (isSceneHeading(s) || isOnlyParen(s) || isLikelyHeaderFooter(s) || isSkippable(s)) continue;
    const m = colonLine(s);
    if (!m) continue;

    consumed[startPos] = true;
    const speaker = m[1].trim();
    const buf: string[] = [];
    if (m[2].trim()) buf.push(m[2].trim());

    while (i < lines.length) {
      const peekPos = i;
      const peek = lines[i].trimRight();
      const isBlank = !peek.trim();
      const nextIsSpeaker = !!colonLine(peek) || isStandaloneSpeaker(peek);
      const nextIsHeader = isSceneHeading(peek) || isLikelyHeaderFooter(peek) || isSkippable(peek);
      if (isBlank || nextIsSpeaker || nextIsHeader) break;
      if (!isOnlyParen(peek)) {
        buf.push(peek.trim());
        continuationAppends++;
      }
      consumed[peekPos] = true;
      i++;
    }

    const t = cleanDialogue(buf.join(" ").replace(/\s+/g, " ").trim());
    if (t) parsed.push({ pos: startPos, speaker, text: t });
  }

  // Pass 2: screenplay blocks (NAME on its own line; optional parenthetical; dialogue lines)
  i = 0;
  while (i < lines.length) {
    if (consumed[i]) {
      i++;
      continue;
    }
    let line = lines[i].trimRight();
    const startPos = i;
    i++;

    if (!line.trim()) continue;
    if (isSceneHeading(line) || isLikelyHeaderFooter(line) || isSkippable(line)) continue;

    const candidate = line.trim();
    if (isStandaloneSpeaker(candidate)) {
      const speaker = candidate;
      consumed[startPos] = true;
      if (i < lines.length && isOnlyParen(lines[i].trim())) {
        consumed[i] = true;
        i++; // skip parenthetical
      }

      const buf: string[] = [];
      while (i < lines.length) {
        if (consumed[i]) {
          i++;
          continue;
        }
        const peek = lines[i].trimRight();
        const isBlank = !peek.trim();
        const nextIsSpeaker = isStandaloneSpeaker(peek) || !!colonLine(peek);
        const nextIsHeader = isSceneHeading(peek) || isLikelyHeaderFooter(peek) || isSkippable(peek);
        if (isBlank || nextIsSpeaker || nextIsHeader) break;
        if (!isOnlyParen(peek)) buf.push(peek);
        consumed[i] = true;
        i++;
      }
      const t = cleanDialogue(buf.join(" ").replace(/\s+/g, " ").trim());
      if (t) parsed.push({ pos: startPos, speaker, text: t });
    }
  }

  parsed.sort((a, b) => a.pos - b.pos);
  scene.lines = parsed.map(({ speaker, text }) => ({ speaker, text }));

  logDebugCounts();
  return mergeSpeakerAliases([scene]);
}

// Conservative alias merge: single-word speaker -> multi-word speaker when unambiguous
function mergeSpeakerAliases(scenes: Scene[]): Scene[] {
  const counts = new Map<string, number>();
  for (const sc of scenes) {
    for (const ln of sc.lines) {
      counts.set(ln.speaker, (counts.get(ln.speaker) ?? 0) + 1);
    }
  }

  const aliasMap = new Map<string, string>();
  for (const [name] of counts) {
    if (name.includes(" ")) continue; // only remap single-word speakers
    // Find multi-word speakers whose last token matches this single-word speaker
    const matches: string[] = [];
    for (const [other] of counts) {
      if (!other.includes(" ")) continue;
      const lastToken = other.split(/\s+/).pop();
      if (lastToken === name) matches.push(other);
    }
    if (matches.length === 1 && (counts.get(matches[0]) ?? 0) > (counts.get(name) ?? 0)) {
      aliasMap.set(name, matches[0]);
    }
  }

  if (aliasMap.size === 0) return scenes;

  for (const sc of scenes) {
    for (const ln of sc.lines) {
      const mapped = aliasMap.get(ln.speaker);
      if (mapped) ln.speaker = mapped;
    }
  }
  return scenes;
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
  const INCLUDED_CREDITS = 150;

  function getMixdownEnabled(): boolean {
    const v = String(process.env.MIXDOWN_ENABLED || "").trim();
    return !!v && v !== "0" && v.toLowerCase() !== "false";
  }

  // Room diagnosability: capture last mixdown error and event
  let lastMixdownError: any = null;
  let lastMixdownEvent: any = null;
  let lastStemsUploadEvent: any = null;
  let lastStemsUploadError: any = null;

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

  type CreditsState = {
    granted: number;
    used: number;
    periodStart: string;
    periodEnd: string;
  };

  type CreditsStore = {
    stateByOwner: Map<string, CreditsState>;
    renderOwner: Map<string, string>;
    accountedRenders: Set<string>;
  };

  function getPeriodBounds(now: Date = new Date()): { periodStart: string; periodEnd: string } {
    const y = now.getUTCFullYear();
    const m = now.getUTCMonth();
    const periodStart = new Date(Date.UTC(y, m, 1));
    const periodEnd = new Date(Date.UTC(y, m + 1, 1));
    return { periodStart: periodStart.toISOString(), periodEnd: periodEnd.toISOString() };
  }

  function getCreditsStore(): CreditsStore {
    const key = "__debugCreditsStore";
    const localsAny = app.locals as any;
    if (!localsAny[key]) {
      localsAny[key] = {
        stateByOwner: new Map<string, CreditsState>(),
        renderOwner: new Map<string, string>(),
        accountedRenders: new Set<string>(),
      } satisfies CreditsStore;
    }
    return localsAny[key] as CreditsStore;
  }

  function getOwnerKey(req: Request): string {
    const { userId } = getPasskeySession(req as any);
    return userId || "shared";
  }

  function ensureOwnerState(ownerKey: string): CreditsState {
    const store = getCreditsStore();
    const bounds = getPeriodBounds();
    const existing = store.stateByOwner.get(ownerKey);
    if (!existing || existing.periodStart !== bounds.periodStart) {
      const next: CreditsState = {
        granted: 0,
        used: 0,
        periodStart: bounds.periodStart,
        periodEnd: bounds.periodEnd,
      };
      store.stateByOwner.set(ownerKey, next);
      return next;
    }
    return existing;
  }

  function creditsSnapshot(ownerKey: string) {
    const state = ensureOwnerState(ownerKey);
    const included = INCLUDED_CREDITS;
    const granted = state.granted;
    const used = state.used;
    const remaining = included + granted - used;
    return {
      included,
      granted,
      used,
      remaining,
      period_start: state.periodStart,
      period_end: state.periodEnd,
    };
  }

  // GET /debug/whoami - probe for active route file and env info
  debug.get("/whoami", (req: Request, res: Response) => {
    res.json({
      ok: true,
      marker: "credits-gate-v1",
      allow_test_routes: process.env.ALLOW_TEST_ROUTES === "1" && process.env.OFFBOOK_ENV === "staging",
      offbook_env: process.env.OFFBOOK_ENV || null,
      node_env: process.env.NODE_ENV || null,
    });
  });

  // GET /debug/credits - in-memory credits snapshot (DEBUG ONLY - use GET /credits for production)
  // This endpoint is kept for internal testing only. iOS app should use GET /credits instead.
  debug.get("/credits", (req: Request, res: Response) => {
    const ownerKey = getOwnerKey(req);
    const snap = creditsSnapshot(ownerKey);
    res.setHeader("x-credits-remaining", String(snap.remaining));
    res.json(snap);
  });

  // POST /debug/credits/grant?amount=N - adjust granted credits for testing
  debug.post("/credits/grant", (req: Request, res: Response) => {
    const ownerKey = getOwnerKey(req);
    const amountRaw = req.query.amount;
    const amount = typeof amountRaw === "string" ? Number(amountRaw) : Number(amountRaw ?? 0);
    if (!Number.isFinite(amount)) {
      return res.status(400).json({ error: "amount must be a finite number" });
    }
    const state = ensureOwnerState(ownerKey);
    state.granted += amount;
    const snap = creditsSnapshot(ownerKey);
    res.setHeader("x-credits-remaining", String(snap.remaining));
    res.json(snap);
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
    return res.json({
      ok: true,
      mixdownEnabled: getMixdownEnabled(),
      env_MIXDOWN_ENABLED: process.env.MIXDOWN_ENABLED ?? null,
      lastMixdownEvent,
      lastMixdownError
    });
  });

  // GET /debug/last_stems_upload - Room diagnosability
  debug.get("/last_stems_upload", audit("/debug/last_stems_upload"), (req: Request, res: Response) => {
    return res.json({ ok: true, lastStemsUploadEvent, lastStemsUploadError });
  });

  // GET /debug/stems_check?take_id=...
  debug.get("/stems_check", requireUser, audit("/debug/stems_check"), async (req: Request, res: Response) => {
    try {
      const user = (req as any).user || res.locals.user;
      if (!user || !user.id) {
        return res.status(401).json({ error: "Unauthorized" });
      }

      const takeId = String(req.query?.take_id || "");
      if (!takeId) {
        return res.status(400).json({ error: "take_id required" });
      }

      const userId = String(user.id);
      const r2IsEnabled = r2Enabled();

      if (!r2IsEnabled) {
        return res.json({
          ok: true,
          takeId,
          userId,
          r2Enabled: false,
          found: false,
          message: "R2 not enabled"
        });
      }

      // Try all possible extensions (same list as mixed_file)
      const stemExts = [".m4a", ".webm", ".mp3", ".wav", ".ogg", ".mp4"];
      const triedExts: string[] = [];

      for (const ext of stemExts) {
        triedExts.push(ext);
        const micKey = `stems/${userId}/${takeId}-mic${ext}`;
        const readerKey = `stems/${userId}/${takeId}-reader${ext}`;

        try {
          const micHead = await r2Head(micKey);
          const readerHead = await r2Head(readerKey);

          if (micHead && readerHead) {
            // Found matching pair
            return res.json({
              ok: true,
              takeId,
              userId,
              r2Enabled: true,
              found: true,
              micKey,
              readerKey,
              triedExts
            });
          }
        } catch (err) {
          // Continue trying other extensions
          continue;
        }
      }

      // No matching pair found
      return res.json({
        ok: true,
        takeId,
        userId,
        r2Enabled: true,
        found: false,
        triedExts
      });
    } catch (err) {
      console.error("Error in GET /debug/stems_check", err);
      return res.status(500).json({ error: "internal_error" });
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
    const rawText = String(text);
    const rawTitle = String(title);

    // First: run existing parser
    let scenes = parseScenesFromText(rawText, rawTitle);

    // Auto LLM cleanup if quality is poor
    let cleanupUsed = false;
    let cleanupReason = "";
    let cleanupOutLines = 0;
    const qualityCheck = shouldUseImportCleanup(rawText, scenes);
    if (qualityCheck.use) {
      const t0 = Date.now();
      const result = await llmCleanupToScenes(rawText, rawTitle);
      const ms = Date.now() - t0;
      const model = process.env.IMPORT_CLEANUP_MODEL || "?";
      const outLines = result ? result.scenes.flatMap(s => s.lines).length : 0;
      const ok = !!(result && outLines > 0);
      console.log(
        "[import-cleanup] used=%s ok=%s reason=%s model=%s inChars=%d outScenes=%d outLines=%d ms=%d",
        true, ok, qualityCheck.reason, model, rawText.length,
        result ? result.scenes.length : 0, outLines, ms
      );
      if (ok) {
        scenes = result!.scenes;
        cleanupUsed = true;
        cleanupReason = qualityCheck.reason;
        cleanupOutLines = outLines;
      }
    }

    const script: Script = { id, title: rawTitle, text: rawText, scenes };

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
      ...(cleanupUsed ? { cleanup_used: true, cleanup_reason: cleanupReason, cleanup_out_lines: cleanupOutLines } : {}),
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
        let cleanupUsed = false;
        let cleanupReason = "";
        let cleanupOutLines = 0;

        if (textLen >= 40) {
          const parsed = parseScenesFromText(extracted, title);
          // Drop any scenes that have no dialogue lines; they are noise.
          scenes = (parsed || []).filter(
            (sc) => Array.isArray(sc.lines) && sc.lines.length > 0
          );

          // Auto LLM cleanup if quality is poor
          const qualityCheck = shouldUseImportCleanup(extracted, scenes);
          if (qualityCheck.use) {
            const t0 = Date.now();
            const result = await llmCleanupToScenes(extracted, title);
            const ms = Date.now() - t0;
            const model = process.env.IMPORT_CLEANUP_MODEL || "?";
            const outLines = result ? result.scenes.flatMap(s => s.lines).length : 0;
            const ok = !!(result && outLines > 0);
            console.log(
              "[import-cleanup] used=%s ok=%s reason=%s model=%s inChars=%d outScenes=%d outLines=%d ms=%d",
              true, ok, qualityCheck.reason, model, extracted.length,
              result ? result.scenes.length : 0, outLines, ms
            );
            if (ok) {
              scenes = result!.scenes;
              cleanupUsed = true;
              cleanupReason = qualityCheck.reason;
              cleanupOutLines = outLines;
            }
          }
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
          ...(cleanupUsed ? { cleanup_used: true, cleanup_reason: cleanupReason, cleanup_out_lines: cleanupOutLines } : {}),
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

      const result = await generateReaderMp3(lines, voiceMap, "USER", "normal");

      res.setHeader("Content-Type", "audio/mpeg");
      fs.createReadStream(result.outPath).pipe(res);
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
      const renderResult = await (generateReaderMp3 as any)(...args);
      const outPath = typeof renderResult === "string" ? renderResult : renderResult.outPath;
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

  // Background render job (non-blocking)
  async function runRenderJob(
    renderId: string,
    lines: { character: string; text: string }[],
    voiceMap: Record<string, string>,
    role: string,
    pace: "slow" | "normal" | "fast",
    chargedChars: number,
    chargedCredits: number,
    script_id: string,
    scene_id: string,
  ) {
    console.log("[debug/render] start render_id=%s script_id=%s scene_id=%s", renderId, script_id, scene_id);
    const now = Date.now();
    renders.set(renderId, {
      status: "working",
      accounted: false,
      chargedChars,
      chargedCredits,
      scriptId: script_id,
      sceneId: scene_id,
      startedAt: now,
      updatedAt: now,
    });

    // Generate reader MP3 + per-line segments + manifest
    let result: RenderResult;
    try {
      result = await generateReaderMp3(lines, voiceMap, role, pace, renderId, { script_id, scene_id, role });
    } catch (ttsErr) {
      console.error("[debug/render] error render_id=%s tts_failed", renderId, ttsErr);
      renders.set(renderId, {
        status: "error",
        err: "tts_failed",
        accounted: false,
        chargedChars,
        chargedCredits,
        scriptId: script_id,
        sceneId: scene_id,
        startedAt: now,
        updatedAt: Date.now(),
      });
      return;
    }
    const file = result.outPath;

    // Upload to R2 if enabled
    if (r2Enabled()) {
      try {
        const r2Key = `renders/${renderId}.mp3`;
        await r2PutFile(r2Key, file, "audio/mpeg");
        console.log("[debug/render] Uploaded to R2: key=%s", r2Key);

        // Upload per-line segments + manifest to R2
        for (const seg of result.segments) {
          const segFile = path.join(result.segmentDir, `seg_${String(seg.segment_index).padStart(3, "0")}.mp3`);
          const segR2Key = `renders/${renderId}/seg_${String(seg.segment_index).padStart(3, "0")}.mp3`;
          await r2PutFile(segR2Key, segFile, "audio/mpeg");
        }
        const manifestFile = path.join(result.segmentDir, "manifest.json");
        await r2PutFile(`renders/${renderId}/manifest.json`, manifestFile, "application/json");
        console.log("[debug/render] Uploaded segments+manifest to R2: %d segments", result.segments.length);
      } catch (err) {
        console.error("[debug/render] error render_id=%s r2_upload_failed", renderId, err);
        renders.set(renderId, {
          status: "error",
          err: "r2_upload_failed",
          accounted: false,
          chargedChars,
          chargedCredits,
          scriptId: script_id,
          sceneId: scene_id,
          startedAt: now,
          updatedAt: Date.now(),
        });
        return;
      }
    }

    console.log("[debug/render] complete render_id=%s", renderId);
    renders.set(renderId, {
      status: "complete",
      file,
      accounted: false,
      chargedChars,
      chargedCredits,
      scriptId: script_id,
      sceneId: scene_id,
      startedAt: now,
      updatedAt: Date.now(),
    });
  }

  // POST /debug/render (real TTS) - non-blocking, returns immediately
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
    const pace = (body.pace || "normal") as "slow" | "normal" | "fast";
    if (!script_id || !scene_id || !role) {
      return res.status(400).json({ error: "script_id, scene_id, role required" });
    }

    const script = await getOrLoadScript(script_id, userId);
    if (!script) {
      return res.status(404).json({ error: "script not found" });
    }

    // Find the scene
    const scene = script.scenes.find(s => s.id === scene_id) || script.scenes[0];
    if (!scene) {
      return res.status(404).json({ error: "scene not found" });
    }

    // Compute chargedChars: count only lines that will be synthesized (NOT the user/actor role)
    const chargedChars = scene.lines
      .filter(l => l.speaker.toUpperCase() !== role)
      .reduce((sum, l) => sum + (l.text?.length || 0), 0);
    const chargedCredits = chargedChars / 1000;

    // Resolve user key: X-OffBook-User > passkey userId > anon:sid (match /credits)
    const sid = ensureSid(req as any, res as any);
    const xOffbookUser = (req.header("X-OffBook-User") || "").trim();
    let userKey: string;
    if (xOffbookUser) {
      userKey = xOffbookUser;
    } else if (userId) {
      userKey = userId;
    } else {
      userKey = `anon:${sid}`;
    }

    // DB-backed credits gate (mirrors GET /credits logic)
    const billing = await getUserBilling(userKey);
    const creditsRow = await getUserCredits(userKey);

    const nowSec = Math.floor(Date.now() / 1000);
    const periodEndSec = billing?.current_period_end ? Number(billing.current_period_end) : null;
    const dbStatusIsActive = billing?.status === "active" || billing?.status === "trialing";
    const periodExpired = dbStatusIsActive && periodEndSec !== null && nowSec >= periodEndSec;

    if (periodExpired && billing) {
      await upsertUserBilling({ user_id: userKey, plan: billing.plan, status: "inactive" });
    }

    const effectiveStatus = periodExpired ? "inactive" : (billing?.status ?? "inactive");
    const isActiveOrTrialing = effectiveStatus === "active" || effectiveStatus === "trialing";

    const includedMonthly = isActiveOrTrialing ? (billing?.included_quota || 120) : 0;
    const monthlyUsedExact = Number(billing?.renders_used ?? 0);
    const monthlyRemainingExact = Math.max(0, includedMonthly - monthlyUsedExact);

    const topupTotalExact = creditsRow ? Number(creditsRow.total_credits) : 0;
    const topupUsedExact = creditsRow ? Number(creditsRow.used_credits) : 0;
    const topupRemainingExact = Math.max(0, topupTotalExact - topupUsedExact);
    const topupFrozen = !isActiveOrTrialing;

    const spendableExact = monthlyRemainingExact + (topupFrozen ? 0 : topupRemainingExact);

    res.setHeader("x-credits-remaining", String(Math.floor(spendableExact)));
    if (spendableExact < chargedCredits) {
      return res.status(402).json({
        error: "insufficient_credits",
        status: effectiveStatus,
        topup_frozen: topupFrozen,
        monthly_remaining_exact: monthlyRemainingExact,
        topup_remaining_exact: topupRemainingExact,
        remaining_exact: spendableExact,
        chargedCredits,
      });
    }

    const ownerKey = userKey;

    const renderId = crypto.randomUUID();
    const now = Date.now();
    renders.set(renderId, {
      status: "queued",
      accounted: false,
      chargedChars,
      chargedCredits,
      scriptId: script_id,
      sceneId: scene_id,
      startedAt: now,
      updatedAt: now,
    });
    const store = getCreditsStore();
    store.renderOwner.set(renderId, ownerKey);
    store.accountedRenders.delete(renderId);

    // Build lines for TTS
    const lines = scene.lines.map(l => ({ character: l.speaker, text: l.text }));

    // Build voiceMap and ensure UNKNOWN fallback
    const voiceMap = script.voiceMap || {};
    if (!voiceMap.UNKNOWN) {
      voiceMap.UNKNOWN = "alloy";
    }

    // Kick off render in background (non-blocking)
    void runRenderJob(renderId, lines, voiceMap, role, pace, chargedChars, chargedCredits, script_id, scene_id);

    // Respond immediately
    res.json({ render_id: renderId, status: "queued" });
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
      const store = getCreditsStore();
      if (!store.accountedRenders.has(rid)) {
        const ownerKey = store.renderOwner.get(rid) || getOwnerKey(req);
        const state = ensureOwnerState(ownerKey);
        const creditsToCharge = job.chargedCredits ?? 1;
        state.used += creditsToCharge;
        store.accountedRenders.add(rid);

        // Debit against DB-backed billing (noteRenderComplete respects X-OffBook-User header)
        try {
          const result = await noteRenderComplete(req, {
            chargedChars: job.chargedChars,
            chargedCredits: job.chargedCredits,
            meta: { renderId: rid, scriptId: job.scriptId, sceneId: job.sceneId },
          });
          if (result) {
            console.error("[render_status] noteRenderComplete returned error", { render_id: rid, error: result });
          } else {
            console.log("[render_status] debited", { render_id: rid, userKey: ownerKey, chargedCredits: creditsToCharge });
          }
        } catch (err) {
          console.error("[render_status] noteRenderComplete failed", err);
        }

        job.accounted = true;
        renders.set(rid, job);
      }
    }

    const payload: any = { status: job.status };
    if (job.status === "complete" && job.file) {
      const base = baseUrlFrom(req);
      const id = path.basename(job.file, ".mp3");
      payload.download_url = `${base}/api/assets/${id}`;
      payload.manifest_url = `/api/assets/${id}/manifest`;
    }
    if (job.status === "error" && job.err) {
      payload.error = job.err;
    }
    res.json(payload);
  });

  // GET /debug/billing/replay_refund_by_charge
  debug.get("/billing/replay_refund_by_charge", async (req: Request, res: Response) => {
    try {
      // Production safety gate
      if (process.env.ENABLE_BILLING_ADMIN_TOOLS !== "1") {
        return res.status(404).send("Not Found");
      }

      // Billing admin secret check (separate from SHARED_SECRET)
      const billingAdminSecret = process.env.BILLING_ADMIN_SECRET;
      if (!billingAdminSecret || !billingAdminSecret.trim()) {
        return res.status(404).send("Not Found");
      }

      const providedSecret = (req.query.admin_secret as string) || req.header("X-Billing-Admin-Secret");
      if (!providedSecret || providedSecret.trim() !== billingAdminSecret.trim()) {
        return res.status(401).json({ ok: false, error: "unauthorized" });
      }

      const charge_id = String(req.query.charge_id || "").trim();

      if (!charge_id) {
        return res.status(400).json({ ok: false, error: "missing_charge_id" });
      }

      if (!stripe) {
        return res.status(400).json({ ok: false, error: "stripe_not_configured" });
      }

      // Retrieve the charge with expanded payment_intent (supports both py_ and ch_ IDs)
      let charge: Stripe.Charge;
      try {
        charge = await stripe.charges.retrieve(charge_id, {
          expand: ['payment_intent']
        });
      } catch (err: any) {
        console.error("[billing] replay_refund_by_charge failed to retrieve charge", err);
        return res.status(404).json({
          ok: false,
          error: "charge_not_found",
          message: err?.message || String(err),
        });
      }

      // Verify the charge is refunded
      if (!charge.refunded && (!charge.amount_refunded || charge.amount_refunded === 0)) {
        return res.status(400).json({
          ok: false,
          error: "charge_not_refunded",
          message: "Charge has not been refunded",
        });
      }

      // Read metadata from expanded payment_intent first, fallback to charge metadata
      let userId = "";
      let creditsStr = "";

      // Try payment_intent metadata first
      if (charge.payment_intent && typeof charge.payment_intent === 'object') {
        const pi = charge.payment_intent as Stripe.PaymentIntent;
        userId = (pi.metadata?.userId || "").toString().trim();
        creditsStr = (pi.metadata?.credits || "").toString().trim();
      }

      // Fallback to charge metadata if needed
      if (!userId || !creditsStr) {
        userId = userId || (charge.metadata?.userId || "").toString().trim();
        creditsStr = creditsStr || (charge.metadata?.credits || "").toString().trim();
      }

      const credits = parseInt(creditsStr, 10);

      if (!userId || !creditsStr || isNaN(credits)) {
        return res.status(400).json({
          ok: false,
          error: "missing_metadata",
          message: "Missing userId or credits in metadata",
        });
      }

      // Calculate proportional credit reversal for partial refunds
      const chargeAmount = charge.amount || 0;
      const amountRefunded = charge.amount_refunded || 0;

      if (chargeAmount === 0) {
        return res.json({
          ok: true,
          charge_id,
          userId,
          creditsDelta: 0,
          skipped: true,
          reason: "charge_amount_zero"
        });
      }

      const ratio = amountRefunded / chargeAmount;
      const creditsToReverse = Math.round(credits * ratio);

      if (creditsToReverse <= 0) {
        return res.json({
          ok: true,
          charge_id,
          userId,
          creditsDelta: 0,
          skipped: true,
          reason: "credits_to_reverse_zero"
        });
      }

      // Idempotency: use unique key for manual refund replay
      const eventId = `manual_refund:${charge_id}`;
      const eventType = "manual_refund_replay";

      let isNewEvent = false;
      try {
        isNewEvent = await recordBillingEventOnce(eventId, eventType, userId);
      } catch (err) {
        console.error("[billing] replay_refund_by_charge failed to record event", err);
        return res.status(500).json({ ok: false, error: "event_recording_failed" });
      }

      // If duplicate, return early
      if (!isNewEvent) {
        console.log("[billing] replay_refund_by_charge duplicate detected", {
          charge_id,
          userId,
        });
        return res.json({
          ok: true,
          charge_id,
          userId,
          creditsDelta: -creditsToReverse,
          skippedDuplicate: true,
        });
      }

      // Reverse the credits
      const updated = await addUserCredits(userId, -creditsToReverse);

      console.log("[billing] replay_refund_by_charge reversed credits", {
        charge_id,
        userId,
        originalCredits: credits,
        creditsToReverse,
        ratio,
        chargeAmount,
        amountRefunded,
        totalCredits: updated.total_credits,
        usedCredits: updated.used_credits,
        availableCredits: getAvailableCredits(updated),
      });

      return res.json({
        ok: true,
        charge_id,
        userId,
        creditsDelta: -creditsToReverse,
        skippedDuplicate: false,
      });
    } catch (e: any) {
      console.error("[billing] replay_refund_by_charge error", e);
      return res.status(500).json({
        ok: false,
        error: "replay_failed",
        message: e?.message || String(e),
      });
    }
  });

  // ────────────────────────────────────────────────────────────────────────────
  // STAGING TEST ONLY - Credit manipulation endpoints for testing without TTS cost
  // Gated: ALLOW_TEST_ROUTES=1 AND OFFBOOK_ENV === "staging"
  // ────────────────────────────────────────────────────────────────────────────
  const allowTestRoutes = process.env.ALLOW_TEST_ROUTES === "1" && process.env.OFFBOOK_ENV === "staging";

  if (allowTestRoutes) {
    console.log("[http-routes] STAGING TEST ONLY: /debug/test/* routes enabled");

    // Helper: build /credits?debug=1 style response for a user
    async function buildCreditsDebugResponse(userKey: string): Promise<Record<string, unknown>> {
      const billing = await getUserBilling(userKey);
      const creditsRow = await getUserCredits(userKey);

      const nowSec = Math.floor(Date.now() / 1000);
      const periodEndSec = billing?.current_period_end ? Number(billing.current_period_end) : null;
      const periodStartSec = billing?.current_period_start ? Number(billing.current_period_start) : null;
      const dbStatusIsActive = billing?.status === "active" || billing?.status === "trialing";
      const periodExpired = dbStatusIsActive && periodEndSec !== null && nowSec >= periodEndSec;

      const effectiveStatus = periodExpired ? "inactive" : (billing?.status ?? "inactive");
      const isActiveOrTrialing = effectiveStatus === "active" || effectiveStatus === "trialing";

      const includedMonthly = isActiveOrTrialing ? (billing?.included_quota || 120) : 0;
      const monthlyUsedExact = Number(billing?.renders_used ?? 0);
      const monthlyRemainingExact = Math.max(0, includedMonthly - monthlyUsedExact);
      const monthlyRemaining = Math.floor(monthlyRemainingExact);
      const usedMonthly = includedMonthly - monthlyRemaining;

      const topupTotalExact = creditsRow ? Number(creditsRow.total_credits) : 0;
      const topupUsedExact = creditsRow ? Number(creditsRow.used_credits) : 0;
      const topupRemainingExact = Math.max(0, topupTotalExact - topupUsedExact);
      const topupRemaining = Math.floor(topupRemainingExact);
      const topupFrozen = !isActiveOrTrialing;

      const remaining = monthlyRemaining + (topupFrozen ? 0 : topupRemaining);
      const usedTotal = usedMonthly + (creditsRow?.used_credits ?? 0);

      const periodStartIso = isActiveOrTrialing && periodStartSec ? new Date(periodStartSec * 1000).toISOString() : "";
      const periodEndIso = isActiveOrTrialing && periodEndSec ? new Date(periodEndSec * 1000).toISOString() : "";

      return {
        included: includedMonthly,
        granted: topupRemaining,
        used: usedTotal,
        remaining,
        period_start: periodStartIso,
        period_end: periodEndIso,
        topup_frozen: topupFrozen,
        status: effectiveStatus,
        monthly_included: includedMonthly,
        monthly_used: usedMonthly,
        monthly_remaining: monthlyRemaining,
        // Debug fields (always included for test routes)
        debug_user_key: userKey,
        monthly_used_exact: monthlyUsedExact,
        monthly_remaining_exact: monthlyRemainingExact,
        topup_used_exact: topupUsedExact,
        topup_remaining_exact: topupRemainingExact,
      };
    }

    // STAGING TEST ONLY: POST /debug/test/set_credits
    // Directly set credit values for testing
    debug.post("/test/set_credits", express.json(), async (req: Request, res: Response) => {
      try {
        const { user_key, monthly_used_exact, topup_remaining_exact } = req.body || {};

        if (!user_key || typeof user_key !== "string") {
          return res.status(400).json({ error: "missing_user_key" });
        }

        // Update monthly used (renders_used in user_billing)
        if (typeof monthly_used_exact === "number") {
          const existing = await getUserBilling(user_key);
          if (existing) {
            await upsertUserBilling({
              user_id: user_key,
              plan: existing.plan,
              status: existing.status,
              renders_used: monthly_used_exact,
            });
          } else {
            // Create billing row if none exists (default to active pro)
            await upsertUserBilling({
              user_id: user_key,
              plan: "pro",
              status: "active",
              included_quota: 120,
              renders_used: monthly_used_exact,
            });
          }
          console.log(`[test/set_credits] STAGING TEST ONLY: set monthly_used_exact=${monthly_used_exact} for user_key=${user_key}`);
        }

        // Update topup remaining (set total_credits and used_credits accordingly)
        if (typeof topup_remaining_exact === "number") {
          const newTotal = topup_remaining_exact;
          const newUsed = 0;
          await dbRun(
            `INSERT INTO user_credits (user_id, total_credits, used_credits, updated_at)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(user_id) DO UPDATE SET total_credits = ?, used_credits = ?, updated_at = ?`,
            [user_key, newTotal, newUsed, new Date().toISOString(), newTotal, newUsed, new Date().toISOString()]
          );
          console.log(`[test/set_credits] STAGING TEST ONLY: set topup_remaining_exact=${topup_remaining_exact} for user_key=${user_key}`);
        }

        const credits = await buildCreditsDebugResponse(user_key);
        res.json({ ok: true, ...credits });
      } catch (err) {
        console.error("[test/set_credits] STAGING TEST ONLY error:", err);
        res.status(500).json({ error: "internal_error" });
      }
    });

    // STAGING TEST ONLY: POST /debug/test/simulate_debit
    // Apply a debit using the same bucket-selection logic as real charging
    debug.post("/test/simulate_debit", express.json(), async (req: Request, res: Response) => {
      try {
        const { user_key, credits_exact } = req.body || {};

        if (!user_key || typeof user_key !== "string") {
          return res.status(400).json({ error: "missing_user_key" });
        }
        if (typeof credits_exact !== "number" || credits_exact <= 0) {
          return res.status(400).json({ error: "invalid_credits_exact" });
        }

        const billing = await getUserBilling(user_key);

        // Match buildCreditsDebugResponse effectiveStatus logic so inactive implies 0 monthly
        const nowSec = Math.floor(Date.now() / 1000);
        const periodEndSec = billing?.current_period_end ? Number(billing.current_period_end) : null;
        const dbStatusIsActive = billing?.status === "active" || billing?.status === "trialing";
        const periodExpired = dbStatusIsActive && periodEndSec !== null && nowSec >= periodEndSec;
        const effectiveStatus = periodExpired ? "inactive" : (billing?.status ?? "inactive");
        const isActiveOrTrialing = effectiveStatus === "active" || effectiveStatus === "trialing";
        const billingActive = isActiveOrTrialing;

        // Calculate monthly remaining (0 if not active/trialing)
        const includedQuota = isActiveOrTrialing ? (billing?.included_quota ?? 0) : 0;
        const rendersUsed = Number(billing?.renders_used ?? 0);
        const monthlyRemaining = Math.max(0, includedQuota - rendersUsed);

        // Split spend between monthly and topup (same logic as real charging)
        const monthlySpend = Math.min(credits_exact, monthlyRemaining);
        const topupSpend = credits_exact - monthlySpend;

        // Check if topup needed but billing not active
        if (topupSpend > 0 && !billingActive) {
          return res.status(400).json({
            error: "billing_inactive_topup_required",
            monthly_remaining: monthlyRemaining,
            monthly_spend: monthlySpend,
            topup_spend_needed: topupSpend,
          });
        }

        // Apply monthly spend
        if (monthlySpend > 0 && billing) {
          await dbRun(
            `UPDATE user_billing SET renders_used = renders_used + ? WHERE user_id = ?`,
            [monthlySpend, user_key]
          );
        }

        // Apply topup spend
        if (topupSpend > 0) {
          await dbRun(
            `UPDATE user_credits SET used_credits = used_credits + ? WHERE user_id = ?`,
            [topupSpend, user_key]
          );
        }

        console.log(`[test/simulate_debit] STAGING TEST ONLY: debit=${credits_exact} (monthly=${monthlySpend}, topup=${topupSpend}) for user_key=${user_key}`);

        const credits = await buildCreditsDebugResponse(user_key);
        res.json({
          ok: true,
          debited: credits_exact,
          monthly_spend: monthlySpend,
          topup_spend: topupSpend,
          ...credits,
        });
      } catch (err) {
        console.error("[test/simulate_debit] STAGING TEST ONLY error:", err);
        res.status(500).json({ error: "internal_error" });
      }
    });

    // STAGING TEST ONLY: POST /debug/test/reset_monthly
    // Reset monthly usage to 0 (120 remaining)
    debug.post("/test/reset_monthly", express.json(), async (req: Request, res: Response) => {
      try {
        const { user_key } = req.body || {};

        if (!user_key || typeof user_key !== "string") {
          return res.status(400).json({ error: "missing_user_key" });
        }

        const existing = await getUserBilling(user_key);
        if (!existing) {
          // Create billing row with defaults
          await upsertUserBilling({
            user_id: user_key,
            plan: "pro",
            status: "active",
            included_quota: 120,
            renders_used: 0,
          });
        } else {
          await upsertUserBilling({
            user_id: user_key,
            plan: existing.plan,
            status: existing.status,
            renders_used: 0,
          });
        }

        console.log(`[test/reset_monthly] STAGING TEST ONLY: reset monthly to 0 used for user_key=${user_key}`);

        const credits = await buildCreditsDebugResponse(user_key);
        res.json({ ok: true, ...credits });
      } catch (err) {
        console.error("[test/reset_monthly] STAGING TEST ONLY error:", err);
        res.status(500).json({ error: "internal_error" });
      }
    });
  }

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

  // POST /api/gallery/upload_stems - Upload mic and reader stems for a take
  api.post(
    "/gallery/upload_stems",
    requireUser,
    galleryUpload.fields([
      { name: "mic", maxCount: 1 },
      { name: "reader", maxCount: 1 }
    ]),
    async (req: Request, res: Response) => {
      try {
        const user = (req as any).user || res.locals.user;
        const files = (req as any).files;
        const takeId = String(req.body?.id || "");

        const micFile = files?.mic?.[0];
        const readerFile = files?.reader?.[0];

        // Initialize debug event at the start
        lastStemsUploadError = null;
        lastStemsUploadEvent = {
          at: new Date().toISOString(),
          stage: "requested",
          takeId,
          userId: String(user?.id || ""),
          hasMic: !!micFile,
          hasReader: !!readerFile,
        };

        if (!user || !user.id) {
          return res.status(401).json({ error: "Unauthorized" });
        }

        if (!takeId) {
          return res.status(400).json({ error: "id_required" });
        }

        if (!files?.mic || !files?.reader) {
          return res.status(400).json({ error: "mic_and_reader_required" });
        }

        if (!micFile?.path || !readerFile?.path) {
          return res.status(400).json({ error: "stems_upload_bad_storage", hint: "Expected disk storage with file.path" });
        }

        // Determine file extensions from original names or default to .webm
        const micExt = path.extname(micFile.originalname || "") || ".webm";
        const readerExt = path.extname(readerFile.originalname || "") || ".webm";

        // Save stems locally
        const stemsDir = path.join(process.cwd(), "uploads", "gallery", String(user.id), "stems");
        fs.mkdirSync(stemsDir, { recursive: true });

        const micPath = path.join(stemsDir, `${takeId}-mic${micExt}`);
        const readerPath = path.join(stemsDir, `${takeId}-reader${readerExt}`);

        fs.renameSync(micFile.path, micPath);
        fs.renameSync(readerFile.path, readerPath);

        console.log("[stems] Saved locally: user=%s takeId=%s mic=%s reader=%s",
          user.id, takeId, micPath, readerPath);

        // Upload to R2 deterministically (not best-effort) BEFORE responding
        if (r2Enabled()) {
          const micKey = `stems/${user.id}/${takeId}-mic${micExt}`;
          const readerKey = `stems/${user.id}/${takeId}-reader${readerExt}`;

          lastStemsUploadEvent = { ...lastStemsUploadEvent, stage: "r2_uploading", micKey, readerKey };
          lastStemsUploadError = null;

          try {
            // Upload both stems in parallel to avoid doubling the wait time
            await Promise.all([
              r2PutFile(micKey, micPath, micFile.mimetype || "audio/webm"),
              r2PutFile(readerKey, readerPath, readerFile.mimetype || "audio/webm"),
            ]);

            // Verify both stems exist in R2
            const micHead = await r2Head(micKey);
            const readerHead = await r2Head(readerKey);

            if (!micHead || !readerHead) {
              throw new Error("r2_verify_failed");
            }

            lastStemsUploadEvent = { ...lastStemsUploadEvent, stage: "complete", micKey, readerKey, micPath, readerPath };

            console.log("[stems] Uploaded to R2: user=%s takeId=%s micKey=%s readerKey=%s",
              user.id, takeId, micKey, readerKey);

            // Respond with R2 persistence confirmation
            return res.json({
              ok: true,
              takeId,
              storage: {
                micKey,
                readerKey,
                micExt,
                readerExt,
                persisted: "r2"
              }
            });
          } catch (err) {
            console.error("[stems] R2 upload failed, keeping local only:", err);
            lastStemsUploadError = { at: new Date().toISOString(), error: String(err) };
            lastStemsUploadEvent = { ...lastStemsUploadEvent, stage: "error_r2", micPath, readerPath };

            // Keep local stems, respond with error
            return res.status(502).json({
              ok: false,
              error: "r2_upload_failed"
            });
          }
        }

        // R2 not enabled - respond with local-only persistence
        lastStemsUploadEvent = {
          ...lastStemsUploadEvent,
          stage: "complete_local",
          micPath,
          readerPath
        };

        res.json({
          ok: true,
          takeId,
          storage: {
            persisted: "local_only"
          }
        });
      } catch (err) {
        console.error("Error in POST /api/gallery/upload_stems", err);
        lastStemsUploadError = {
          at: new Date().toISOString(),
          error: String((err as any)?.message || err)
        };
        lastStemsUploadEvent = {
          ...lastStemsUploadEvent,
          stage: "error"
        };
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
    let tempMicFile: string | null = null;
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
      if (!getMixdownEnabled()) {
        lastMixdownEvent = {
          ...(lastMixdownEvent as any),
          stage: "mixdown_disabled",
          env_MIXDOWN_ENABLED: process.env.MIXDOWN_ENABLED ?? null
        };
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

      // Prefer local take file if it exists (even when DB stores r2://...)
      // This avoids slow/stalled R2 downloads right after recording.
      let takeInputPath = filePath;

      if (filePath && filePath.startsWith("r2://")) {
        const localDir = path.join(process.cwd(), "uploads", "gallery", String(user.id));
        try {
          if (fs.existsSync(localDir)) {
            const files = fs.readdirSync(localDir);
            const match = files.find((f) => f.startsWith(`${id}.`)); // id.mp4 / id.webm / etc
            if (match) {
              takeInputPath = path.join(localDir, match);
              lastMixdownEvent = { ...(lastMixdownEvent as any), stage: "using_local_take", localPath: takeInputPath };
              console.log("[mixed_file] Using local take file instead of R2: %s", takeInputPath);
            }
          }
        } catch (e) {
          console.warn("[mixdown] local take scan failed", e);
        }

        // If local file not found, download from R2
        if (takeInputPath === filePath) {
          const r2Key = filePath.substring(5); // Remove "r2://" prefix
          const tmpDir = path.join(os.tmpdir(), "offbook");
          fs.mkdirSync(tmpDir, { recursive: true });

          tempTakeFile = path.join(tmpDir, `${id}-take.mp4`);
          takeInputPath = tempTakeFile;

          lastMixdownEvent = {
            ...lastMixdownEvent,
            stage: "downloading_take_r2",
            r2Key,
            tempPath: tempTakeFile
          };

          console.log("[mixed_file] Downloading take from R2: key=%s to temp=%s", r2Key, tempTakeFile);

          try {
            const takeResult = await r2GetObjectStream(r2Key);
            await pipeStreamToFile(takeResult.stream, tempTakeFile, "take", 120000);
            console.log("[mixed_file] Downloaded take from R2 successfully");
          } catch (err) {
            console.error("[mixed_file] Failed to download take from R2:", err);
            lastMixdownEvent = {
              ...lastMixdownEvent,
              stage: "error",
              errorCode: "take_download_failed",
              errorMessage: String(err)
            };
            return res.status(500).json({ error: "take_download_failed" });
          }
        }
      }

      // Bump this when changing ffmpeg logic to bust cache
      const MIX_VER = "v9";
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
      const stemProbe: any[] = [];
      if ((!micStem || !readerStem) && r2Enabled()) {
        const stemExts = [".m4a", ".webm", ".mp3", ".wav", ".ogg", ".mp4"];
        for (const ext of stemExts) {
          const micKey = `stems/${user.id}/${id}-mic${ext}`;
          const readerKey = `stems/${user.id}/${id}-reader${ext}`;

          try {
            const micHead = await r2Head(micKey);
            const readerHead = await r2Head(readerKey);

            stemProbe.push({
              ext,
              micKey,
              readerKey,
              micExists: micHead.exists,
              readerExists: readerHead.exists
            });

            if (micHead.exists && readerHead.exists) {
              // Download both stems to temp
              const tmpDir = path.join(os.tmpdir(), "offbook-mix");
              fs.mkdirSync(tmpDir, { recursive: true });

              const micTemp = path.join(tmpDir, `${id}-mic-${Date.now()}${ext}`);
              const readerTemp = path.join(tmpDir, `${id}-reader-${Date.now()}${ext}`);

              try {
                const micResult = await r2GetObjectStream(micKey);
                await pipeStreamToFile(micResult.stream, micTemp, "mic", 120000);

                const readerResult = await r2GetObjectStream(readerKey);
                await pipeStreamToFile(readerResult.stream, readerTemp, "reader", 120000);

                micStem = micTemp;
                readerStem = readerTemp;
                tempMicFile = micTemp;
                tempReaderFile = readerTemp;
                console.log("[mixed_file] Downloaded stems from R2: mic=%s, reader=%s", micKey, readerKey);
                break;
              } catch (err) {
                console.error("[mixed_file] Failed to download stems from R2:", err);
                lastMixdownEvent = {
                  ...lastMixdownEvent,
                  stage: "error",
                  errorCode: "stems_download_failed",
                  errorMessage: String(err),
                  micKey,
                  readerKey,
                  stemProbe
                };
                return res.status(500).json({ error: "stems_download_failed" });
              }
            }
          } catch (err) {
            // Log HEAD failure and continue trying other extensions
            stemProbe.push({
              ext,
              micKey,
              readerKey,
              headError: String(err)
            });
            continue;
          }
        }
      }

      // Attach stem probe results to debug event
      lastMixdownEvent = { ...(lastMixdownEvent as any), stemProbe };

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
      // Use takeInputPath directory (not filePath) since takeInputPath may be local even if filePath is r2://
      const outDir = takeInputPath.startsWith("r2://")
        ? path.join(os.tmpdir(), "offbook")
        : path.dirname(takeInputPath);

      if (takeInputPath.startsWith("r2://")) {
        fs.mkdirSync(outDir, { recursive: true });
      }

      const outPath = path.join(outDir, `${id}-${mode}-${MIX_VER}.mixed.mp4`);

      // Mark as temp output if we're using temp directory
      if (takeInputPath.startsWith("r2://") || takeInputPath.includes(os.tmpdir())) {
        tempOutputFile = outPath;
      }
      const outExists = fs.existsSync(outPath);

      if (useStems) {
        console.log("[mixed_file] Using stems for take %s: mic=%s, reader=%s", id, micStem, readerStem);

        // Check if rebuild needed
        const micStat = fs.statSync(micStem!);
        const readerStat = fs.statSync(readerStem!);
        const takeStat = fs.statSync(takeInputPath);
        const needsRebuild =
          !outExists ||
          fs.statSync(outPath).mtimeMs <
            Math.max(takeStat.mtimeMs, micStat.mtimeMs, readerStat.mtimeMs);

        if (needsRebuild) {
          // 3-input FFmpeg: take video + mic stem + reader stem
          const filter =
            mode === "dry"
              ? "[2:a]highpass=f=180,lowpass=f=6500,volume=1.99[rd];" +
                "[1:a][rd]amix=inputs=2:weights=1 1.70:normalize=0:duration=first:dropout_transition=3,alimiter=limit=0.95[aout]"
              : "[2:a]aecho=0.35:0.25:18|34:0.18|0.12,highpass=f=180,lowpass=f=6500,volume=1.99[room];" +
                "[1:a][room]amix=inputs=2:weights=1 1.70:normalize=0:duration=first:dropout_transition=3,alimiter=limit=0.95[aout]";

          const baseArgs = [
            "-y",
            "-i",
            takeInputPath, // input 0: take video
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

        const takeStat = fs.statSync(takeInputPath);
        const readerStat = fs.statSync(readerFile);
        const needsRebuild =
          !outExists ||
          fs.statSync(outPath).mtimeMs <
            Math.max(takeStat.mtimeMs, readerStat.mtimeMs);

        if (needsRebuild) {
          const filter =
            "[1:a]aecho=0.35:0.25:18|34:0.18|0.12,highpass=f=180,lowpass=f=6500,volume=1.99[room];" +
            "[0:a][room]amix=inputs=2:duration=first:dropout_transition=4[aout]";
          const baseArgs = [
            "-y",
            "-i",
            takeInputPath,
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

      // Cleanup temp files after response finishes
      res.on("finish", () => {
        try {
          if (tempTakeFile && fs.existsSync(tempTakeFile)) {
            fs.unlinkSync(tempTakeFile);
            console.log("[mixed_file] Cleaned up temp take file: %s", tempTakeFile);
          }
          if (tempMicFile && fs.existsSync(tempMicFile)) {
            fs.unlinkSync(tempMicFile);
            console.log("[mixed_file] Cleaned up temp mic file: %s", tempMicFile);
          }
          if (tempReaderFile && fs.existsSync(tempReaderFile)) {
            fs.unlinkSync(tempReaderFile);
            console.log("[mixed_file] Cleaned up temp reader file: %s", tempReaderFile);
          }
          if (tempOutputFile && fs.existsSync(tempOutputFile)) {
            fs.unlinkSync(tempOutputFile);
            console.log("[mixed_file] Cleaned up temp output file: %s", tempOutputFile);
          }
        } catch (cleanupErr) {
          console.warn("[mixed_file] Cleanup error:", cleanupErr);
        }
      });

      return res.sendFile(outPath);
    } catch (err) {
      console.error("[mixdown] Error processing mixed file request, takeId=%s, userId=%s: %s", id, user?.id, err);

      // Build detailed error message with ffmpeg diagnostics if available
      let errorMessage = String(err);
      const ffmpegErr = (err as any)?.ffmpeg;
      if (ffmpegErr) {
        errorMessage += `\nFFmpeg exit code: ${ffmpegErr.code}`;
        if (ffmpegErr.stderr) {
          errorMessage += `\nFFmpeg stderr: ${ffmpegErr.stderr.slice(-500)}`;
        }
        if (ffmpegErr.args) {
          errorMessage += `\nFFmpeg args: ${JSON.stringify(ffmpegErr.args)}`;
        }
      }

      lastMixdownEvent = {
        ...lastMixdownEvent,
        stage: "error",
        errorCode: "internal_error",
        errorMessage
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

      // Helper to infer video MIME type by extension
      const inferMimeByExt = (pathOrKey: string): string | undefined => {
        const ext = path.extname(pathOrKey).toLowerCase();
        if (ext === ".mp4" || ext === ".m4v") return "video/mp4";
        if (ext === ".mov") return "video/quicktime";
        if (ext === ".webm") return "video/webm";
        return undefined;
      };

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

      // Set Cache-Control: no-store for this route
      res.setHeader("Cache-Control", "no-store");

      // Check if file is stored in R2
      if (filePath.startsWith("r2://")) {
        const r2Key = filePath.substring(5); // Remove "r2://" prefix
        const mime = (row as any).mime_type as string | undefined;
        const rangeHeader = req.headers.range;

        // Compute extension from best available string
        const extSource = r2Key || (row as any).filename || (row as any).name || "";
        const inferredMime = inferMimeByExt(extSource);

        try {
          const { stream, contentType, contentLength, contentRange, statusCode } =
            await r2GetObjectStream(r2Key, rangeHeader);

          // Set headers
          res.setHeader("Accept-Ranges", "bytes");

          // Prioritize inferred MIME to fix legacy takes with wrong stored mime_type
          const effectiveMime = inferredMime || contentType || (mime && mime.startsWith("video/") ? mime : undefined) || "video/mp4";
          res.setHeader("Content-Type", effectiveMime);

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

        // Check if file is empty (0 bytes)
        const stats = fs.statSync(filePath);
        if (stats.size === 0) {
          return res.status(404).json({ error: "file_empty" });
        }

        // Compute extension from best available string
        const extSource = filePath || (row as any).filename || (row as any).name || "";
        const inferredMime = inferMimeByExt(extSource);
        const storedMime = (row as any).mime_type as string | undefined;

        // Prioritize inferred MIME to fix legacy takes with wrong stored mime_type
        const effectiveMime = inferredMime || storedMime || "video/mp4";

        // Set Accept-Ranges header for all local files
        res.setHeader("Accept-Ranges", "bytes");

        if (wantsDownload) {
          res.setHeader("Content-Type", effectiveMime);
          return res.download(filePath, safeName);
        }

        // Handle Range requests (206 Partial Content)
        const rangeHeader = req.headers.range;
        if (rangeHeader) {
          const parts = rangeHeader.replace(/bytes=/, "").split("-");
          const start = parseInt(parts[0], 10);
          const end = parts[1] ? parseInt(parts[1], 10) : stats.size - 1;

          // Clamp to file bounds
          const clampedStart = Math.max(0, Math.min(start, stats.size - 1));
          const clampedEnd = Math.max(clampedStart, Math.min(end, stats.size - 1));
          const chunkSize = clampedEnd - clampedStart + 1;

          res.status(206);
          res.setHeader("Content-Range", `bytes ${clampedStart}-${clampedEnd}/${stats.size}`);
          res.setHeader("Content-Length", chunkSize);
          res.setHeader("Content-Type", effectiveMime);

          const fileStream = fs.createReadStream(filePath, { start: clampedStart, end: clampedEnd });
          fileStream.pipe(res);
        } else {
          // No Range header: send entire file
          res.setHeader("Content-Type", effectiveMime);
          res.sendFile(filePath);
        }
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

  api.get("/assets/:render_id", secretGuard, async (req: Request, res: Response) => {
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

        try {
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
        } catch (r2Err: any) {
          // R2 object not found - fall through to 404
          console.error(`[assets] R2 fetch failed for ${r2Key}: ${r2Err.message || r2Err}`);
        }
      }

      // Not found
      return res.status(404).json({ error: "asset not found" });
    } catch (err) {
      console.error("Error in GET /api/assets/:render_id", err);
      return res.status(500).send("Internal Server Error");
    }
  });
  // ────────────────────────────────────────────────────────────────────────────
  // POST /billing/apple/sync - Sync Apple entitlement to user_billing
  // ────────────────────────────────────────────────────────────────────────────
  app.post("/billing/apple/sync", secretGuard, express.json(), async (req: Request, res: Response) => {
    try {
      // Identify user: X-OffBook-User header > passkey userId > anon:sid
      const sid = ensureSid(req as any, res as any);
      const { userId } = getPasskeySession(req as any);
      const xOffbookUser = (req.header("X-OffBook-User") || "").trim();
      const userKey = xOffbookUser || userId || `anon:${sid}`;

      const { status, periodStartMs, periodEndMs } = req.body || {};

      if (!status || typeof status !== "string") {
        return res.status(400).json({ error: "missing_status" });
      }
      if (typeof periodStartMs !== "number" || typeof periodEndMs !== "number") {
        return res.status(400).json({ error: "missing_period_timestamps" });
      }

      // Convert ms → seconds for DB storage (DB stores seconds as string)
      const periodStartSec = Math.floor(periodStartMs / 1000);
      const periodEndSec = Math.floor(periodEndMs / 1000);

      // Check existing billing for rollover logic
      const existing = await getUserBilling(userKey);
      const existingEndSec = existing?.current_period_end ? Number(existing.current_period_end) : null;
      const nowSec = Math.floor(Date.now() / 1000);

      // Reset ONLY when this sync represents a new billing period AFTER the previous one ended.
      // This prevents accidental wipes from restore/duplicate sync calls where timestamps drift.
      const isRollover =
        existingEndSec !== null &&
        periodEndSec > existingEndSec &&
        nowSec >= existingEndSec;

      const resetMonthlyUsed = isRollover;

      // Upsert user_billing
      await upsertUserBilling({
        user_id: userKey,
        plan: "pro",
        status: status,
        included_quota: 120,
        current_period_start: String(periodStartSec),
        current_period_end: String(periodEndSec),
        renders_used: resetMonthlyUsed ? 0 : (existing?.renders_used ?? 0),
      });

      console.log(`[billing/apple/sync] userKey=${userKey} status=${status} existingEndSec=${existingEndSec} periodEndSec=${periodEndSec} nowSec=${nowSec} isRollover=${isRollover} resetMonthlyUsed=${resetMonthlyUsed}`);

      res.json({
        ok: true,
        userKey,
        status,
        included: 120,
        periodStartSec,
        periodEndSec,
        resetMonthlyUsed,
      });
    } catch (err) {
      console.error("[billing/apple/sync] error:", err);
      res.status(500).json({ error: "internal_error" });
    }
  });

  // ────────────────────────────────────────────────────────────────────────────
  // POST /billing/apple/topup - Mint top-up credits from Apple IAP purchase
  // ────────────────────────────────────────────────────────────────────────────
  app.post("/billing/apple/topup", secretGuard, express.json(), async (req: Request, res: Response) => {
    try {
      // Identify user: X-OffBook-User header > passkey userId > anon:sid
      const sid = ensureSid(req as any, res as any);
      const { userId } = getPasskeySession(req as any);
      const xOffbookUser = (req.header("X-OffBook-User") || "").trim();
      const userKey = xOffbookUser || userId || `anon:${sid}`;

      const { credits, transaction_id, product_id } = req.body || {};

      // Validate required fields
      if (typeof credits !== "number" || credits <= 0) {
        return res.status(400).json({ error: "invalid_credits", message: "credits must be a positive number" });
      }
      if (!transaction_id || typeof transaction_id !== "string") {
        return res.status(400).json({ error: "missing_transaction_id", message: "transaction_id is required for idempotency" });
      }

      // Idempotency: use transaction_id to prevent double-minting
      const eventId = `apple_topup:${transaction_id}`;
      const eventType = "apple_topup";

      let isNewEvent = false;
      try {
        isNewEvent = await recordBillingEventOnce(eventId, eventType, userKey);
      } catch (err) {
        console.error("[billing/apple/topup] failed to record event", err);
        return res.status(500).json({ error: "event_recording_failed" });
      }

      // If duplicate, return success but indicate it was already processed
      if (!isNewEvent) {
        console.log(`[billing/apple/topup] duplicate transaction_id=${transaction_id} for userKey=${userKey}`);

        // Still return current credits state
        const creditsRow = await getUserCredits(userKey);
        const topupTotal = creditsRow ? Number(creditsRow.total_credits) : 0;
        const topupUsed = creditsRow ? Number(creditsRow.used_credits) : 0;
        const topupRemaining = Math.max(0, topupTotal - topupUsed);

        return res.json({
          ok: true,
          userKey,
          credits_added: 0,
          duplicate: true,
          transaction_id,
          product_id: product_id || null,
          topup_total: topupTotal,
          topup_used: topupUsed,
          topup_remaining: topupRemaining,
        });
      }

      // Mint the credits
      const updated = await addUserCredits(userKey, credits);
      const topupRemaining = Math.max(0, updated.total_credits - updated.used_credits);

      console.log(`[billing/apple/topup] minted credits=${credits} for userKey=${userKey} transaction_id=${transaction_id} product_id=${product_id || "N/A"} new_total=${updated.total_credits}`);

      res.json({
        ok: true,
        userKey,
        credits_added: credits,
        duplicate: false,
        transaction_id,
        product_id: product_id || null,
        topup_total: updated.total_credits,
        topup_used: updated.used_credits,
        topup_remaining: topupRemaining,
      });
    } catch (err) {
      console.error("[billing/apple/topup] error:", err);
      res.status(500).json({ error: "internal_error" });
    }
  });

  // ────────────────────────────────────────────────────────────────────────────
  // GET /credits - Production credits endpoint (DB-backed billing + top-ups)
  // ────────────────────────────────────────────────────────────────────────────
  app.get("/credits", secretGuard, async (req: Request, res: Response) => {
    try {
      // Ensure session exists and get user identity
      // Priority: X-OffBook-User header > passkey userId > anon:sid
      const sid = ensureSid(req as any, res as any);
      const { userId } = getPasskeySession(req as any);
      const xOffbookUser = (req.header("X-OffBook-User") || "").trim();
      let userKey: string;
      let userKeySource: "x-offbook-user" | "passkey" | "anon-sid";
      if (xOffbookUser) {
        userKey = xOffbookUser;
        userKeySource = "x-offbook-user";
      } else if (userId) {
        userKey = userId;
        userKeySource = "passkey";
      } else {
        userKey = `anon:${sid}`;
        userKeySource = "anon-sid";
      }

      // Load billing + top-up state from DB
      const billing = await getUserBilling(userKey);
      const creditsRow = await getUserCredits(userKey);

      // Check if subscription period has expired
      const nowSec = Math.floor(Date.now() / 1000);
      const periodEndSec = billing?.current_period_end ? Number(billing.current_period_end) : null;
      const periodStartSec = billing?.current_period_start ? Number(billing.current_period_start) : null;
      const dbStatusIsActive = billing?.status === "active" || billing?.status === "trialing";
      const periodExpired = dbStatusIsActive && periodEndSec !== null && nowSec >= periodEndSec;

      // If expired, persist status flip to inactive for consistency
      if (periodExpired && billing) {
        await upsertUserBilling({
          user_id: userKey,
          plan: billing.plan,
          status: "inactive",
        });
        console.log(`[credits] period expired, flipped status to inactive for userKey=${userKey}`);
      }

      // Effective status: if period expired, treat as inactive
      const effectiveStatus = periodExpired ? "inactive" : (billing?.status ?? "inactive");
      const isActiveOrTrialing = effectiveStatus === "active" || effectiveStatus === "trialing";

      // Compute totals - active or trialing status gets included quota
      const includedMonthly = isActiveOrTrialing ? (billing?.included_quota || 120) : 0;

      // Exact float values (from NUMERIC/REAL columns)
      const monthlyUsedExact = Number(billing?.renders_used ?? 0);
      const monthlyRemainingExact = Math.max(0, includedMonthly - monthlyUsedExact);

      // Display integers: floor remaining, derive used to keep UI conservative
      const monthlyRemaining = Math.floor(monthlyRemainingExact);
      const usedMonthly = includedMonthly - monthlyRemaining;

      // Top-up: exact and display values
      const topupTotalExact = creditsRow ? Number(creditsRow.total_credits) : 0;
      const topupUsedExact = creditsRow ? Number(creditsRow.used_credits) : 0;
      const topupRemainingExact = Math.max(0, topupTotalExact - topupUsedExact);
      const topupRemaining = Math.floor(topupRemainingExact);
      const topupFrozen = !isActiveOrTrialing;

      const remaining = monthlyRemaining + (topupFrozen ? 0 : topupRemaining);
      const usedTotal = usedMonthly + (creditsRow?.used_credits ?? 0);

      // Convert period timestamps to ISO (stored as seconds, output as ISO)
      // If expired/inactive, return empty strings for period
      const periodStartIso = isActiveOrTrialing && periodStartSec ? new Date(periodStartSec * 1000).toISOString() : "";
      const periodEndIso = isActiveOrTrialing && periodEndSec ? new Date(periodEndSec * 1000).toISOString() : "";

      res.setHeader("x-credits-remaining", String(remaining));

      const payload: Record<string, unknown> = {
        included: includedMonthly,
        granted: topupRemaining,
        used: usedTotal,
        remaining,
        period_start: periodStartIso,
        period_end: periodEndIso,
        topup_frozen: topupFrozen,
        status: effectiveStatus,
        // Explicit monthly fields (integers for UI)
        monthly_included: includedMonthly,
        monthly_used: usedMonthly,
        monthly_remaining: monthlyRemaining,
        // Always return exact topup balance so iOS can display "(Frozen)" with real amount
        topup_remaining_exact: topupRemainingExact,
      };

      // Debug aid: include exact values and user key when debug=1
      if (req.query.debug === "1") {
        payload.debug_user_key = userKey;
        payload.debug_user_key_source = userKeySource;
        payload.monthly_used_exact = monthlyUsedExact;
        payload.monthly_remaining_exact = monthlyRemainingExact;
        payload.topup_used_exact = topupUsedExact;
      }

      res.json(payload);
    } catch (err) {
      console.error("[credits] error:", err);
      res.status(500).json({ error: "internal_error" });
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
