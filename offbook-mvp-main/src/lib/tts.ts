// src/lib/tts.ts
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import OpenAI from "openai";

type Line = { character: string; text: string };
type VoiceMap = Record<string, string>;
type Pace = "slow" | "normal" | "fast";

// Lazily initialize the OpenAI client after the env is available
let _client: OpenAI | null = null;

function hasOpenAIKey(): boolean {
  return !!process.env.OPENAI_API_KEY && process.env.OPENAI_API_KEY.trim().length > 0;
}
function getClient(): OpenAI | null {
  if (!hasOpenAIKey()) return null;
  if (_client) return _client;
  _client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
  return _client;
}

export function ttsProvider() {
  return hasOpenAIKey() ? "openai" : "stub";
}

// simple per-pace “gap repeats”
const GAP_REPEATS: Record<Pace, number> = { slow: 2, normal: 1, fast: 0 };

async function ttsToBuffer(text: string, voice: string): Promise<Buffer> {
  const client = getClient();
  if (!client) throw new Error("OPENAI_API_KEY not set");
  const resp = await client.audio.speech.create({
    model: "gpt-4o-mini-tts",
    voice: voice || "alloy",
    input: text,
    format: "mp3",
  });
  const arr = await resp.arrayBuffer();
  return Buffer.from(arr);
}

let cachedGap: Buffer | null = null;
async function getGapBuffer(voice: string): Promise<Buffer> {
  const client = getClient();
  if (!client) return Buffer.alloc(0);
  if (cachedGap) return cachedGap;
  // tiny “.” gap; generated once to keep encoding consistent
  cachedGap = await ttsToBuffer(".", voice || "alloy");
  return cachedGap;
}

/**
 * Generate a reader MP3 for partner lines (skip actor 'role').
 * Returns absolute outPath. Falls back to stub if no OPENAI_API_KEY.
 */
export async function generateReaderMp3(
  lines: Line[],
  voiceMap: VoiceMap,
  role: string,
  pace: Pace = "normal"
): Promise<string> {
  const id = crypto.randomUUID();
  const outDir = path.join(process.cwd(), "assets", "renders");
  fs.mkdirSync(outDir, { recursive: true });
  const outPath = path.join(outDir, `${id}.mp3`);

  if (!hasOpenAIKey()) {
    // STUB path (no key)
    const partnerTexts = lines
      .filter((l) => l.character.toUpperCase() !== role.toUpperCase())
      .map((l) => l.text);
    const debugPayload = Buffer.from(
      `OFFBOOK STUB MP3\nROLE=${role}\nPACE=${pace}\nTEXT=${partnerTexts.join(" | ").slice(0, 800)}\n`,
      "utf8"
    );
    fs.writeFileSync(outPath, debugPayload);
    return outPath;
  }

  // OpenAI path
  const chunks: Buffer[] = [];
  const repeats = GAP_REPEATS[pace] ?? 1;

  for (const ln of lines) {
    if (ln.character.toUpperCase() === role.toUpperCase()) {
      const gap = await getGapBuffer(voiceMap["UNKNOWN"] || "alloy");
      for (let i = 0; i < repeats; i++) chunks.push(gap);
      continue;
    }
    const v = voiceMap[ln.character] || voiceMap["UNKNOWN"] || "alloy";
    const audio = await ttsToBuffer(ln.text, v);
    chunks.push(audio);
    const gap = await getGapBuffer(v);
    for (let i = 0; i < repeats; i++) chunks.push(gap);
  }

  fs.writeFileSync(outPath, Buffer.concat(chunks));
  return outPath;
}
