// src/lib/tts.ts
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import os from "node:os";
import { spawn } from "node:child_process";
import OpenAI from "openai";
import ffmpegPath from "ffmpeg-static";

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
    response_format: "mp3",
  });
  const arr = await resp.arrayBuffer();
  return Buffer.from(arr);
}

/**
 * Robust TTS with retry + fallback to alloy voice.
 * Never silently drops a line - throws if all attempts fail.
 */
async function ttsToBufferRobust(
  text: string,
  voice: string,
  lineIndex: number
): Promise<Buffer> {
  let lastError: Error | null = null;

  // Attempt 1: requested voice
  try {
    const buf = await ttsToBuffer(text, voice);
    console.log(`[tts] line=${lineIndex} voice=${voice} retry=0 fallbackToAlloy=false`);
    return buf;
  } catch (err) {
    lastError = err as Error;
    console.warn(`[tts] line=${lineIndex} voice=${voice} attempt 1 failed: ${lastError.message}`);
  }

  // Attempt 2: retry with requested voice
  try {
    const buf = await ttsToBuffer(text, voice);
    console.log(`[tts] line=${lineIndex} voice=${voice} retry=1 fallbackToAlloy=false`);
    return buf;
  } catch (err) {
    lastError = err as Error;
    console.warn(`[tts] line=${lineIndex} voice=${voice} attempt 2 failed: ${lastError.message}`);
  }

  // Attempt 3: fallback to alloy
  if (voice !== "alloy") {
    try {
      const buf = await ttsToBuffer(text, "alloy");
      console.log(`[tts] line=${lineIndex} voice=alloy retry=2 fallbackToAlloy=true`);
      return buf;
    } catch (err) {
      lastError = err as Error;
      console.error(`[tts] line=${lineIndex} voice=alloy fallback failed: ${lastError.message}`);
    }
  }

  // All attempts failed
  const textSnippet = text.slice(0, 40);
  const errorMsg = `TTS failed for line ${lineIndex} ("${textSnippet}..."): ${lastError?.message || "unknown"}`;
  console.error(`[tts] render failed line=${lineIndex} reason=${lastError?.message || "unknown"}`);
  throw new Error(errorMsg);
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
  pace: Pace = "normal",
  fixedId?: string
): Promise<string> {
  const id = fixedId || crypto.randomUUID();
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

  // OpenAI path with ffmpeg-based concatenation
  const repeats = GAP_REPEATS[pace] ?? 1;
  const tmpDir = path.join(os.tmpdir(), `offbook-tts-${id}`);
  fs.mkdirSync(tmpDir, { recursive: true });

  console.log(`[tts] generateReaderMp3 starting: ${lines.length} lines, role=${role}`);

  const segmentFiles: string[] = [];
  let segmentIndex = 0;

  try {
    // Generate segments as individual MP3 files
    for (let i = 0; i < lines.length; i++) {
      const ln = lines[i];

      if (ln.character.toUpperCase() === role.toUpperCase()) {
        // Actor's line - add gap(s)
        const gap = await getGapBuffer(voiceMap["UNKNOWN"] || "alloy");
        for (let j = 0; j < repeats; j++) {
          const segPath = path.join(tmpDir, `seg-${String(segmentIndex).padStart(3, "0")}.mp3`);
          fs.writeFileSync(segPath, gap);
          segmentFiles.push(segPath);
          segmentIndex++;
        }
        continue;
      }

      // Partner line - log and generate with robust retry
      console.log(`[tts] Partner line (scene line ${i}): ${ln.character} - "${ln.text.slice(0, 40)}..."`);

      const v = voiceMap[ln.character] || voiceMap["UNKNOWN"] || "alloy";
      const audio = await ttsToBufferRobust(ln.text, v, i);

      const segPath = path.join(tmpDir, `seg-${String(segmentIndex).padStart(3, "0")}.mp3`);
      fs.writeFileSync(segPath, audio);
      segmentFiles.push(segPath);
      console.log(`[tts] Wrote segment ${segmentIndex}: ${segPath} (${audio.length} bytes)`);
      segmentIndex++;

      // Add gap(s) after partner line
      const gap = await getGapBuffer(v);
      for (let j = 0; j < repeats; j++) {
        const gapPath = path.join(tmpDir, `seg-${String(segmentIndex).padStart(3, "0")}.mp3`);
        fs.writeFileSync(gapPath, gap);
        segmentFiles.push(gapPath);
        segmentIndex++;
      }
    }

    console.log(`[tts] Generated ${segmentFiles.length} segments, concatenating with ffmpeg`);

    // Prepend lead silence to prevent first-frame clipping
    const leadSilencePath = path.join(tmpDir, "lead_silence.mp3");
    const ffmpegBin = ffmpegPath || "ffmpeg";
    await new Promise<void>((resolve, reject) => {
      const proc = spawn(ffmpegBin, [
        "-hide_banner",
        "-loglevel", "error",
        "-f", "lavfi",
        "-i", "anullsrc=r=44100:cl=mono",
        "-t", "0.35",
        "-q:a", "9",
        "-y",
        leadSilencePath,
      ]);

      proc.on("close", (code) => {
        if (code === 0) {
          resolve();
        } else {
          reject(new Error(`ffmpeg silence generation failed with code ${code}`));
        }
      });

      proc.on("error", (err) => {
        reject(err);
      });
    });

    segmentFiles.unshift(leadSilencePath);
    console.log(`[tts] prepended lead silence 0.35s`);

    // Create ffmpeg concat list file
    const concatListPath = path.join(tmpDir, "concat.txt");
    const concatList = segmentFiles.map(f => `file '${f}'`).join("\n");
    fs.writeFileSync(concatListPath, concatList);

    // Always re-encode to ensure proper MP3 headers for iOS Safari compatibility
    // Try libmp3lame first, then libshine fallback. No Buffer.concat - fail visibly.
    let ffmpegResult = await runFFmpegConcat(concatListPath, outPath, "libmp3lame");

    if (!ffmpegResult.success) {
      console.log(`[tts] ffmpeg libmp3lame failed, retrying with libshine`);
      ffmpegResult = await runFFmpegConcat(concatListPath, outPath, "libshine");
    }

    if (!ffmpegResult.success) {
      // All ffmpeg attempts failed - throw to surface error visibly
      const errorSnippet = ffmpegResult.error?.slice(0, 200) || "unknown";
      console.error(`[tts] render failed reason=ffmpeg_concat_failed stderr="${errorSnippet}"`);
      throw new Error(`ffmpeg concat failed after libmp3lame+libshine: ${errorSnippet}`);
    }

    const outBytes = fs.statSync(outPath).size;
    console.log(`[tts] assembled mp3 via ffmpeg reencode encoder=${ffmpegResult.mode} bytes=${outBytes}`);

    return outPath;
  } finally {
    // Clean up temp files (best effort)
    try {
      if (fs.existsSync(tmpDir)) {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    } catch (cleanupErr) {
      console.warn(`[tts] Cleanup failed for ${tmpDir}:`, cleanupErr);
    }
  }
}

/**
 * Run ffmpeg concat and return success/failure.
 */
async function runFFmpegConcat(
  concatListPath: string,
  outPath: string,
  encoder: "libmp3lame" | "libshine"
): Promise<{ success: boolean; mode: string; error?: string }> {
  const ffmpegBin = ffmpegPath || "ffmpeg";

  return new Promise((resolve) => {
    const args = [
      "-hide_banner",
      "-loglevel", "error",
      "-f", "concat",
      "-safe", "0",
      "-i", concatListPath,
      "-c:a", encoder,
      "-ar", "44100",
      "-ac", "1",
      "-q:a", "4",
      "-write_xing", "1",
      "-id3v2_version", "3",
      "-y", outPath,
    ];

    const proc = spawn(ffmpegBin, args);
    let stderr = "";

    proc.stderr?.on("data", (chunk) => {
      stderr += chunk.toString();
    });

    proc.on("close", (code) => {
      if (code === 0) {
        resolve({ success: true, mode: encoder });
      } else {
        const errorSnippet = stderr.slice(0, 400);
        console.error(`[tts] ffmpeg (${encoder}) error: ${errorSnippet}`);
        resolve({ success: false, mode: encoder, error: errorSnippet });
      }
    });

    proc.on("error", (err) => {
      console.error(`[tts] ffmpeg (${encoder}) spawn error:`, err);
      resolve({ success: false, mode: encoder, error: err.message });
    });
  });
}
