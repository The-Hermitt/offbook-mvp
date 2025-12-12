import OpenAI, { toFile } from "openai";
import * as fs from "fs";
import * as path from "path";

const OPENAI_API_KEY = process.env.OPENAI_API_KEY || "";

// Optional STT: if there is no key, we treat STT as disabled.
const openai = OPENAI_API_KEY ? new OpenAI({ apiKey: OPENAI_API_KEY }) : null;

export function isSttEnabled(): boolean {
  return !!openai;
}

export interface TranscribeChunkOptions {
  // Raw audio data as a Node.js Buffer
  audio: Buffer;
  // Browser-reported mime type, e.g. "audio/webm;codecs=opus" or "audio/mp4"
  mime?: string;
  // Reserved for future use
  prompt?: string;
}

export interface TranscribeChunkResult {
  text: string;
}

/**
 * Normalize a raw mime string coming from the browser.
 * - Strips off any ";codecs=..." suffix
 * - Maps common aliases to a canonical form
 */
function normalizeMime(raw?: string): string {
  if (typeof raw !== "string" || !raw.trim()) {
    return "audio/webm";
  }
  const base = raw.toLowerCase().split(";")[0].trim();

  switch (base) {
    // MP3 / MPEG
    case "audio/mpeg":
    case "video/mpeg":
      return "audio/mp3";

    // AAC-style audio that should be treated as mp4/m4a
    case "audio/m4a":
    case "audio/aac":
      return "audio/mp4";

    // MP4 containers (Safari often reports video/mp4 even for “audio only”)
    case "audio/mp4":
    case "video/mp4":
      return "audio/mp4";

    // WebM containers (can come back as audio/webm or video/webm)
    case "audio/webm":
    case "video/webm":
      return "audio/webm";

    // Ogg containers
    case "audio/ogg":
    case "video/ogg":
      return "audio/ogg";

    // Plain WAV
    case "audio/wav":
      return "audio/wav";

    default:
      // Safe fallback that OpenAI supports
      return "audio/webm";
  }
}

/**
 * Choose a file extension that matches the (normalized) mime type.
 * This matters because OpenAI can reject files when the extension
 * doesn't match the actual audio format.
 */
function extensionFromMime(mime: string): string {
  const base = mime.toLowerCase().split(";")[0].trim();

  switch (base) {
    case "audio/mp3":
    case "audio/mpeg":
      return "mp3";
    case "audio/mp4":
    case "audio/m4a":
      return "m4a";
    case "audio/ogg":
      return "ogg";
    case "audio/wav":
      return "wav";
    case "audio/webm":
    default:
      return "webm";
  }
}

/**
 * Transcribe a single audio chunk.
 * Called by /debug/stt_transcribe_chunk with a raw Buffer + mime string.
 */
export async function transcribeChunk(
  opts: TranscribeChunkOptions
): Promise<TranscribeChunkResult> {
  if (!openai) {
    throw new Error("stt_disabled");
  }

  const { audio, mime } = opts;

  if (!audio || !Buffer.isBuffer(audio) || audio.length === 0) {
    throw new Error("missing_audio");
  }

  // Make sure mime + extension line up with the real format
  const safeMime = normalizeMime(mime);
  const ext = extensionFromMime(safeMime);
  const filename = `chunk.${ext}`;

  console.log(
    "[stt] transcribeChunk input:",
    {
      rawMime: mime || null,
      safeMime,
      ext,
      bytes: audio.length,
    }
  );

  if (process.env.NODE_ENV === "development") {
    try {
      const outDir = path.join(process.cwd(), "tmp_stt2");
      await fs.promises.mkdir(outDir, { recursive: true });

      const debugFilename =
        `${Date.now()}-${Math.random().toString(36).slice(2)}.${ext}`;
      const debugPath = path.join(outDir, debugFilename);

      await fs.promises.writeFile(debugPath, audio);

      console.log("[stt] wrote debug audio file:", {
        path: debugPath,
        bytes: audio.length,
        safeMime,
      });
    } catch (err) {
      console.warn("[stt] failed to write debug audio file:", err);
    }
  }

  // Wrap the buffer in a File-like object for the OpenAI SDK
  const file = await toFile(audio, filename, {
    type: safeMime,
  });

  const resp = await openai.audio.transcriptions.create({
    file,
    model: "whisper-1",
  });

  const text = ((resp as any).text || "").trim();
  return { text };
}
