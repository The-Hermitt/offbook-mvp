import { z } from 'zod';
import { db } from '../lib/db.js';
import { normalizeChar } from '../lib/normalize.js';

export const setVoiceSchema = z.object({
  script_id: z.string(),
  voice_map: z.record(z.string())
});

const ALLOWED_VOICES = ['alloy', 'verse', 'nova', 'aria'];
const DEFAULT_VOICE = 'alloy';

export function setVoice(params: z.infer<typeof setVoiceSchema>) {
  const { script_id, voice_map } = params;

  const script = db.prepare('SELECT id FROM scripts WHERE id = ?').get(script_id);
  if (!script) {
    throw new Error(`Script ${script_id} not found`);
  }

  const normalized: Record<string, string> = {};
  for (const [char, voice] of Object.entries(voice_map)) {
    const normalizedChar = normalizeChar(char);
    const validVoice = ALLOWED_VOICES.includes(voice) ? voice : DEFAULT_VOICE;
    normalized[normalizedChar] = validVoice;
  }

  db.prepare(
    `INSERT INTO voice_configs (script_id, voice_map, updated_at)
     VALUES (?, ?, unixepoch())
     ON CONFLICT(script_id) DO UPDATE SET voice_map = excluded.voice_map, updated_at = unixepoch()`
  ).run(script_id, JSON.stringify(normalized));

  return { ok: true, voice_map: normalized };
}
