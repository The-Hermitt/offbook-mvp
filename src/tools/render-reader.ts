import { z } from 'zod';
import { db } from '../lib/db.js';
import { generateAudio } from '../lib/tts.js';
import { normalizeChar } from '../lib/normalize.js';
import { nanoid } from 'nanoid';

export const renderReaderSchema = z.object({
  script_id: z.string(),
  scene_id: z.string(),
  role: z.string(),
  pace: z.enum(['slow', 'normal', 'fast']).default('normal')
});

export async function renderReader(params: z.infer<typeof renderReaderSchema>) {
  const { script_id, scene_id, role, pace } = params;

  const scene = db.prepare(
    'SELECT id, lines FROM scenes WHERE id = ? AND script_id = ?'
  ).get(scene_id, script_id) as { id: string; lines: string } | undefined;

  if (!scene) {
    throw new Error(`Scene ${scene_id} not found in script ${script_id}`);
  }

  const lines = JSON.parse(scene.lines) as Array<{ idx: number; char: string; text: string }>;
  const normalizedRole = normalizeChar(role);

  const partnerLines = lines.filter(line => {
    const normalizedChar = normalizeChar(line.char);
    return normalizedChar !== normalizedRole;
  });

  const voiceConfigRow = db.prepare(
    'SELECT voice_map FROM voice_configs WHERE script_id = ?'
  ).get(script_id) as { voice_map: string } | undefined;

  const voiceMap = voiceConfigRow ? JSON.parse(voiceConfigRow.voice_map) : {};

  const renderId = nanoid();
  db.prepare(
    `INSERT INTO renders (id, script_id, scene_id, role, status)
     VALUES (?, ?, ?, ?, 'pending')`
  ).run(renderId, script_id, scene_id, normalizedRole);

  try {
    const audioPath = await generateAudio(partnerLines, voiceMap, pace);

    db.prepare(
      `UPDATE renders SET audio_path = ?, status = 'complete' WHERE id = ?`
    ).run(audioPath, renderId);

    const appUrl = process.env.APP_URL || 'http://localhost:3000';
    const downloadUrl = `${appUrl}/api/assets/${renderId}`;

    return {
      render_id: renderId,
      status: 'complete',
      download_url: downloadUrl
    };
  } catch (error) {
    db.prepare(`UPDATE renders SET status = 'failed' WHERE id = ?`).run(renderId);
    throw error;
  }
}
