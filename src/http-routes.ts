// @ts-nocheck
// src/http-routes.ts
//
// REST debug harness used by curl/Postman and also by the MCP proxy.
// Endpoints:
//   POST   /debug/upload_script            { pdf_url, title }
//   GET    /debug/scenes?script_id=...     -> { script_id, scenes:[...] }
//   POST   /debug/set_voice                { script_id, voice_map{CHAR:VOICE} }
//   POST   /debug/render                   { script_id, scene_id, role, pace }
//   GET    /debug/render_status?render_id=...

import { Router } from 'express';
import path from 'path';
import fs from 'fs';
import { nanoid } from 'nanoid';
import { z } from 'zod';

type Scene = { id: string; title: string; lines: Array<{ speaker: string; text: string }> };
type ScriptRec = { id: string; title: string; scenes: Scene[]; voice_map: Record<string, string> };
type RenderRec = { id: string; script_id: string; scene_id: string; status: 'pending'|'complete'|'error'; filepath?: string };

const mem = {
  scripts: new Map<string, ScriptRec>(),
  renders: new Map<string, RenderRec>(),
};

// --- Validation
const UploadSchema = z.object({ pdf_url: z.string().url(), title: z.string().min(1).max(200) });
const ScenesSchema = z.object({ script_id: z.string().min(1) });
const NonEmptyRecord = <T extends z.ZodTypeAny>(schema: T) =>
  z.record(schema).refine((o) => Object.keys(o).length > 0, { message: 'voice_map must have at least one entry' });
const SetVoiceSchema = z.object({ script_id: z.string().min(1), voice_map: NonEmptyRecord(z.string().min(1)) });
const RenderSchema = z.object({
  script_id: z.string().min(1),
  scene_id: z.string().min(1),
  role: z.string().min(1),
  pace: z.enum(['slow', 'normal', 'fast']).default('normal'),
});
const StatusSchema = z.object({ render_id: z.string().min(1) });

// --- Stub parser (stable for MVP)
async function parseStub(_pdf_url: string): Promise<Scene[]> {
  return [
    {
      id: 'scene-1',
      title: 'Stub Scene',
      lines: [
        { speaker: 'UNKNOWN', text: 'Hello there.' },
        { speaker: 'UNKNOWN', text: 'This is a stub line for MVP.' },
      ],
    },
  ];
}

// --- TTS (OpenAI if key present; tiny stub otherwise)
async function synthesizeMp3(text: string, voice: string): Promise<Buffer> {
  if (process.env.OPENAI_API_KEY) {
    const { default: OpenAI } = await import('openai');
    const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
    const resp = await openai.audio.speech.create({
      model: 'gpt-4o-mini-tts',
      voice: voice || 'alloy',
      input: text || 'This is a test line.',
      format: 'mp3',
    } as any);
    const arr = await resp.arrayBuffer();
    return Buffer.from(arr);
  }
  // Tiny valid-ish MP3 header (stub)
  return Buffer.from('4944330300000000000f544954320000000000035465737400', 'hex');
}

function ensureRenderDir() {
  const dir = path.join(process.cwd(), 'assets', 'renders');
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

const router = Router();

router.post('/upload_script', async (req, res) => {
  try {
    const { pdf_url, title } = UploadSchema.parse(req.body || {});
    const scenes = await parseStub(pdf_url);
    const id = nanoid();
    mem.scripts.set(id, { id, title, scenes, voice_map: {} });
    res.json({ script_id: id, title, scene_count: scenes.length });
  } catch (e: any) {
    res.status(400).json({ error: e?.message || String(e) });
  }
});

router.get('/scenes', (req, res) => {
  try {
    const { script_id } = ScenesSchema.parse({ script_id: req.query.script_id });
    const rec = mem.scripts.get(script_id);
    if (!rec) return res.status(404).json({ error: 'script not found' });
    res.json({ script_id, scenes: rec.scenes });
  } catch (e: any) {
    res.status(400).json({ error: e?.message || String(e) });
  }
});

router.post('/set_voice', (req, res) => {
  try {
    const { script_id, voice_map } = SetVoiceSchema.parse(req.body || {});
    const rec = mem.scripts.get(script_id);
    if (!rec) return res.status(404).json({ error: 'script not found' });
    rec.voice_map = { ...rec.voice_map, ...voice_map };
    res.json({ ok: true });
  } catch (e: any) {
    res.status(400).json({ error: e?.message || String(e) });
  }
});

router.post('/render', async (req, res) => {
  try {
    const { script_id, scene_id, role, pace } = RenderSchema.parse(req.body || {});
    const rec = mem.scripts.get(script_id);
    if (!rec) return res.status(404).json({ error: 'script not found' });
    const scene = rec.scenes.find((s) => s.id === scene_id);
    if (!scene) return res.status(404).json({ error: 'scene not found' });

    const render_id = nanoid();
    const render: RenderRec = { id: render_id, script_id, scene_id, status: 'pending' };
    mem.renders.set(render_id, render);

    const partnerLines = scene.lines.filter((l) => l.speaker !== role).map((l) => l.text).join(' ');
    const voice = rec.voice_map['UNKNOWN'] || 'alloy';
    const buf = await synthesizeMp3(partnerLines || 'Partner lines are empty.', voice);

    const dir = ensureRenderDir();
    const fp = path.join(dir, `${render_id}.mp3`);
    fs.writeFileSync(fp, buf);

    render.status = 'complete';
    render.filepath = fp;

    res.json({ render_id, status: render.status });
  } catch (e: any) {
    res.status(400).json({ error: e?.message || String(e) });
  }
});

router.get('/render_status', (req, res) => {
  try {
    const { render_id } = StatusSchema.parse({ render_id: req.query.render_id });
    const r = mem.renders.get(render_id);
    if (!r) return res.status(404).json({ error: 'render not found' });
    const download_url = r.status === 'complete' ? `/api/assets/${render_id}` : undefined;
    res.json({ render_id, status: r.status, download_url });
  } catch (e: any) {
    res.status(400).json({ error: e?.message || String(e) });
  }
});

export default router;
