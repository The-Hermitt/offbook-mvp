// src/http-routes.ts
import type { Express, Request, Response, NextFunction } from 'express';
import multer from 'multer';
import crypto from 'crypto';

// Reuse the parser you already have
import { analyzeScriptText, parseArrayBuffer } from './lib/pdf.js';

// Types
type Line = { speaker: string; text: string };
type Scene = { id: string; title: string; lines: Line[] };

type Script = {
  id: string;
  title: string;
  scenes: Scene[];
  voiceMap: Record<string, string>;
};

type RenderJob = {
  id: string;
  script_id: string;
  scene_id: string;
  role: string;
  pace: string;
  status: 'pending' | 'complete' | 'error';
  filePath?: string; // if you write to disk
  url?: string;      // served via /api/assets/:render_id
};

// In-memory stores (OK for MVP / Render free disk)
const scripts = new Map<string, Script>();
const renders = new Map<string, RenderJob>();

// Helpers
function newId(prefix: string): string {
  return `${prefix}_${crypto.randomBytes(8).toString('hex')}`;
}

function guardSecret(sharedSecret: string) {
  const hasSecret = !!sharedSecret;
  return (req: Request, res: Response, next: NextFunction) => {
    if (!hasSecret) return next();
    const header = req.get('X-Shared-Secret') || '';
    const qs = (req.query?.secret as string) || '';
    if (header === sharedSecret || qs === sharedSecret) return next();
    // Hide the route existence if secret mismatch
    res.status(404).send('Not Found');
  };
}

const upload = multer({ storage: multer.memoryStorage() });

// Attachors
export function attachDebugRoutes(app: Express, opts: { sharedSecret: string }) {
  const { sharedSecret } = opts;
  const requireSecret = guardSecret(sharedSecret);

  // POST /debug/upload_script_text
  app.post('/debug/upload_script_text', requireSecret, async (req, res) => {
    try {
      const { text = '', title = 'Script' } = (req.body || {}) as { text: string; title: string };
      const scenes = analyzeScriptText(text || '', /*strictColon*/ false);
      const script_id = newId('script');
      const script: Script = { id: script_id, title, scenes, voiceMap: {} };
      scripts.set(script_id, script);
      res.json({ script_id, scene_count: scenes.length });
    } catch (err: any) {
      console.error('upload_script_text error:', err?.message);
      res.status(500).json({ error: 'upload_script_text_failed' });
    }
  });

  // POST /debug/upload_script_upload (multipart: pdf + title)
  app.post('/debug/upload_script_upload', requireSecret, upload.single('pdf'), async (req, res) => {
    try {
      const title = (req.body?.title as string) || 'Script PDF';
      const buf = req.file?.buffer;
      if (!buf) return res.status(400).json({ error: 'missing_pdf' });

      const scenes = await parseArrayBuffer(buf);
      const script_id = newId('script');
      const script: Script = { id: script_id, title, scenes, voiceMap: {} };
      scripts.set(script_id, script);
      res.json({ script_id, scene_count: scenes.length });
    } catch (err: any) {
      console.error('upload_script_upload error:', err?.message);
      res.status(500).json({ error: 'upload_script_upload_failed' });
    }
  });

  // GET /debug/scenes?script_id=...
  app.get('/debug/scenes', requireSecret, (req, res) => {
    const script_id = (req.query?.script_id as string) || '';
    const script = scripts.get(script_id);
    if (!script) return res.status(404).json({ error: 'script_not_found' });
    res.json({ script_id, scenes: script.scenes });
  });

  // POST /debug/set_voice  { script_id, voice_map:{CHAR:VOICE} }
  app.post('/debug/set_voice', requireSecret, (req, res) => {
    try {
      const { script_id, voice_map } = req.body || {};
      if (!script_id || typeof voice_map !== 'object') {
        return res.status(400).json({ error: 'bad_request' });
      }
      const script = scripts.get(script_id);
      if (!script) return res.status(404).json({ error: 'script_not_found' });
      script.voiceMap = { ...script.voiceMap, ...voice_map };
      res.json({ ok: true });
    } catch (err: any) {
      console.error('set_voice error:', err?.message);
      res.status(500).json({ error: 'set_voice_failed' });
    }
  });

  // POST /debug/render  { script_id, scene_id, role, pace }
  app.post('/debug/render', requireSecret, async (req, res) => {
    try {
      const { script_id, scene_id, role, pace = 'normal' } = req.body || {};
      const script = scripts.get(script_id);
      if (!script) return res.status(404).json({ error: 'script_not_found' });

      // Minimal render job for MVP
      const render_id = newId('render');
      const job: RenderJob = {
        id: render_id,
        script_id,
        scene_id,
        role,
        pace,
        status: 'pending'
      };
      renders.set(render_id, job);

      // For MVP: mark complete immediately and serve a fake asset URL
      job.status = 'complete';
      job.url = `/api/assets/${render_id}`;

      res.json({ render_id, status: job.status });
    } catch (err: any) {
      console.error('render error:', err?.message);
      res.status(500).json({ error: 'render_failed' });
    }
  });

  // GET /debug/render_status?render_id=...
  app.get('/debug/render_status', requireSecret, (req, res) => {
    const render_id = (req.query?.render_id as string) || '';
    const job = renders.get(render_id);
    if (!job) return res.status(404).json({ error: 'render_not_found' });
    const payload: any = { render_id: job.id, status: job.status };
    if (job.status === 'complete' && job.url) payload.download_url = job.url;
    res.json(payload);
  });
}

// Serve assets from memory/dummy (MVP)
export function attachAssetRoutes(app: Express) {
  app.get('/api/assets/:render_id', (req: Request, res: Response) => {
    const { render_id } = req.params;
    const job = renders.get(render_id);
    if (!job || job.status !== 'complete') return res.status(404).send('Not Found');

    // A tiny silent mp3 buffer to keep the UI happy (1 second of silence)
    // In a real build, stream the file from disk or cloud storage (R2).
    const silence = Buffer.from(
      // Minimal MP3 silence header+frames (not pretty, but works for MVP debug)
      // If your player rejects it, replace with a static file on disk.
      '4944330300000000000F5449543200000000000053696C656E6365', // ID3 "Silence" (hex)
      'hex'
    );
    res.setHeader('Content-Type', 'audio/mpeg');
    res.setHeader('Cache-Control', 'no-store');
    res.send(silence);
  });
}
