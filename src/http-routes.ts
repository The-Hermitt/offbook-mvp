// src/http-routes.ts
import type { Express, Request, Response, NextFunction } from 'express';
import multer from 'multer';
import crypto from 'crypto';

// Parser
import { analyzeScriptText, parseArrayBuffer } from './lib/pdf.js';

// Types
type Line = { speaker: string; text: string };
type Scene = { id: string; title: string; lines: Line[] };

type Script = {
  id: string;
  title: string;
  scenes: Scene[];
  voiceMap: Record<string, string>;
  meta: {
    source: 'paste' | 'pdf';
    notes?: string;             // e.g., "no_text_extracted" | "empty_after_parse"
    roles: string[];
    roleCount: number;
    lineCount: number;
    noisy: boolean;
  };
};

type RenderJob = {
  id: string;
  script_id: string;
  scene_id: string;
  role: string;
  pace: string;
  status: 'pending' | 'complete' | 'error';
  url?: string;
};

// In-memory stores (OK for MVP)
const scripts = new Map<string, Script>();
const renders = new Map<string, RenderJob>();

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
    // Hide route existence if secret mismatch
    res.status(404).send('Not Found');
  };
}

const upload = multer({ storage: multer.memoryStorage() });

function rolesFromScenes(scenes: Scene[]): string[] {
  const set = new Set<string>();
  for (const sc of scenes) for (const ln of sc.lines || []) if (ln.speaker && ln.speaker !== 'UNKNOWN') set.add(ln.speaker);
  return Array.from(set);
}

function countLines(scenes: Scene[]): number {
  let n = 0;
  for (const sc of scenes) n += (sc.lines?.length || 0);
  return n;
}

export function attachDebugRoutes(app: Express, opts: { sharedSecret: string }) {
  const { sharedSecret } = opts;
  const requireSecret = guardSecret(sharedSecret);

  // POST /debug/upload_script_text  { text, title }
  app.post('/debug/upload_script_text', requireSecret, async (req, res) => {
    try {
      const { text = '', title = 'Script' } = (req.body || {}) as { text: string; title: string };
      const scenes = analyzeScriptText(text || '', /*strictColon*/ false);

      const script_id = newId('script');
      const roles = rolesFromScenes(scenes);
      const script: Script = {
        id: script_id,
        title,
        scenes,
        voiceMap: {},
        meta: {
          source: 'paste',
          roles,
          roleCount: roles.length,
          lineCount: countLines(scenes),
          noisy: roles.length === 0 || countLines(scenes) === 0,
        }
      };
      scripts.set(script_id, script);

      res.json({ script_id, scene_count: scenes.length, role_count: roles.length });
    } catch (err: any) {
      console.error('upload_script_text error:', err?.stack || err?.message);
      res.status(500).json({ error: 'upload_script_text_failed' });
    }
  });

  // POST /debug/upload_script_upload   (multipart: pdf + title)
  app.post('/debug/upload_script_upload', requireSecret, upload.single('pdf'), async (req, res) => {
    try {
      const title = (req.body?.title as string) || 'Script PDF';
      const buf = req.file?.buffer;
      if (!buf) return res.status(400).json({ error: 'missing_pdf' });

      // Try to parse with our PDF pipeline
      let scenes = await parseArrayBuffer(buf);

      const roles = rolesFromScenes(scenes);
      const empty = roles.length === 0 || countLines(scenes) === 0;
      const notes = empty ? 'no_text_or_no_dialogue' : undefined;

      const script_id = newId('script');
      const script: Script = {
        id: script_id,
        title,
        scenes,
        voiceMap: {},
        meta: {
          source: 'pdf',
          notes,
          roles,
          roleCount: roles.length,
          lineCount: countLines(scenes),
          noisy: empty || roles.length > 20, // crude noisy/empty flag
        }
      };
      scripts.set(script_id, script);

      res.json({ script_id, scene_count: scenes.length, role_count: roles.length });
    } catch (err: any) {
      console.error('upload_script_upload error:', err?.stack || err?.message);
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

  // NEW: GET /debug/preview?script_id=...
  // Returns: roles, counts, basic notes
  app.get('/debug/preview', requireSecret, (req, res) => {
    const script_id = (req.query?.script_id as string) || '';
    const script = scripts.get(script_id);
    if (!script) return res.status(404).json({ error: 'script_not_found' });

    const { meta } = script;
    const roles = rolesFromScenes(script.scenes);
    const payload = {
      script_id,
      source: meta?.source || 'unknown',
      roles,
      role_count: roles.length,
      line_count: countLines(script.scenes),
      noisy: meta?.noisy ?? roles.length === 0,
      notes: meta?.notes || (roles.length === 0 ? 'no_roles_detected' : undefined),
      example: roles.length === 0 ? 'Try paste format: JANE: Hello there.' : undefined,
    };
    res.json(payload);
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
      console.error('set_voice error:', err?.stack || err?.message);
      res.status(500).json({ error: 'set_voice_failed' });
    }
  });

  // POST /debug/render  { script_id, scene_id, role, pace }
  app.post('/debug/render', requireSecret, async (req, res) => {
    try {
      const { script_id, scene_id, role, pace = 'normal' } = req.body || {};
      const script = scripts.get(script_id);
      if (!script) return res.status(404).json({ error: 'script_not_found' });

      const render_id = newId('render');
      const job: RenderJob = {
        id: render_id, script_id, scene_id, role, pace, status: 'pending'
      };
      renders.set(render_id, job);

      // MVP stub: complete immediately with a fake asset
      job.status = 'complete';
      job.url = `/api/assets/${render_id}`;

      res.json({ render_id, status: job.status });
    } catch (err: any) {
      console.error('render error:', err?.stack || err?.message);
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

// Assets stub (MVP)
export function attachAssetRoutes(app: Express) {
  app.get('/api/assets/:render_id', (req: Request, res: Response) => {
    const { render_id } = req.params as any;
    const job = (renders as any).get(render_id);
    if (!job || job.status !== 'complete') return res.status(404).send('Not Found');
    const silence = Buffer.from('4944330300000000000F5449543200000000000053696C656E6365', 'hex');
    res.setHeader('Content-Type', 'audio/mpeg');
    res.setHeader('Cache-Control', 'no-store');
    res.send(silence);
  });
}
