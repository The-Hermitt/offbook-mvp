// src/http-routes.ts
import type { Express, Request, Response, NextFunction } from 'express';
import multer from 'multer';
import crypto from 'crypto';

// IMPORTANT: These come from our server-side PDF/text utilities.
// - parseUploadedPdf: text-only PDF extraction (no canvas); flags scannedSuspected
// - analyzeScriptText: turns raw text into scenes
import { analyzeScriptText, parseUploadedPdf } from './lib/pdf.js';

type Line = { speaker: string; text: string };
type Scene = { id: string; title: string; lines: Line[] };

type Script = {
  id: string;
  title: string;
  scenes: Scene[];
  voiceMap: Record<string, string>;
  // Meta is loose here to avoid tight coupling with lib internals.
  meta?: Record<string, unknown> | null;
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
    res.status(404).send('Not Found');
  };
}

const upload = multer({ storage: multer.memoryStorage() });

export function attachDebugRoutes(app: Express, opts: { sharedSecret: string }) {
  const { sharedSecret } = opts;
  const requireSecret = guardSecret(sharedSecret);

  /**
   * Upload text directly (Paste path).
   */
  app.post('/debug/upload_script_text', requireSecret, async (req, res) => {
    try {
      const { text = '', title = 'Script' } = (req.body || {}) as { text: string; title: string };

      // Our analyzeScriptText returns { scenes, roles }.
      const analyzed = analyzeScriptText(text || '');
      const scenes: Scene[] = analyzed.scenes as Scene[];

      const script_id = newId('script');
      const script: Script = {
        id: script_id,
        title,
        scenes,
        voiceMap: {},
        meta: { pathUsed: 'naive', rawLength: text.length }
      };
      scripts.set(script_id, script);
      res.json({ script_id, scene_count: scenes.length });
    } catch (err: any) {
      console.error('upload_script_text error:', err?.message || err);
      res.status(500).json({ error: 'upload_script_text_failed' });
    }
  });

  /**
   * Upload a PDF. The server does text-only extraction (no canvas).
   * If it suspects a scanned PDF (image-only / no text), it returns { scanned:true }.
   * The client then performs a silent, local OCR fallback and re-uploads text.
   */
  app.post('/debug/upload_script_upload', requireSecret, upload.single('pdf'), async (req, res) => {
    try {
      const title = (req.body?.title as string) || 'Script PDF';
      const buf = req.file?.buffer;
      if (!buf) return res.status(400).json({ error: 'missing_pdf' });

      // Server-side: extract TEXT ONLY, never render pages (no node-canvas).
      const { text, meta } = await parseUploadedPdf(buf);

      // If little/no text, signal the client to run its own extraction.
      // No jargon to the user; the UI will fallback automatically.
      const charCount = (text || '').replace(/\s/g, '').length;
      const scanned = !!(meta && (meta as any).scannedSuspected) || charCount < 40;
      if (scanned) {
        return res.json({ scanned: true });
      }

      // We have text; analyze into scenes.
      const analyzed = analyzeScriptText(text || '');
      const scenes: Scene[] = analyzed.scenes as Scene[];

      const script_id = newId('script');
      const script: Script = { id: script_id, title, scenes, voiceMap: {}, meta: meta as any };
      scripts.set(script_id, script);
      res.json({ script_id, scene_count: scenes.length });
    } catch (err: any) {
      console.error('upload_script_upload error:', err?.message || err);
      // Do NOT crash; the client will fallback to local extraction if it sees a failure.
      res.status(500).json({ error: 'upload_script_upload_failed' });
    }
  });

  /**
   * Fetch parsed scenes for a script.
   */
  app.get('/debug/scenes', requireSecret, (req, res) => {
    const script_id = (req.query?.script_id as string) || '';
    const script = scripts.get(script_id);
    if (!script) return res.status(404).json({ error: 'script_not_found' });
    res.json({ script_id, scenes: script.scenes });
  });

  /**
   * Simple diagnostics/preview.
   */
  app.get('/debug/preview', requireSecret, (req, res) => {
    const script_id = (req.query?.script_id as string) || '';
    const script = scripts.get(script_id);
    if (!script) return res.status(404).json({ error: 'script_not_found' });

    const roles = Array.from(
      new Set(
        script.scenes.flatMap(sc => sc.lines.map(l => l.speaker)).filter(Boolean)
      )
    );

    res.json({
      script_id,
      title: script.title,
      roles,
      meta: script.meta ?? null
    });
  });

  /**
   * Save voice selections for partner roles.
   */
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
      console.error('set_voice error:', err?.message || err);
      res.status(500).json({ error: 'set_voice_failed' });
    }
  });

  /**
   * Render stub (immediate success for MVP).
   */
  app.post('/debug/render', requireSecret, async (req, res) => {
    try {
      const { script_id, scene_id, role, pace = 'normal' } = req.body || {};
      const script = scripts.get(script_id);
      if (!script) return res.status(404).json({ error: 'script_not_found' });

      const render_id = newId('render');
      const job: RenderJob = { id: render_id, script_id, scene_id, role, pace, status: 'pending' };
      renders.set(render_id, job);

      // Immediate success for now.
      job.status = 'complete';
      job.url = `/api/assets/${render_id}`;

      res.json({ render_id, status: job.status });
    } catch (err: any) {
      console.error('render error:', err?.message || err);
      res.status(500).json({ error: 'render_failed' });
    }
  });

  app.get('/debug/render_status', requireSecret, (req, res) => {
    const render_id = (req.query?.render_id as string) || '';
    const job = renders.get(render_id);
    if (!job) return res.status(404).json({ error: 'render_not_found' });
    const payload: any = { render_id: job.id, status: job.status };
    if (job.status === 'complete' && job.url) payload.download_url = job.url;
    res.json(payload);
  });
}

/**
 * Minimal asset route (silent mp3 placeholder).
 */
export function attachAssetRoutes(app: Express) {
  app.get('/api/assets/:render_id', (req: Request, res: Response) => {
    const silence = Buffer.from('4944330300000000000F5449543200000000000053696C656E6365','hex');
    res.setHeader('Content-Type', 'audio/mpeg');
    res.setHeader('Cache-Control', 'no-store');
    res.send(silence);
  });
}
