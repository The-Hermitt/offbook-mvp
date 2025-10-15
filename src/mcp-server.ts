// @ts-nocheck
// src/mcp-server.ts
//
// HTTP MCP endpoint that proxies to the same REST debug routes.
// POST /mcp { tool, args } -> { ok, result|error }

import express from 'express';
import fetch from 'node-fetch';
import { z } from 'zod';

// ---------- Validation ----------
const UploadSchema = z.object({
  pdf_url: z.string().url(),
  title: z.string().min(1).max(200),
});
const ScenesSchema = z.object({ script_id: z.string().min(1) });
const NonEmptyRecord = <T extends z.ZodTypeAny>(schema: T) =>
  z.record(schema).refine((obj) => Object.keys(obj).length > 0, {
    message: 'voice_map must have at least one entry',
  });
const SetVoiceSchema = z.object({
  script_id: z.string().min(1),
  voice_map: NonEmptyRecord(z.string().min(1)),
});
const RenderSchema = z.object({
  script_id: z.string().min(1),
  scene_id: z.string().min(1),
  role: z.string().min(1),
  pace: z.enum(['slow', 'normal', 'fast']).default('normal'),
});
const StatusSchema = z.object({ render_id: z.string().min(1) });

// ---------- Router ----------
export function createMcpServer() {
  const router = express.Router();

  router.post('/', express.json({ limit: '2mb' }), async (req, res) => {
    try {
      const { tool, args } = req.body || {};
      if (!tool || typeof tool !== 'string') {
        return res.status(400).json({ ok: false, error: 'missing tool' });
      }

      const PORT = process.env.PORT || '3010';
      const BASE = `http://127.0.0.1:${PORT}/debug`;

      const secret = req.get('X-Shared-Secret');
      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      if (secret) headers['X-Shared-Secret'] = secret;

      switch (tool) {
        case 'upload_script': {
          const data = UploadSchema.parse(args || {});
          const r = await fetch(`${BASE}/upload_script`, { method: 'POST', headers, body: JSON.stringify(data) });
          return res.json({ ok: true, result: await r.json() });
        }
        case 'list_scenes': {
          const { script_id } = ScenesSchema.parse(args || {});
          const q = new URLSearchParams({ script_id }).toString();
          const r = await fetch(`${BASE}/scenes?${q}`, { headers });
          return res.json({ ok: true, result: await r.json() });
        }
        case 'set_voice': {
          const data = SetVoiceSchema.parse(args || {});
          const r = await fetch(`${BASE}/set_voice`, { method: 'POST', headers, body: JSON.stringify(data) });
          return res.json({ ok: true, result: await r.json() });
        }
        case 'render_reader': {
          const data = RenderSchema.parse(args || {});
          const r = await fetch(`${BASE}/render`, { method: 'POST', headers, body: JSON.stringify(data) });
          return res.json({ ok: true, result: await r.json() });
        }
        case 'render_status': {
          const { render_id } = StatusSchema.parse(args || {});
          const q = new URLSearchParams({ render_id }).toString();
          const r = await fetch(`${BASE}/render_status?${q}`, { headers });
          return res.json({ ok: true, result: await r.json() });
        }
        default:
          return res.status(400).json({ ok: false, error: `unknown tool: ${tool}` });
      }
    } catch (err: any) {
      return res.status(400).json({ ok: false, error: err?.message || String(err) });
    }
  });

  router.get('/tools', (_req, res) => {
    res.json({ tools: ['upload_script', 'list_scenes', 'set_voice', 'render_reader', 'render_status'] });
  });

  return router;
}
