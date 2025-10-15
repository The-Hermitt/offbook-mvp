// @ts-nocheck
// src/server.ts
//
// Mounts: /health, /health/tts, /debug (if present), /mcp, /api/assets/:rid

import express from 'express';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { createMcpServer } from './mcp-server'; // no extension

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json({ limit: '5mb' }));

// --------- Optional shared-secret guard ---------
const SHARED_SECRET = process.env.SHARED_SECRET;
function requireSecret(req, res, next) {
  if (!SHARED_SECRET) return next();
  const supplied = req.get('X-Shared-Secret');
  if (supplied && supplied === SHARED_SECRET) return next();
  return res.status(401).json({ error: 'unauthorized' });
}

// --------- Health ---------
app.get('/health', (_req, res) => res.json({ ok: true }));
app.get('/health/tts', (_req, res) => {
  const hasKey = !!process.env.OPENAI_API_KEY;
  res.json({ provider: hasKey ? 'openai' : 'stub', has_key: hasKey });
});

// --------- Static (optional) ---------
const publicDir = path.join(process.cwd(), 'public');
if (fs.existsSync(publicDir)) {
  app.use(express.static(publicDir, { maxAge: '1h' }));
  console.log('[server] static /public mounted');
}

// --------- REST debug harness (optional) ---------
(async () => {
  try {
    const mod = await import('./http-routes'); // prefer default export Router
    const httpRoutes = mod.default || mod.router || null;
    if (httpRoutes) {
      app.use('/debug', requireSecret, httpRoutes);
      console.log('[server] /debug routes mounted');
    } else {
      console.warn('[server] ./http-routes present but no export found');
    }
  } catch (e) {
    console.warn('[server] ./http-routes not found (continuing without debug routes)');
  }
})();

// --------- MCP endpoint ---------
app.use('/mcp', requireSecret, createMcpServer());
console.log('[server] /mcp mounted');

// --------- Legacy asset streaming (local) ---------
app.get('/api/assets/:rid', (req, res) => {
  const rid = req.params.rid;
  const fp = path.join(process.cwd(), 'assets', 'renders', `${rid}.mp3`);
  if (!fs.existsSync(fp)) return res.status(404).json({ error: 'not found' });
  res.setHeader('Content-Type', 'audio/mpeg');
  fs.createReadStream(fp).pipe(res);
});

const PORT = Number(process.env.PORT || 3010);
const HOST = process.env.HOST || '0.0.0.0';

app.listen(PORT, HOST, () => {
  console.log(`[server] listening on http://${HOST}:${PORT}`);
  if (SHARED_SECRET) console.log('[server] shared-secret auth is ENABLED');
});
