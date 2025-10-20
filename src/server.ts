// src/server.ts
import express from 'express';
import path from 'path';
import cors from 'cors';
import { fileURLToPath } from 'url';
import { attachDebugRoutes, attachAssetRoutes } from './http-routes.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.set('trust proxy', true);

// Basic middleware
app.use(cors());
app.use(express.json({ limit: '4mb' }));
app.use(express.urlencoded({ extended: true, limit: '4mb' }));

// Static UI
const publicDir = path.join(__dirname, '..', 'public');
app.use(express.static(publicDir));

// Health checks
app.get('/health', (req, res) => { res.json({ ok: true }); });
app.get('/health/tts', (req, res) => {
  const provider = process.env.OPENAI_API_KEY ? 'openai' : 'stub';
  const has_key = !!process.env.OPENAI_API_KEY;
  res.json({ provider, has_key });
});

// Shared secret (optional)
const SHARED_SECRET = process.env.SHARED_SECRET || '';

// Attach routes
attachDebugRoutes(app, { sharedSecret: SHARED_SECRET });
attachAssetRoutes(app);

// Default route
app.get('/', (req, res) => {
  res.sendFile(path.join(publicDir, 'app-tabs.html'));
});

// Global error safety nets (avoid process crash → 502)
process.on('uncaughtException', (err) => {
  console.error('[fatal] uncaughtException:', err);
});
process.on('unhandledRejection', (reason) => {
  console.error('[fatal] unhandledRejection:', reason);
});

// Start server
const PORT = process.env.PORT ? Number(process.env.PORT) : 10000;
app.listen(PORT, () => {
  console.log(`[offbook] listening on ${PORT}`);
});

export default app;
