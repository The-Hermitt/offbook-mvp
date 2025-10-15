// src/http-routes.ts
import { Router } from "express";
import fs from "node:fs";
import path from "node:path";

import {
  insertScript, insertScene, insertLine,
  getScenes, countScenes, countLines, getLines,
  upsertVoices, createRender, completeRender, getRender, failRender, getVoiceFor,
} from "./lib/db.js";

import { downloadPDF, parsePDF } from "./lib/pdf.js";
import { generateReaderMp3, ttsProvider } from "./lib/tts.js";

const router = Router();

function ensureDir(p: string) { fs.mkdirSync(p, { recursive: true }); }
function rendersDir() {
  const p = path.join(process.cwd(), "assets", "renders");
  ensureDir(p);
  return p;
}

router.get("/", (_req, res) => {
  res.json({ ok: true, routes: [
    "upload_script",
    "scenes",
    "set_voice",
    "render",
    "render_status",
    "render_inspect",
    "tts_info",
    "play" // ← now present
  ]});
});

// quick probe to see which TTS provider is active
router.get("/tts_info", (_req, res) => {
  res.json({ provider: ttsProvider() });
});

/**
 * POST /debug/upload_script
 * { pdf_url, title } -> { script_id, title, scene_count }
 */
router.post("/upload_script", async (req, res) => {
  try {
    const { pdf_url, title } = req.body || {};
    if (!pdf_url || !title) return res.status(400).json({ error: "missing pdf_url or title" });

    if (!/^https:\/\//i.test(String(pdf_url))) {
      return res.status(400).json({ error: "Only https: URLs are allowed for pdf_url" });
    }

    const pdfPath = await downloadPDF(pdf_url);
    const buf = fs.readFileSync(pdfPath);
    const parsed: any = await parsePDF(buf);

    if (!parsed || !Array.isArray(parsed.scenes)) {
      return res.status(500).json({
        error: "upload_script failed",
        message: "Parser returned unexpected shape (no scenes array).",
      });
    }

    const script_id = insertScript(String(title), String(pdfPath));

    let sOrd = 0;
    for (const scene of parsed.scenes) {
      const scene_id = insertScene(script_id, String(scene?.title ?? `Scene ${sOrd + 1}`), sOrd++);
      let lOrd = 0;
      const lines = Array.isArray(scene?.lines) ? scene.lines : [];
      for (const ln of lines) {
        insertLine(scene_id, String(ln?.character ?? "UNKNOWN"), String(ln?.text ?? ""), lOrd++);
      }
    }

    res.json({ script_id, title, scene_count: countScenes(script_id) });
  } catch (e: any) {
    res.status(500).json({
      error: "upload_script failed",
      message: String(e?.message || e),
      body_seen: req.body,
    });
  }
});

/**
 * GET /debug/scenes?script_id=...
 */
router.get("/scenes", (req, res) => {
  try {
    const script_id = String(req.query.script_id || "");
    if (!script_id) return res.status(400).json({ error: "missing script_id" });

    const scenes = getScenes(script_id).map(s => ({
      id: s.id, title: s.title, ord: s.ord, line_count: countLines(s.id),
    }));
    res.json({ script_id, scenes });
  } catch (e: any) {
    res.status(500).json({ error: "scenes failed", message: String(e?.message || e) });
  }
});

/**
 * POST /debug/set_voice
 * { script_id, voice_map }
 */
router.post("/set_voice", (req, res) => {
  try {
    const { script_id, voice_map } = req.body || {};
    if (!script_id || !voice_map || typeof voice_map !== "object") {
      return res.status(400).json({ error: "missing script_id or voice_map" });
    }
    upsertVoices(String(script_id), voice_map);
    res.json({ ok: true });
  } catch (e: any) {
    res.status(500).json({ error: "set_voice failed", message: String(e?.message || e) });
  }
});

/**
 * POST /debug/render  (ASYNC)
 * { script_id, scene_id, role, pace } -> { render_id, status: "pending" }
 */
router.post("/render", (req, res) => {
  try {
    const { script_id, scene_id, role, pace } = req.body || {};
    if (!script_id || !scene_id || !role) {
      return res.status(400).json({ error: "missing script_id, scene_id, or role" });
    }

    const render_id = createRender(String(script_id), String(scene_id), String(role), String(pace ?? "normal"));

    // background job
    setImmediate(async () => {
      try {
        const lines = getLines(String(scene_id));
        const voiceMap: Record<string, string> = {};
        const chars = Array.from(new Set(lines.map(l => l.character)));
        for (const c of chars) voiceMap[c] = getVoiceFor(String(script_id), c) || "alloy";
        if (!voiceMap["UNKNOWN"]) voiceMap["UNKNOWN"] = "alloy";

        const outPath = await generateReaderMp3(
          lines.map(l => ({ character: l.character, text: l.text })),
          voiceMap,
          String(role),
          (String(pace ?? "normal") as "slow"|"normal"|"fast")
        );
        completeRender(render_id, outPath);
      } catch (err: any) {
        failRender(render_id, String(err?.message || err));
      }
    });

    res.json({ render_id, status: "pending" });
  } catch (e: any) {
    res.status(500).json({ error: "render failed", message: String(e?.message || e) });
  }
});

/**
 * GET /debug/render_status?render_id=...
 */
router.get("/render_status", (req, res) => {
  try {
    const render_id = String(req.query.render_id || "");
    if (!render_id) return res.status(400).json({ error: "missing render_id" });

    const r = getRender(render_id);
    if (!r) return res.status(404).json({ error: "render not found" });

    const payload: any = { render_id, status: r.status };
    if (r.status === "complete" && r.audio_path) {
      payload.download_url = `/api/assets/${render_id}`;
    }
    if (r.status === "error") payload.message = r.message || "unknown error";
    res.json(payload);
  } catch (e: any) {
    res.status(500).json({ error: "render_status failed", message: String(e?.message || e) });
  }
});

/**
 * GET /debug/render_inspect?render_id=...
 */
router.get("/render_inspect", (req, res) => {
  try {
    const render_id = String(req.query.render_id || "");
    if (!render_id) return res.status(400).json({ error: "missing render_id" });

    const r = getRender(render_id);
    if (!r) return res.status(404).json({ error: "render not found" });

    const audio_path = r.audio_path ? path.resolve(r.audio_path) : null;
    const exists = audio_path ? fs.existsSync(audio_path) : false;
    const size = exists && audio_path ? fs.statSync(audio_path).size : 0;

    res.json({
      render_id,
      status: r.status,
      audio_path,
      exists,
      size_bytes: size,
      download_url: exists ? `/api/assets/${render_id}` : null,
    });
  } catch (e: any) {
    res.status(500).json({ error: "render_inspect failed", message: String(e?.message || e) });
  }
});

/**
 * GET /debug/play?render_id=...
 * Tiny HTML page with an <audio> player for your phone.
 */
router.get("/play", (req, res) => {
  const render_id = String(req.query.render_id || "");
  const assetPath = render_id ? `/api/assets/${render_id}` : "";
  const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>OffBook Player</title>
<style>
  body { font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial; padding: 24px; max-width: 640px; margin: 0 auto; }
  .card { border: 1px solid #e5e7eb; border-radius: 12px; padding: 20px; box-shadow: 0 2px 12px rgba(0,0,0,0.04);}
  input, button { font-size: 16px; padding: 10px 12px; border-radius: 10px; border: 1px solid #d1d5db; }
  button { background: #111827; color: white; border: none; }
  label { display:block; font-weight: 600; margin-bottom: 6px; }
  .row { display:flex; gap:8px; }
  audio { width:100%; margin-top: 16px; }
  small { color:#6b7280; }
</style>
</head>
<body>
  <h1>OffBook – Player</h1>
  <div class="card">
    <form action="/debug/play" method="get">
      <label for="render_id">Render ID</label>
      <div class="row">
        <input id="render_id" name="render_id" type="text" value="${render_id}" placeholder="paste render_id" style="flex:1" required/>
        <button type="submit">Load</button>
      </div>
      <small>After rendering, paste the <code>render_id</code> here, tap Load, then Play.</small>
    </form>
    ${assetPath ? `<audio controls src="${assetPath}" preload="metadata"></audio>` : ""}
  </div>
</body>
</html>`;
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(html);
});

export default router;
