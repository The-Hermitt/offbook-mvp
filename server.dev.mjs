import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import multer from "multer";
import pdfParse from "pdf-parse";

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

const app = express();
const PORT = 3010;
const SECRET = process.env.SHARED_SECRET || "1976";
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 25 * 1024 * 1024 } });

app.use(express.json({ limit: "4mb" }));

// --- Redirect root to the app with secret ---
app.get("/", (req,res)=> res.redirect(`/app-tabs.html?secret=${encodeURIComponent(SECRET)}`));

// --- Gate /debug APIs by shared secret header (from the app) ---
app.use("/debug", (req,res,next)=>{
  const s = req.get("X-Shared-Secret") || req.query.secret;
  if(s !== SECRET) return res.status(403).json({ error:"forbidden" });
  next();
});

// === In-memory script store + naive parser ===
const store = new Map(); // script_id -> { scenes }
let counter = 1;

function parseScriptText(text=""){
  const lines = String(text).split(/\r?\n/);
  const scene = { id:"sc-1", lines:[] };
  const speakers = new Set();
  for(const ln of lines){
    const m = ln.match(/^([A-Z][A-Z0-9 _'.-]+)\s*:\s*(.+)$/i);
    if(m){
      const speaker = m[1].trim().toUpperCase();
      const text    = m[2].trim();
      scene.lines.push({ speaker, text });
      speakers.add(speaker);
    }
  }
  return { scenes:[scene], speakers:[...speakers] };
}

// --- /debug/upload_script_text ---
app.post("/debug/upload_script_text", (req,res)=>{
  const { title="Sides", text="" } = req.body||{};
  const { scenes, speakers } = parseScriptText(text);
  const script_id = `scr-${counter++}`;
  store.set(script_id, { title, scenes });
  res.json({ script_id, scene_count: scenes.length, speakers, note:"ok" });
});

// --- /debug/scenes ---
app.get("/debug/scenes", (req,res)=>{
  const id = req.query.script_id;
  const rec = id && store.get(id);
  if(!rec) return res.json({ scenes: [] });
  res.json({ scenes: rec.scenes });
});

// --- /debug/set_voice (no-op) ---
app.post("/debug/set_voice", (req,res)=> res.json({ ok:true }));

// --- /debug/voices_probe ---
app.get("/debug/voices_probe", (req,res)=> res.json({ voices:["alloy","verse","aria"] }));

// === Minimal TTS mocks ===
// Generate a small 0.3s silent WAV so preloading/decoding works
function silentWav(durationSec=0.3, sampleRate=44100){
  const numFrames = Math.max(1, Math.floor(durationSec*sampleRate));
  const dataSize = numFrames * 2; // 16-bit mono
  const buf = Buffer.alloc(44 + dataSize);
  buf.write("RIFF",0); buf.writeUInt32LE(36+dataSize,4);
  buf.write("WAVEfmt ",8); buf.writeUInt32LE(16,16); // PCM chunk size
  buf.writeUInt16LE(1,20);  // PCM
  buf.writeUInt16LE(1,22);  // mono
  buf.writeUInt32LE(sampleRate,24);
  buf.writeUInt32LE(sampleRate*2,28); // byte rate
  buf.writeUInt16LE(2,32);  // block align
  buf.writeUInt16LE(16,34); // bits/sample
  buf.write("data",36); buf.writeUInt32LE(dataSize,40);
  // audio data remains zero (silence)
  return buf;
}
app.get("/mock-tts/:id.wav", (req,res)=>{
  res.set("Content-Type","audio/wav");
  res.send(silentWav(0.3));
});

// --- /debug/tts_line -> return a URL to our silent wav ---
app.post("/debug/tts_line", (req,res)=>{
  const url = `/mock-tts/${Date.now()}.wav`;
  res.json({ url });
});

// --- /debug/render & status (mock combined reader track) ---
const renders = new Map(); // id -> { ready:boolean, url }
app.post("/debug/render", (req,res)=>{
  const render_id = `rnd-${Date.now()}`;
  const url = `/mock-tts/reader-${Date.now()}.wav`;
  renders.set(render_id, { ready:false, url });
  setTimeout(()=>{ const r=renders.get(render_id); if(r){ r.ready=true; } }, 800); // short delay
  res.json({ render_id });
});
app.get("/debug/render_status", (req,res)=>{
  const r = renders.get(req.query.render_id);
  if(!r) return res.json({ status:"error", error:"unknown render_id" });
  if(r.ready) return res.json({ status:"complete", download_url: r.url });
  res.json({ status:"working" });
});

// --- Upload PDF ---
app.post("/debug/upload_script_upload", upload.single("pdf"), async (req,res)=>{
  const f = req.file;
  console.log("[pdf-upload]", f?.originalname, f?.mimetype, f?.size);
  if(!f || !(f.buffer?.length)) return res.status(400).json({ error:"no-file" });

  try{
    const parsed = await pdfParse(f.buffer);
    const text = String(parsed?.text || "");
    const textLen = text.length;

    // naive speaker scrape to keep UI hints working
    const speakers = Array.from(new Set(
      text.split(/\r?\n/)
        .map((l)=> (l.match(/^([A-Z][A-Z0-9 _'.-]+)\s*:/)?.[1] || "").trim())
        .filter(Boolean)
    ));

    // mirror the old fast endpoint shape the UI expects
    return res.json({
      note: "fast",
      textLen,
      speakers,
      scenes: textLen > 0 ? 1 : 0,
    });
  }catch(e){
    console.error("[pdf-parse-error]", e);
    return res.status(500).json({ error: "parse-failed" });
  }
});

// --- Static files (public) ---
app.use(express.static(path.join(__dirname,"public")));

app.listen(PORT, ()=> {
  console.log(`[offbook] Dev API server on http://localhost:${PORT}`);
  console.log(`[offbook] Try: http://localhost:${PORT}/ (redirects to app with secret)`);
});
