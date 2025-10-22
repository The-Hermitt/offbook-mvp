// src/lib/db.ts
import fs from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";

const dataDir = path.join(process.cwd(), "data");
const dbFile = path.join(dataDir, "offbook.json");

type Script = { id: string; title: string; pdf_path: string; created_at: number };
type Scene = { id: string; script_id: string; title: string; ord: number };
type Line = { id: string; scene_id: string; character: string; text: string; ord: number };
type Voice = { script_id: string; character: string; voice: string };
type Render = {
  id: string;
  script_id: string;
  scene_id: string;
  role: string;
  pace: string;
  status: "pending" | "complete" | "error";
  audio_path?: string;
  message?: string;
  created_at: number;
};

type DBShape = {
  scripts: Script[];
  scenes: Scene[];
  lines: Line[];
  voices: Voice[];        // unique by (script_id, character)
  renders: Render[];
};

function ensureFiles() {
  fs.mkdirSync(dataDir, { recursive: true });
  if (!fs.existsSync(dbFile)) {
    const empty: DBShape = { scripts: [], scenes: [], lines: [], voices: [], renders: [] };
    fs.writeFileSync(dbFile, JSON.stringify(empty, null, 2));
  }
}
function load(): DBShape {
  ensureFiles();
  const raw = fs.readFileSync(dbFile, "utf8");
  return JSON.parse(raw) as DBShape;
}
function save(db: DBShape) {
  fs.writeFileSync(dbFile, JSON.stringify(db, null, 2));
}
function now() { return Math.floor(Date.now() / 1000); }

// --- Public API (used by routes/server) ---
export function insertScript(title: string, pdf_path: string) {
  const db = load();
  const id = randomUUID();
  db.scripts.push({ id, title, pdf_path, created_at: now() });
  save(db);
  return id;
}

export function insertScene(script_id: string, title: string, ord: number) {
  const db = load();
  const id = randomUUID();
  db.scenes.push({ id, script_id, title, ord });
  save(db);
  return id;
}

export function insertLine(scene_id: string, character: string, text: string, ord: number) {
  const db = load();
  const id = randomUUID();
  db.lines.push({ id, scene_id, character, text, ord });
  save(db);
  return id;
}

export function getScenes(script_id: string) {
  const db = load();
  return db.scenes
    .filter(s => s.script_id === script_id)
    .sort((a, b) => a.ord - b.ord);
}

export function countScenes(script_id: string) {
  const db = load();
  return db.scenes.filter(s => s.script_id === script_id).length;
}

export function countLines(scene_id: string) {
  const db = load();
  return db.lines.filter(l => l.scene_id === scene_id).length;
}

export function getLines(scene_id: string) {
  const db = load();
  return db.lines
    .filter(l => l.scene_id === scene_id)
    .sort((a, b) => a.ord - b.ord);
}

export function upsertVoices(script_id: string, voice_map: Record<string, string>) {
  const db = load();
  for (const [character, voice] of Object.entries(voice_map)) {
    const idx = db.voices.findIndex(v => v.script_id === script_id && v.character === character);
    if (idx >= 0) db.voices[idx].voice = voice;
    else db.voices.push({ script_id, character, voice });
  }
  save(db);
}

export function getVoiceFor(script_id: string, character: string) {
  const db = load();
  return db.voices.find(v => v.script_id === script_id && v.character === character)?.voice;
}

export function createRender(script_id: string, scene_id: string, role: string, pace: string) {
  const db = load();
  const id = randomUUID();
  db.renders.push({
    id, script_id, scene_id, role, pace,
    status: "pending",
    created_at: now()
  });
  save(db);
  return id;
}

export function completeRender(render_id: string, audio_path: string) {
  const db = load();
  const r = db.renders.find(x => x.id === render_id);
  if (r) { r.status = "complete"; r.audio_path = audio_path; save(db); }
}

export function failRender(render_id: string, message: string) {
  const db = load();
  const r = db.renders.find(x => x.id === render_id);
  if (r) { r.status = "error"; r.message = message; save(db); }
}

export function getRender(render_id: string) {
  const db = load();
  return db.renders.find(x => x.id === render_id);
}
