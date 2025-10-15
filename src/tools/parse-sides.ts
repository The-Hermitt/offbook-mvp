// src/tools/parse-sides.ts
import { db } from "../lib/db.js";

/**
 * Supports both styles:
 *   parseSides("abc123")
 *   parseSides({ script_id: "abc123" })
 * If no script_id is provided, falls back to the most recent script.
 */
export async function parseSides(
  paramsOrId?: { script_id?: string } | string
): Promise<
  | {
      ok: true;
      script_id: string;
      title: string;
      scenes: Array<{ id: string; scene_number: number; characters: string[]; line_count: number }>;
      characters: string[];
      scene_count: number;
    }
  | { ok: false; error: string }
> {
  // Normalize args -> scriptId
  let scriptId = "";
  if (typeof paramsOrId === "string") {
    scriptId = paramsOrId.trim();
  } else if (paramsOrId && typeof paramsOrId === "object" && paramsOrId.script_id) {
    scriptId = String(paramsOrId.script_id).trim();
  }

  // Fallback: latest script
  if (!scriptId) {
    const latest = db
      .prepare(`SELECT id, title, created_at FROM scripts ORDER BY created_at DESC LIMIT 1`)
      .get() as { id: string; title: string; created_at: number } | undefined;
    if (!latest) return { ok: false, error: "No scripts found. Upload a script first." };
    scriptId = latest.id;
  }

  // Load script
  const script = db
    .prepare(`SELECT id, title FROM scripts WHERE id = ?`)
    .get(scriptId) as { id: string; title: string } | undefined;
  if (!script) return { ok: false, error: `Script ${scriptId} not found.` };

  // Load scenes
  const rows = db
    .prepare(
      `SELECT id, scene_number, characters, lines
         FROM scenes
        WHERE script_id = ?
        ORDER BY scene_number ASC`
    )
    .all(scriptId) as Array<{ id: string; scene_number: number; characters: string; lines: string }>;

  const scenes = rows.map((r) => {
    const chars = JSON.parse(r.characters || "[]") as string[];
    const lines = JSON.parse(r.lines || "[]") as Array<{ idx: number; char: string; text: string }>;
    return { id: r.id, scene_number: r.scene_number, characters: chars, line_count: lines.length };
  });

  const allCharacters = Array.from(new Set(scenes.flatMap((s) => s.characters || [])));

  return {
    ok: true,
    script_id: script.id,
    title: script.title,
    scenes,
    characters: allCharacters,
    scene_count: scenes.length,
  };
}
