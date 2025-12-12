import Database from "better-sqlite3";
import fs from "fs";
import path from "path";

const DB_PATH = process.env.SQLITE_PATH || path.join("data", "offbook.db");

// Ensure folder exists (safe in dev/Render)
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

// Reuse a single instance across reloads
const g = global as any;
export const db: Database.Database = g.__OFFBOOK_DB__ || new Database(DB_PATH);
g.__OFFBOOK_DB__ = db;

// --- Credits schema (Stripe top-ups & usage, MVP) ---
// This is safe to run on every startup; IF NOT EXISTS keeps it idempotent.
try {
  db.exec(`
    CREATE TABLE IF NOT EXISTS user_credits (
      user_id TEXT PRIMARY KEY,
      total_credits INTEGER NOT NULL DEFAULT 0,
      used_credits  INTEGER NOT NULL DEFAULT 0,
      updated_at    TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);
} catch (e) {
  // Best-effort: do not crash the server if SQLite migration fails.
  console.error("[db] failed to ensure user_credits table", e);
}

try {
  db.exec(`
    CREATE TABLE IF NOT EXISTS scripts (
      id           TEXT PRIMARY KEY,
      user_id      TEXT NOT NULL,
      title        TEXT NOT NULL,
      scene_count  INTEGER NOT NULL,
      scenes_json  TEXT NOT NULL,
      created_at   TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at   TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);
} catch (e) {
  console.error("[db] failed to ensure scripts table", e);
}

export default db;

export function getDB() {
  return db;
}
<<<<<<< HEAD
=======

function ensureGalleryTakesSchema() {
  try {
    // Look at the existing table definition, if any.
    const rows = db.prepare(`PRAGMA table_info('gallery_takes')`).all();
    const hasExisting = rows && rows.length > 0;

    // Columns we expect for the current implementation.
    const expected = [
      "id",
      "user_id",
      "script_id",
      "scene_id",
      "name",
      "mime_type",
      "size",
      "created_at",
      "note",
      "file_path",
    ];

    const missing = hasExisting
      ? expected.filter((col) => !rows.some((r: any) => r.name === col))
      : [];

    // If there is an existing table but it's missing any expected columns,
    // we treat it as legacy and drop it so we can recreate a clean one.
    if (hasExisting && missing.length > 0) {
      console.warn(
        "[db] detected legacy gallery_takes schema; dropping table. Missing:",
        missing.join(", ")
      );
      db.exec(`DROP TABLE IF EXISTS gallery_takes;`);
    }

    // Create the current schema if needed.
    db.exec(`
      CREATE TABLE IF NOT EXISTS gallery_takes (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        script_id TEXT,
        scene_id TEXT,
        name TEXT NOT NULL,
        mime_type TEXT,
        size INTEGER,
        created_at INTEGER NOT NULL,
        note TEXT,
        file_path TEXT NOT NULL
      );
    `);
  } catch (e) {
    console.error("[db] failed to ensure gallery_takes schema", e);
  }
}

// --- Gallery takes schema (per-user persistent gallery) ---
ensureGalleryTakesSchema();

export const GalleryStore = {
  listByUser(userId: string) {
    return db
      .prepare(
        `SELECT id, user_id, script_id, scene_id, name, mime_type, size, created_at, note
         FROM gallery_takes
         WHERE user_id = ?
         ORDER BY created_at DESC`
      )
      .all(userId);
  },

  getById(id: string, userId: string) {
    return db
      .prepare(
        `SELECT id, user_id, script_id, scene_id, name, mime_type, size, created_at, note, file_path
         FROM gallery_takes
        WHERE id = ? AND user_id = ?`
      )
      .get(id, userId);
  },

  save(take: {
    id: string;
    user_id: string;
    script_id?: string | null;
    scene_id?: string | null;
    name: string;
    mime_type?: string | null;
    size?: number | null;
    created_at: number;
    note?: string | null;
    file_path: string;
  }) {
    db.prepare(
      `INSERT INTO gallery_takes
         (id, user_id, script_id, scene_id, name, mime_type, size, created_at, note, file_path)
       VALUES
         (@id, @user_id, @script_id, @scene_id, @name, @mime_type, @size, @created_at, @note, @file_path)
       ON CONFLICT(id) DO UPDATE SET
         user_id = excluded.user_id,
         script_id = excluded.script_id,
         scene_id = excluded.scene_id,
         name = excluded.name,
         mime_type = excluded.mime_type,
         size = excluded.size,
         created_at = excluded.created_at,
         note = excluded.note,
         file_path = excluded.file_path`
    ).run(take);
  },
};
>>>>>>> feature/pwa-auth
