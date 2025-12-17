// src/lib/db.ts
// Database router: delegates to Postgres (if DATABASE_URL) or SQLite (local dev)

import Database from "better-sqlite3";
import fs from "fs";
import path from "path";
import { pgExec, pgGet, pgAll, pgRun } from "./pg.js";

const DATABASE_URL = process.env.DATABASE_URL;
export const USING_POSTGRES = Boolean(DATABASE_URL);

// ---------- SQLite setup (local dev fallback) ----------
let sqliteDb: Database.Database | null = null;

function getSqliteDb(): Database.Database {
  if (!sqliteDb) {
    const DB_PATH = process.env.SQLITE_PATH || path.join("data", "offbook.db");
    fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

    const g = global as any;
    sqliteDb = g.__OFFBOOK_DB__ || new Database(DB_PATH);
    g.__OFFBOOK_DB__ = sqliteDb;

    console.log("[db] Using SQLite at", DB_PATH);
  }
  return sqliteDb;
}

// ---------- Unified async DB API ----------

export async function dbExec(sql: string): Promise<void> {
  if (USING_POSTGRES) {
    await pgExec(sql);
  } else {
    getSqliteDb().exec(sql);
  }
}

export async function dbGet<T>(sql: string, params?: any[]): Promise<T | null> {
  if (USING_POSTGRES) {
    // Convert SQLite ? placeholders to Postgres $1, $2, etc.
    const pgSql = convertPlaceholders(sql);
    return await pgGet<T>(pgSql, params);
  } else {
    const stmt = getSqliteDb().prepare(sql);
    const result = params ? stmt.get(...params) : stmt.get();
    return (result as T) || null;
  }
}

export async function dbAll<T>(sql: string, params?: any[]): Promise<T[]> {
  if (USING_POSTGRES) {
    const pgSql = convertPlaceholders(sql);
    return await pgAll<T>(pgSql, params);
  } else {
    const stmt = getSqliteDb().prepare(sql);
    const result = params ? stmt.all(...params) : stmt.all();
    return result as T[];
  }
}

export async function dbRun(sql: string, params?: any[]): Promise<{ rowCount: number; changes?: number }> {
  if (USING_POSTGRES) {
    const pgSql = convertPlaceholders(sql);
    const result = await pgRun(pgSql, params);
    return { rowCount: result.rowCount, changes: result.rowCount };
  } else {
    const stmt = getSqliteDb().prepare(sql);
    const result = params ? stmt.run(...params) : stmt.run();
    return { rowCount: result.changes, changes: result.changes };
  }
}

// Convert SQLite ? placeholders to Postgres $1, $2, etc.
function convertPlaceholders(sql: string): string {
  let index = 0;
  return sql.replace(/\?/g, () => `$${++index}`);
}

// ---------- Schema creation (Postgres-safe SQL) ----------

export async function ensureSchema(): Promise<void> {
  console.log(`[db] Ensuring schema (${USING_POSTGRES ? 'Postgres' : 'SQLite'})...`);

  try {
    // Users table (for future WebAuthn user management)
    await dbExec(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        email TEXT,
        created_at ${USING_POSTGRES ? 'TIMESTAMP DEFAULT NOW()' : "TEXT NOT NULL DEFAULT (datetime('now'))"}
      )
    `);

    // WebAuthn credentials table
    await dbExec(`
      CREATE TABLE IF NOT EXISTS webauthn_credentials (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        credential_id TEXT NOT NULL,
        public_key TEXT NOT NULL,
        counter ${USING_POSTGRES ? 'INTEGER' : 'INTEGER'} NOT NULL DEFAULT 0,
        created_at ${USING_POSTGRES ? 'TIMESTAMP DEFAULT NOW()' : "TEXT NOT NULL DEFAULT (datetime('now'))"}
      )
    `);

    // Scripts table
    await dbExec(`
      CREATE TABLE IF NOT EXISTS scripts (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        title TEXT NOT NULL,
        scene_count ${USING_POSTGRES ? 'INTEGER' : 'INTEGER'} NOT NULL,
        scenes_json TEXT NOT NULL,
        created_at ${USING_POSTGRES ? 'TIMESTAMP DEFAULT NOW()' : "TEXT NOT NULL DEFAULT (datetime('now'))"},
        updated_at ${USING_POSTGRES ? 'TIMESTAMP DEFAULT NOW()' : "TEXT NOT NULL DEFAULT (datetime('now'))"}
      )
    `);

    // Ensure is_deleted column exists
    if (USING_POSTGRES) {
      await dbExec(`
        ALTER TABLE scripts ADD COLUMN IF NOT EXISTS is_deleted BOOLEAN NOT NULL DEFAULT FALSE
      `);
      await dbExec(`
        UPDATE scripts SET is_deleted = FALSE WHERE is_deleted IS NULL
      `);
    } else {
      // SQLite: ALTER TABLE ADD COLUMN doesn't support IF NOT EXISTS
      try {
        await dbExec(`
          ALTER TABLE scripts ADD COLUMN is_deleted INTEGER NOT NULL DEFAULT 0
        `);
        console.log("[db] Added is_deleted column to scripts table");
      } catch (err: any) {
        // Ignore "duplicate column name" error
        if (!err?.message?.includes("duplicate column")) {
          throw err;
        }
      }
      await dbExec(`
        UPDATE scripts SET is_deleted = 0 WHERE is_deleted IS NULL
      `);
    }

    // User credits table
    await dbExec(`
      CREATE TABLE IF NOT EXISTS user_credits (
        user_id TEXT PRIMARY KEY,
        total_credits ${USING_POSTGRES ? 'INTEGER' : 'INTEGER'} NOT NULL DEFAULT 0,
        used_credits ${USING_POSTGRES ? 'INTEGER' : 'INTEGER'} NOT NULL DEFAULT 0,
        updated_at ${USING_POSTGRES ? 'TIMESTAMP DEFAULT NOW()' : "TEXT NOT NULL DEFAULT (datetime('now'))"}
      )
    `);

    // Gallery takes table
    await dbExec(`
      CREATE TABLE IF NOT EXISTS gallery_takes (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        script_id TEXT,
        scene_id TEXT,
        name TEXT NOT NULL,
        mime_type TEXT,
        size ${USING_POSTGRES ? 'INTEGER' : 'INTEGER'},
        created_at ${USING_POSTGRES ? 'BIGINT' : 'INTEGER'} NOT NULL,
        note TEXT,
        notes TEXT DEFAULT '',
        reader_render_id TEXT,
        file_path TEXT NOT NULL
      )
    `);

    // Audit logs table
    await dbExec(`
      CREATE TABLE IF NOT EXISTS audit_logs (
        id ${USING_POSTGRES ? 'SERIAL PRIMARY KEY' : 'INTEGER PRIMARY KEY AUTOINCREMENT'},
        user_id TEXT,
        action TEXT NOT NULL,
        resource TEXT,
        details TEXT,
        ip_address TEXT,
        user_agent TEXT,
        created_at ${USING_POSTGRES ? 'TIMESTAMP DEFAULT NOW()' : "TEXT NOT NULL DEFAULT (datetime('now'))"}
      )
    `);

    // Billing events table (for Stripe webhook idempotency)
    await dbExec(`
      CREATE TABLE IF NOT EXISTS billing_events (
        event_id TEXT PRIMARY KEY,
        event_type TEXT NOT NULL,
        user_id TEXT,
        created_at ${USING_POSTGRES ? 'TIMESTAMP DEFAULT NOW()' : "TEXT NOT NULL DEFAULT (datetime('now'))"}
      )
    `);

    // SQLite-specific: Add missing columns if needed
    if (!USING_POSTGRES) {
      await ensureGalleryTakesColumns();
    }

    console.log("[db] Schema ensured successfully");
  } catch (err) {
    console.error("[db] Failed to ensure schema:", err);
    throw err;
  }
}

// SQLite-specific: ensure gallery_takes has notes and reader_render_id columns
async function ensureGalleryTakesColumns(): Promise<void> {
  try {
    const db = getSqliteDb();
    const rows = db.prepare(`PRAGMA table_info('gallery_takes')`).all();
    const colNames = Array.isArray(rows) ? rows.map((r: any) => r.name) : [];

    if (!colNames.includes("notes")) {
      db.exec(`ALTER TABLE gallery_takes ADD COLUMN notes TEXT DEFAULT ''`);
      db.exec(`UPDATE gallery_takes SET notes = COALESCE(notes, note, '') WHERE notes IS NULL OR notes = ''`);
      console.log("[db] Added notes column to gallery_takes");
    }

    if (!colNames.includes("reader_render_id")) {
      db.exec(`ALTER TABLE gallery_takes ADD COLUMN reader_render_id TEXT`);
      console.log("[db] Added reader_render_id column to gallery_takes");
    }
  } catch (err) {
    console.error("[db] Failed to ensure gallery_takes columns:", err);
  }
}

// ---------- Legacy SQLite direct access (for existing code) ----------
// This allows existing code to keep working during incremental migration

const g = global as any;
let legacyDb: Database.Database | null = null;

if (!USING_POSTGRES) {
  legacyDb = getSqliteDb();
}

export const db = legacyDb as Database.Database;
export default db;

export function getDB() {
  if (USING_POSTGRES) {
    throw new Error("getDB() is not available when using Postgres. Use async dbGet/dbAll/dbRun instead.");
  }
  return getSqliteDb();
}

// ---------- GalleryStore (legacy sync interface for SQLite) ----------
// Will be migrated to async in next step

export const GalleryStore = {
  listByUser(userId: string) {
    if (USING_POSTGRES) {
      throw new Error("GalleryStore sync methods not available with Postgres. Use async API.");
    }
    return getSqliteDb()
      .prepare(
        `SELECT id, user_id, script_id, scene_id, name, mime_type, size, created_at, note, notes, reader_render_id
         FROM gallery_takes
         WHERE user_id = ?
         ORDER BY created_at DESC`
      )
      .all(userId);
  },

  getById(id: string, userId: string) {
    if (USING_POSTGRES) {
      throw new Error("GalleryStore sync methods not available with Postgres. Use async API.");
    }
    return getSqliteDb()
      .prepare(
        `SELECT id, user_id, script_id, scene_id, name, mime_type, size, created_at, note, notes, reader_render_id, file_path
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
    notes?: string | null;
    reader_render_id?: string | null;
    file_path: string;
  }) {
    if (USING_POSTGRES) {
      throw new Error("GalleryStore sync methods not available with Postgres. Use async API.");
    }
    const notesVal =
      typeof take.notes === "string"
        ? take.notes
        : typeof take.note === "string"
        ? take.note
        : "";
    const noteVal =
      typeof take.note === "string"
        ? take.note
        : typeof take.notes === "string"
        ? take.notes
        : null;
    const readerRenderIdVal =
      typeof take.reader_render_id === "string" && take.reader_render_id.trim()
        ? take.reader_render_id.trim()
        : null;

    getSqliteDb().prepare(
      `INSERT INTO gallery_takes
         (id, user_id, script_id, scene_id, name, mime_type, size, created_at, note, notes, reader_render_id, file_path)
       VALUES
         (@id, @user_id, @script_id, @scene_id, @name, @mime_type, @size, @created_at, @note, @notes, @reader_render_id, @file_path)
       ON CONFLICT(id) DO UPDATE SET
         user_id = excluded.user_id,
         script_id = excluded.script_id,
         scene_id = excluded.scene_id,
         name = excluded.name,
         mime_type = excluded.mime_type,
         size = excluded.size,
         created_at = excluded.created_at,
         note = excluded.note,
         notes = excluded.notes,
         reader_render_id = excluded.reader_render_id,
         file_path = excluded.file_path`
    ).run({
      ...take,
      note: noteVal,
      notes: notesVal,
      reader_render_id: readerRenderIdVal,
    });
  },

  deleteById(id: string, userId: string) {
    if (USING_POSTGRES) {
      throw new Error("GalleryStore sync methods not available with Postgres. Use async API.");
    }
    return getSqliteDb()
      .prepare(`DELETE FROM gallery_takes WHERE id = ? AND user_id = ?`)
      .run(id, userId);
  },

  updateNotes(id: string, userId: string, notes: string) {
    if (USING_POSTGRES) {
      throw new Error("GalleryStore sync methods not available with Postgres. Use async API.");
    }
    return getSqliteDb()
      .prepare(`UPDATE gallery_takes SET notes = ?, note = ? WHERE id = ? AND user_id = ?`)
      .run(notes, notes, id, userId);
  },
};
