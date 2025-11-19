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

export default db;

export function getDB() {
  return db;
}
