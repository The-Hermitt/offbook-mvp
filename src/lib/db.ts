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

export default db;
