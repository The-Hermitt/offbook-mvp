// src/lib/pg.ts
// Neon Postgres adapter using pg library

import pg from "pg";

const { Pool } = pg;

let pool: pg.Pool | null = null;

function getPool(): pg.Pool {
  if (!pool) {
    const DATABASE_URL = process.env.DATABASE_URL;
    if (!DATABASE_URL) {
      throw new Error("DATABASE_URL is not set");
    }
    pool = new Pool({
      connectionString: DATABASE_URL,
      ssl: {
        rejectUnauthorized: false, // Neon requires SSL
      },
    });
    console.log("[pg] Connected to Neon Postgres");
  }
  return pool;
}

export async function pgExec(sql: string): Promise<void> {
  const client = getPool();
  await client.query(sql);
}

export async function pgGet<T>(sql: string, params?: any[]): Promise<T | null> {
  const client = getPool();
  const result = await client.query(sql, params);
  return result.rows.length > 0 ? (result.rows[0] as T) : null;
}

export async function pgAll<T>(sql: string, params?: any[]): Promise<T[]> {
  const client = getPool();
  const result = await client.query(sql, params);
  return result.rows as T[];
}

export async function pgRun(sql: string, params?: any[]): Promise<{ rowCount: number }> {
  const client = getPool();
  const result = await client.query(sql, params);
  return { rowCount: result.rowCount || 0 };
}

export async function pgClose(): Promise<void> {
  if (pool) {
    await pool.end();
    pool = null;
    console.log("[pg] Connection pool closed");
  }
}
