import type { Request } from "express";
import { getDB } from "./db";

export type CreditSnapshot = {
  granted: number; // total credits ever granted
  used: number; // renders counted against this user
  remaining: number; // granted - used
};

type UsageRecord = { used: number; granted: number };
const usageByUser = new Map<string, UsageRecord>();
const accountedRenders = new Set<string>();

const memCredits: Map<string, { granted: number; used: number }> = (() => {
  const globalStore = (globalThis as any).memCredits;
  if (globalStore && globalStore instanceof Map) return globalStore;
  const map = new Map<string, { granted: number; used: number }>();
  (globalThis as any).memCredits = map;
  return map;
})();

const INCLUDED = Number(process.env.INCLUDED_RENDERS_PER_MONTH || 10);

function getUserIdFromReq(req: Request): string {
  // Try a few common places; fall back to a dev bucket
  // These can be swapped later when auth is finalized.
  // @ts-ignore
  const uid = (req as any).user?.id || (req.session as any)?.uid || (req.headers["x-user-id"] as string);
  return uid || "dev";
}

function ensureUser(uid: string): UsageRecord {
  if (!usageByUser.has(uid)) usageByUser.set(uid, { used: 0, granted: 0 });
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  return usageByUser.get(uid)!;
}

function dbGet(uid: string) {
  const db = getDB();
  const row = db.prepare(`SELECT uid, granted, used FROM credits WHERE uid = ?`).get(uid);
  if (!row) return { granted: 0, used: 0 };
  return { granted: Number(row.granted) || 0, used: Number(row.used) || 0 };
}

function dbUpsert(uid: string, grantedDelta: number, usedDelta = 0) {
  const db = getDB();
  db.prepare(
    `
    INSERT INTO credits (uid, granted, used) VALUES (?, ?, ?)
    ON CONFLICT(uid) DO UPDATE SET
      granted = credits.granted + excluded.granted,
      used    = credits.used    + excluded.used
  `,
  ).run(uid, Math.max(0, grantedDelta | 0), Math.max(0, usedDelta | 0));
  return dbGet(uid);
}

/** Return a snapshot for this uid. Unknown users are permissive (dev-friendly). */
export async function getCreditsSnapshot(uid: string): Promise<CreditSnapshot> {
  try {
    const row = dbGet(uid);
    const granted = Number(row.granted) || 0;
    const used = Number(row.used) || 0;
    const remaining = Math.max(0, granted - used);
    return { granted, used, remaining };
  } catch {
    const row = memCredits.get(uid) || { granted: 0, used: 0 };
    const granted = Number(row.granted) || 0;
    const used = Number(row.used) || 0;
    const remaining = Math.max(0, granted - used);
    return { granted, used, remaining };
  }
}

// --- Dev helpers (for local/staging testing only). Will be replaced in Task 3.
export function __dev_setCredits(uid: string, granted: number, used = 0) {
  memCredits.set(uid, { granted, used });
}
export function __dev_clear() {
  memCredits.clear();
}

export function grantTestCredits(uid: string, amount: number) {
  const rec = ensureUser(uid);
  rec.granted += amount;
}

export function noteRenderComplete(uid: string, renderId: string) {
  if (!renderId) return;
  const key = `${uid}:${renderId}`;
  if (accountedRenders.has(key)) return; // already counted
  accountedRenders.add(key);
  const rec = ensureUser(uid);
  rec.used += 1;
}

export function getSnapshot(uid: string) {
  const rec = ensureUser(uid);
  const included = INCLUDED;
  const remaining = Math.max(included + rec.granted - rec.used, 0);
  return {
    uid,
    included,
    granted: rec.granted,
    used: rec.used,
    remaining,
  };
}

export function maybeDevGrant(req: Request, uid: string) {
  // Support ?dev=1 flow for local/staging convenience
  const dev = req.query.dev === "1" || req.query.dev === 1 ? true : false;
  if (dev) grantTestCredits(uid, 200);
}

export async function devGrantCredits(uid: string, amount: number) {
  try {
    const row = dbUpsert(uid, Math.max(0, amount | 0), 0);
    const remaining = Math.max(0, row.granted - row.used);
    return { granted: row.granted, used: row.used, remaining };
  } catch {
    const row = memCredits.get(uid) || { granted: 0, used: 0 };
    row.granted = (row.granted || 0) + Math.max(0, amount | 0);
    memCredits.set(uid, row);
    const remaining = Math.max(0, row.granted - row.used);
    return { granted: row.granted, used: row.used, remaining };
  }
}

export function getUserId(req: Request) {
  return getUserIdFromReq(req);
}

// Return a safe uid string or null (shared with routes)
export function __resolveUid(req: any): string | null {
  return (
    req?.user?.id ||
    (req?.headers?.["x-user-id"] as string | undefined) ||
    (req?.headers?.["x-uid"] as string | undefined) ||
    req?.session?.uid ||
    null
  ) as string | null;
}
