import { dbGet, dbRun } from "./db";

// Persistent credit record for a user.
// total_credits = total purchased or granted.
// used_credits  = how many have been consumed.
// available = total_credits - used_credits (never negative).
export type UserCreditsRow = {
  user_id: string;
  total_credits: number;
  used_credits: number;
  updated_at: string;
};

// Table creation is now handled by ensureSchema() in src/lib/db.ts

// Helper to compute available credits (never negative).
export function getAvailableCredits(row: UserCreditsRow | null): number {
  if (!row) return 0;
  const remaining = row.total_credits - row.used_credits;
  return remaining > 0 ? remaining : 0;
}

export async function getUserCredits(userId: string): Promise<UserCreditsRow | null> {
  const row = await dbGet<UserCreditsRow>(
    "SELECT user_id, total_credits, used_credits, updated_at FROM user_credits WHERE user_id = ?",
    [userId]
  );
  return row || null;
}

// Upsert helper for future webhook use:
// - If the user has no row yet, create one with total_credits = max(amount, 0), used_credits = 0.
// - If the user already exists, add `amount` to total_credits (never below 0).
// Returns the fresh row.
export async function addUserCredits(userId: string, amount: number): Promise<UserCreditsRow> {
  const now = new Date().toISOString();
  const existing = await getUserCredits(userId);

  if (!existing) {
    const total = amount > 0 ? amount : 0;
    const used = 0;
    await dbRun(
      "INSERT INTO user_credits (user_id, total_credits, used_credits, updated_at) VALUES (?, ?, ?, ?)",
      [userId, total, used, now]
    );
    return {
      user_id: userId,
      total_credits: total,
      used_credits: used,
      updated_at: now,
    };
  }

  const nextTotal = existing.total_credits + amount;
  const total = nextTotal > 0 ? nextTotal : 0;
  const used = existing.used_credits;

  await dbRun(
    "UPDATE user_credits SET total_credits = ?, used_credits = ?, updated_at = ? WHERE user_id = ?",
    [total, used, now, userId]
  );

  return {
    user_id: userId,
    total_credits: total,
    used_credits: used,
    updated_at: now,
  };
}

export async function spendUserCredits(userId: string, amount: number): Promise<UserCreditsRow | null> {
  if (!userId || amount <= 0) return null;

  const row = await getUserCredits(userId);

  if (!row) {
    return null;
  }

  const remaining = row.total_credits - row.used_credits;
  if (remaining <= 0) {
    return row;
  }

  const now = new Date().toISOString();
  const toSpend = Math.min(amount, remaining);
  const result = await dbRun(
    "UPDATE user_credits SET used_credits = used_credits + ?, updated_at = ? WHERE user_id = ? AND used_credits + ? <= total_credits",
    [toSpend, now, userId, toSpend]
  );

  if (!result || typeof result.changes !== "number" || result.changes === 0) {
    // No row updated (likely because credits are exhausted). Return the original row.
    return row;
  }

  return {
    ...row,
    used_credits: row.used_credits + toSpend,
    updated_at: now,
  };
}

export async function getAvailableCreditsForUser(userId: string): Promise<number> {
  if (!userId) return 0;
  const row = await dbGet<{ total_credits: number; used_credits: number }>(
    "SELECT total_credits, used_credits FROM user_credits WHERE user_id = ?",
    [userId]
  );

  if (!row) return 0;
  const remaining = (row.total_credits || 0) - (row.used_credits || 0);
  return remaining > 0 ? remaining : 0;
}
