import db from "./db";

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

// Ensure the table exists at startup.
// This is idempotent and safe to call multiple times.
db.exec(`
  CREATE TABLE IF NOT EXISTS user_credits (
    user_id       TEXT PRIMARY KEY,
    total_credits INTEGER NOT NULL,
    used_credits  INTEGER NOT NULL,
    updated_at    TEXT NOT NULL
  )
`);

// Helper to compute available credits (never negative).
export function getAvailableCredits(row: UserCreditsRow | null): number {
  if (!row) return 0;
  const remaining = row.total_credits - row.used_credits;
  return remaining > 0 ? remaining : 0;
}

export function getUserCredits(userId: string): UserCreditsRow | null {
  const stmt = db.prepare<[{ user_id: string }], UserCreditsRow>(
    "SELECT user_id, total_credits, used_credits, updated_at FROM user_credits WHERE user_id = ?"
  );
  const row = stmt.get(userId) || null;
  return row;
}

// Upsert helper for future webhook use:
// - If the user has no row yet, create one with total_credits = max(amount, 0), used_credits = 0.
// - If the user already exists, add `amount` to total_credits (never below 0).
// Returns the fresh row.
export function addUserCredits(userId: string, amount: number): UserCreditsRow {
  const now = new Date().toISOString();
  const existing = getUserCredits(userId);

  if (!existing) {
    const total = amount > 0 ? amount : 0;
    const used = 0;
    db.prepare(
      "INSERT INTO user_credits (user_id, total_credits, used_credits, updated_at) VALUES (?,?,?,?)"
    ).run(userId, total, used, now);
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

  db.prepare(
    "UPDATE user_credits SET total_credits = ?, used_credits = ?, updated_at = ? WHERE user_id = ?"
  ).run(total, used, now, userId);

  return {
    user_id: userId,
    total_credits: total,
    used_credits: used,
    updated_at: now,
  };
}

export function spendUserCredits(userId: string, amount: number): UserCreditsRow | null {
  if (!userId || amount <= 0) return null;

  const row = db
    .prepare<[{ user_id: string }], UserCreditsRow | undefined>(
      "SELECT user_id, total_credits, used_credits, updated_at FROM user_credits WHERE user_id = ?"
    )
    .get(userId);

  if (!row) {
    return null;
  }

  const remaining = row.total_credits - row.used_credits;
  if (remaining <= 0) {
    return row;
  }

  const now = new Date().toISOString();
  const toSpend = Math.min(amount, remaining);
  const nextUsed = row.used_credits + toSpend;

  db
    .prepare("UPDATE user_credits SET used_credits = ?, updated_at = ? WHERE user_id = ?")
    .run(nextUsed, now, userId);

  return {
    ...row,
    used_credits: nextUsed,
    updated_at: now,
  };
}

export function getAvailableCreditsForUser(userId: string): number {
  if (!userId) return 0;
  const row = db
    .prepare<
      [{ user_id: string }],
      { total_credits: number; used_credits: number } | undefined
    >(
      "SELECT total_credits, used_credits FROM user_credits WHERE user_id = ?"
    )
    .get(userId);

  if (!row) return 0;
  const remaining = (row.total_credits || 0) - (row.used_credits || 0);
  return remaining > 0 ? remaining : 0;
}
