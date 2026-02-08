import express from "express";
import crypto from "node:crypto";
import Stripe from "stripe";
import { getAvailableCreditsForUser, spendUserCredits } from "../lib/credits";
import db, { dbAll, dbGet, dbRun, USING_POSTGRES, getUserBilling, upsertUserBilling } from "../lib/db";

const INCLUDED_RENDERS_PER_MONTH = Number(process.env.INCLUDED_RENDERS_PER_MONTH || 0);
const DEV_STARTING_CREDITS = Number(process.env.DEV_STARTING_CREDITS || 0);
const CHARS_PER_CREDIT = 1000;
const MAX_PASSKEYS_PER_USER = 2;
const COOLDOWN_MS = parseInt(process.env.LINK_CODE_COOLDOWN_MS || "120000", 10);
const REAUTH_WINDOW_MS = parseInt(process.env.LINK_CODE_REAUTH_WINDOW_MS || "300000", 10); // default 5 min

const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || "";
const stripe = STRIPE_SECRET_KEY ? new Stripe(STRIPE_SECRET_KEY) : null;

// Helper to safely convert to bigint or null
function toBigintOrNull(value: any): string | null {
  if (value == null) return null;
  if (typeof value === "number") return String(value);
  if (typeof value === "string") {
    const parsed = parseInt(value, 10);
    return isNaN(parsed) ? null : String(parsed);
  }
  return null;
}

function getSubscriptionPeriodFromItems(sub: any): { start: number | null; end: number | null } {
  const items = (sub as any)?.items?.data || [];
  const starts: number[] = [];
  const ends: number[] = [];

  for (const item of items) {
    const s = item.current_period_start;
    const e = item.current_period_end;
    if (typeof s === "number") starts.push(s);
    if (typeof e === "number") ends.push(e);
  }

  const start = starts.length > 0 ? Math.min(...starts) : null;
  const end = ends.length > 0 ? Math.max(...ends) : null;

  return { start, end };
}

function isActiveishStatus(status: string) {
  return status === "active" || status === "trialing" || status === "past_due" || status === "unpaid";
}

async function resolveBestSubscription(
  stripe: Stripe,
  stripeCustomerId: string,
  preferredSubscriptionId?: string | null
): Promise<Stripe.Subscription | null> {
  try {
    let preferredSub: Stripe.Subscription | null = null;

    // If we have a preferred subscription ID, try to retrieve it as a candidate
    if (preferredSubscriptionId) {
      try {
        const sub = await stripe.subscriptions.retrieve(preferredSubscriptionId);
        if (isActiveishStatus(sub.status)) {
          preferredSub = sub;
        }
      } catch (err) {
        console.warn("[auth/session] failed to retrieve preferred subscription", {
          preferredSubscriptionId,
          error: (err as any)?.message,
        });
      }
    }

    // Always list all subscriptions for this customer
    const list = await stripe.subscriptions.list({
      customer: stripeCustomerId,
      status: "all" as any,
      limit: 100,
      expand: ["data.items.data.price.product"],
    });

    // Filter to active-ish statuses only
    let candidates = list.data.filter((s) => isActiveishStatus(s.status));

    // If preferredSub exists and is not already in the list, append it
    if (preferredSub && !candidates.some((s) => s.id === preferredSub!.id)) {
      candidates.push(preferredSub);
    }

    if (candidates.length === 0) {
      return null;
    }

    // Try to identify Pro Monthly subscriptions by price ID or lookup key
    const proMonthlyPriceId = process.env.STRIPE_PRICE_PRO_MONTHLY;

    if (proMonthlyPriceId) {
      const matchingPrice = candidates.filter((s) =>
        s.items.data.some(
          (item) =>
            item.price.id === proMonthlyPriceId ||
            (item.price as any).lookup_key === "pro-monthly"
        )
      );

      if (matchingPrice.length > 0) {
        candidates = matchingPrice;
      }
    }

    // Select the one with the greatest current_period_end (most recent/future billing)
    const best = candidates.reduce((prev, curr) => {
      const prevPeriod = getSubscriptionPeriodFromItems(prev);
      const currPeriod = getSubscriptionPeriodFromItems(curr);
      const prevEnd = prevPeriod.end ?? 0;
      const currEnd = currPeriod.end ?? 0;
      return currEnd > prevEnd ? curr : prev;
    });

    const bestPeriod = getSubscriptionPeriodFromItems(best);
    console.log("[billing] resolveBestSubscription", {
      stripeCustomerId,
      preferredSubscriptionId,
      chosenId: best?.id,
      chosenEnd: bestPeriod.end,
      candidateCount: candidates.length,
    });

    return best;
  } catch (err) {
    console.error("[auth/session] resolveBestSubscription failed", {
      stripeCustomerId,
      preferredSubscriptionId,
      error: (err as any)?.message || String(err),
    });
    return null;
  }
}

async function countPasskeysForUser(userId: string): Promise<number> {
  const row = await dbGet<{ c: number }>(
    "SELECT COUNT(1) AS c FROM webauthn_credentials WHERE user_id = ?",
    [userId]
  );
  return Number(row?.c ?? 0);
}

// Session type stored in req.session (extends cookie-session)
type Sess = {
  sid?: string;
  regChallenge?: string;
  authChallenge?: string;
  userId?: string;
  credentialId?: string;
  loggedIn?: boolean;
  regUserHandle?: string;
  pendingLinkUserId?: string;
  pendingLinkCode?: string;
  lastAuthAt?: number;

  // — Entitlements (dev placeholders) —
  plan?: "none" | "dev";
  rendersUsed?: number;
  creditsAvailable?: number;
  periodStart?: string;
  periodEnd?: string;
};

function b64url(bytes: Buffer) {
  return bytes.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function b64urlToBuf(s: string) {
  const norm = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = "===".slice((norm.length + 3) % 4);
  return Buffer.from(norm + pad, "base64");
}
function genChallenge(len = 32) {
  return b64url(crypto.randomBytes(len));
}
function timingSafeEq(a: string, b: string) {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

function parseCookies(req: express.Request) {
  const header = req.headers.cookie || "";
  const out: Record<string, string> = {};
  header.split(";").forEach((part) => {
    const [k, ...v] = part.trim().split("=");
    if (!k) return;
    out[decodeURIComponent(k)] = decodeURIComponent(v.join("=") || "");
  });
  return out;
}

function ensureSessionDefaults(req: express.Request): Sess {
  const sess = req.session as Sess;
  if (!sess.sid || typeof sess.sid !== "string" || sess.sid.length < 10) {
    sess.sid = crypto.randomUUID();
  }
  if (!sess.userId) {
    sess.userId = `anon:${sess.sid}`;
  }
  if (!sess.plan) {
    const now = new Date();
    const start = new Date(now.getFullYear(), now.getMonth(), 1);
    const end = new Date(now.getFullYear(), now.getMonth() + 1, 1);
    const stripeEnabled = Boolean((process.env.STRIPE_SECRET_KEY || "").trim());
    sess.plan = "none";
    sess.rendersUsed = 0;
    sess.creditsAvailable = stripeEnabled ? 0 : DEV_STARTING_CREDITS;
    sess.periodStart = start.toISOString();
    sess.periodEnd = end.toISOString();
  }
  return sess;
}

export function ensureSid(req: express.Request, _res: express.Response) {
  const sess = ensureSessionDefaults(req);
  return sess.sid!;
}

export interface NoteRenderOpts {
  kind?: string;
  chargedChars?: number;
  chargedCredits?: number;
  meta?: Record<string, any>;
}

export async function noteRenderComplete(req: express.Request, opts?: NoteRenderOpts): Promise<string | undefined> {
  const sess = ensureSessionDefaults(req);
  const sid = sess.sid!;

  // Respect X-OffBook-User header for consistent user identity across reinstalls
  const headerRaw = req.header("X-OffBook-User") || req.header("X-User-Id") || "";
  const headerUser = sanitizeHeaderUserId(headerRaw);
  if (headerUser && !sess.loggedIn) {
    sess.userId = headerUser;
  }

  const userId = deriveUserId(sess) || sess.userId || `anon:${sid}`;

  // Calculate spend amount (fractional)
  const spend = opts?.chargedCredits ?? (opts?.chargedChars ? opts.chargedChars / CHARS_PER_CREDIT : 1);

  // Get user billing state
  let userBilling = null;
  try {
    userBilling = await getUserBilling(userId);
  } catch (err) {
    console.error("[credits] failed to get user billing", err);
  }

  // Check if billing is active (pro plan with valid period)
  const periodEnd = userBilling?.current_period_end ? parseInt(userBilling.current_period_end, 10) : null;
  const periodEndMs = periodEnd ? periodEnd * 1000 : NaN;
  const nowMs = Date.now();
  const billingActive = userBilling?.plan === "pro" &&
    (userBilling.status === "active" || userBilling.status === "trialing") &&
    (Number.isNaN(periodEndMs) || nowMs < periodEndMs);

  // Calculate monthly remaining
  const includedQuota = userBilling?.included_quota ?? 0;
  const rendersUsed = userBilling?.renders_used ?? 0;
  const monthlyRemaining = Math.max(0, includedQuota - rendersUsed);

  // Split spend between monthly and topup
  const monthlySpend = Math.min(spend, monthlyRemaining);
  const topupSpend = spend - monthlySpend;

  // If topup needed but billing not active, return error
  if (topupSpend > 0 && !billingActive) {
    console.log("[credits] cannot spend top-ups: billing not active", {
      userId,
      spend,
      monthlySpend,
      topupSpend,
      plan: userBilling?.plan,
      status: userBilling?.status,
      periodEnd,
    });
    return "billing_inactive_topup_required";
  }

  // Apply monthly spend
  if (monthlySpend > 0 && userBilling) {
    try {
      await dbRun(
        `UPDATE user_billing SET renders_used = renders_used + ? WHERE user_id = ?`,
        [monthlySpend, userId]
      );
      console.log("[credits] consumed Pro included quota", {
        userId,
        monthlySpend,
        newRendersUsed: rendersUsed + monthlySpend,
        includedQuota,
      });
    } catch (err) {
      console.error("[credits] failed to update monthly renders_used", err);
    }
  }

  // Apply topup spend
  if (topupSpend > 0) {
    try {
      await dbRun(
        `UPDATE user_credits SET used_credits = used_credits + ? WHERE user_id = ?`,
        [topupSpend, userId]
      );
      console.log("[credits] consumed top-up credits", {
        userId,
        topupSpend,
      });
    } catch (err) {
      console.error("[credits] failed to update top-up used_credits", err);
    }
  }

  // Insert usage event
  try {
    const metaJson = opts?.meta ? JSON.stringify(opts.meta) : null;
    await dbRun(
      `INSERT INTO usage_events (id, user_id, kind, chars, credits, meta_json)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [crypto.randomUUID(), userId, opts?.kind || "render_tts", opts?.chargedChars ?? null, spend, metaJson]
    );
  } catch (err) {
    console.error("[credits] failed to insert usage_event", err);
  }

  // Update session state for legacy compatibility
  const beforeUsed = typeof sess.rendersUsed === "number" ? sess.rendersUsed : 0;
  sess.rendersUsed = beforeUsed + spend;

  console.log("[credits] noteRenderComplete", {
    userId,
    spend,
    monthlySpend,
    topupSpend,
    chargedChars: opts?.chargedChars,
    chargedCredits: opts?.chargedCredits,
  });

  return undefined; // success
}

function getRpId(req: express.Request) {
  const envId = (process.env.RP_ID || "").trim();
  if (envId) return envId;
  // Fallback: derive from Host header (works fine on ngrok for solo dev)
  const host = (req.headers["x-forwarded-host"] || req.headers.host || "").toString();
  return host.replace(/:\d+$/, "");
}
function getAllowedOrigin(req: express.Request) {
  const envOrigin = (process.env.RP_ORIGIN || "").trim();
  if (envOrigin) return envOrigin;
  const host = (req.headers["x-forwarded-host"] || req.headers.host || "").toString().replace(/:\d+$/, "");
  const proto = (req.headers["x-forwarded-proto"] || req.protocol || "https").toString();
  return `${proto}://${host}`;
}

const router = express.Router();

const INVITE_CODE = (process.env.INVITE_CODE || "").trim();
const ENFORCE_AUTH_GATE = /^true$/i.test(process.env.ENFORCE_AUTH_GATE || "");
const ENABLE_SOLO_TESTER_MIGRATION = process.env.ENABLE_SOLO_TESTER_MIGRATION === "1";

function shortSha256(input: string): string {
  return crypto.createHash("sha256").update(input).digest("hex").slice(0, 16);
}

function deriveUserId(sess: Sess | undefined | null): string {
  if (!sess) return "";
  if (sess.credentialId && sess.credentialId.trim()) {
    return `pk_${shortSha256(sess.credentialId.trim())}`;
  }
  if (sess.userId && sess.userId.trim()) return sess.userId.trim();
  return "";
}

// Sanitize header user id: trim, max 200 chars, only allow [a-zA-Z0-9:._-]
function sanitizeHeaderUserId(raw: string): string {
  const trimmed = raw.trim().slice(0, 200);
  return /^[a-zA-Z0-9:._-]+$/.test(trimmed) ? trimmed : "";
}

// Lightweight helper for other routes to read the passkey session state
export function getPasskeySession(req: express.Request) {
  const sess = ensureSessionDefaults(req);
  const passkeyLoggedIn = Boolean(sess.loggedIn);
  const allowAnon = !ENFORCE_AUTH_GATE;

  // Check for X-OffBook-User or X-User-Id header (stable identity across reinstalls)
  const headerRaw = req.header("X-OffBook-User") || req.header("X-User-Id") || "";
  const headerUser = sanitizeHeaderUserId(headerRaw);

  let userId: string | null = null;
  if (passkeyLoggedIn) {
    userId = deriveUserId(sess);
  } else if (allowAnon) {
    // Prefer header user id when present and valid (prevents reinstall resets)
    if (headerUser) {
      sess.userId = headerUser;
      userId = headerUser;
    } else {
      userId = sess.userId || `anon:${sess.sid}`;
    }
  }

  return { passkeyLoggedIn, userId };
}

// --- GET /auth/session -------------------------------------------------------
router.get("/session", async (req, res) => {
  const sess = ensureSessionDefaults(req);
  const sid = sess.sid!;

  const cookies = parseCookies(req);
  const invited = (process.env.INVITE_CODE || "").trim()
    ? cookies["ob_invite"] === "ok"
    : true;

  const passkeyLoggedIn = Boolean(sess.loggedIn);
  const allowAnon = !ENFORCE_AUTH_GATE;

  // Check for X-OffBook-User or X-User-Id header (stable identity across reinstalls)
  const headerRaw = req.header("X-OffBook-User") || req.header("X-User-Id") || "";
  const headerUser = sanitizeHeaderUserId(headerRaw);

  // Ensure anon identity is stable - prefer header user id when present
  if (allowAnon && sess) {
    if (headerUser) {
      sess.userId = headerUser;
    } else if (!sess.userId) {
      sess.userId = `anon:${sid}`;
    }
  }

  let userId: string | null = null;
  if (passkeyLoggedIn) {
    userId = deriveUserId(sess);
  } else if (allowAnon) {
    // Prefer header user id when present
    userId = headerUser || sess.userId || `anon:${sid}`;
  }

  // One-time migration: move legacy solo-tester + old anon data to this user
  if (userId && userId !== "solo-tester") {
    try {
      // Determine legacy anon id from session
      const anonLegacy = (sess && typeof sess.userId === "string" && sess.userId.startsWith("anon:") && sess.userId !== userId)
        ? sess.userId
        : null;

      // Build list of legacy IDs to check (dedupe and skip current userId)
      const legacyIds = [
        ENABLE_SOLO_TESTER_MIGRATION ? "solo-tester" : null,
        anonLegacy,
      ]
        .filter(Boolean)
        .filter((id) => id !== userId) as string[];

      if (legacyIds.length > 0) {
        for (const legacyId of legacyIds) {
          const hasLegacy = await dbGet<{ "1": number }>("SELECT 1 FROM scripts WHERE user_id = ? LIMIT 1", [legacyId]);
          if (hasLegacy) {
            // Migrate scripts
            await dbRun("UPDATE scripts SET user_id = ? WHERE user_id = ?", [userId, legacyId]);

            // Migrate user_credits only if destination doesn't exist
            const hasDestCredits = await dbGet<{ "1": number }>("SELECT 1 FROM user_credits WHERE user_id = ? LIMIT 1", [userId]);
            if (!hasDestCredits) {
              await dbRun("UPDATE user_credits SET user_id = ? WHERE user_id = ?", [userId, legacyId]);
            }

            // Migrate gallery_takes only if destination doesn't exist
            const hasDestGallery = await dbGet<{ "1": number }>("SELECT 1 FROM gallery_takes WHERE user_id = ? LIMIT 1", [userId]);
            if (!hasDestGallery) {
              await dbRun("UPDATE gallery_takes SET user_id = ? WHERE user_id = ?", [userId, legacyId]);
            }

            console.log("[auth] migrated legacy data from %s to %s", legacyId, userId);
          }
        }
      }
    } catch (err) {
      console.error("[auth] migration failed for userId=%s", userId, err);
    }
  }

  // Staging auto-seed credits (if STAGING_SEED_CREDITS is set)
  // Skip when Stripe is configured to prevent masking purchased credits
  if (userId) {
    const stripeEnabled = Boolean((process.env.STRIPE_SECRET_KEY || "").trim());
    if (!stripeEnabled) {
      const seed = parseInt(process.env.STAGING_SEED_CREDITS || "", 10);
      if (Number.isFinite(seed) && seed > 0) {
        try {
          const row = await dbGet<{ total_credits?: number; used_credits?: number }>("SELECT total_credits, used_credits FROM user_credits WHERE user_id = ?", [userId]);
          if (!row) {
            await dbRun("INSERT INTO user_credits (user_id, total_credits, used_credits) VALUES (?, ?, 0)", [userId, seed]);
            console.log("[auth] staging seed: created credits row with %d credits for userId=%s", seed, userId);
          } else {
            const total = row.total_credits ?? 0;
            const used = row.used_credits ?? 0;
            const available = total - used;
            if (available <= 0) {
              await dbRun("UPDATE user_credits SET total_credits = ? WHERE user_id = ?", [used + seed, userId]);
              console.log("[auth] staging seed: replenished credits to %d for userId=%s", seed, userId);
            }
          }
        } catch (err) {
          console.error("[auth] staging seed failed for userId=%s", userId, err);
        }
      }
    } else {
      // Log once when staging seed is skipped due to Stripe
      const seed = parseInt(process.env.STAGING_SEED_CREDITS || "", 10);
      if (Number.isFinite(seed) && seed > 0) {
        console.log("[auth] staging seed skipped (Stripe enabled)");
      }
    }
  }

  let dbCredits = 0;
  let userBilling = null;

  if (userId) {
    try {
      dbCredits = await getAvailableCreditsForUser(userId);
    } catch (err) {
      console.error(
        "[auth/session] failed to read credits for userId=%s",
        userId,
        err
      );
    }

    // Load subscription data if user is logged in with passkey
    if (passkeyLoggedIn) {
      try {
        userBilling = await getUserBilling(userId);

        // Refresh Stripe period for Pro users
        if (userBilling?.plan === "pro" && userBilling?.stripe_customer_id && stripe) {
          try {
            // Use resolveBestSubscription to get the correct active subscription
            const sub = await resolveBestSubscription(
              stripe,
              userBilling.stripe_customer_id,
              userBilling.stripe_subscription_id
            );

            if (sub) {
              const subId = sub.id;
              const { start, end } = getSubscriptionPeriodFromItems(sub);
              const cps = toBigintOrNull(start);
              const cpe = toBigintOrNull(end);

              // Required clear log line
              const startISO = cps ? new Date(parseInt(cps, 10) * 1000).toISOString() : null;
              const endISO = cpe ? new Date(parseInt(cpe, 10) * 1000).toISOString() : null;
              console.log(`[billing] resolved stripe sub=${subId} status=${sub.status} period=${startISO}..${endISO}`);

              // Only update if we got valid period values
              if (cps && cpe) {
                await upsertUserBilling({
                  user_id: userId,
                  plan: "pro",
                  stripe_customer_id: userBilling.stripe_customer_id,
                  stripe_subscription_id: subId,
                  status: sub.status || "active",
                  current_period_start: cps,
                  current_period_end: cpe,
                  included_quota: 120,
                  renders_used: userBilling.renders_used,
                });

                // Update local userBilling object with fresh values
                userBilling.stripe_subscription_id = subId;
                userBilling.current_period_start = cps;
                userBilling.current_period_end = cpe;
                userBilling.status = sub.status || "active";
              }
            }
          } catch (err) {
            console.warn("[auth/session] stripe period refresh failed (falling back to DB)", {
              userId,
              stripeCustomerId: userBilling?.stripe_customer_id,
              stripeSubscriptionId: userBilling?.stripe_subscription_id,
              msg: (err as any)?.message || String(err),
            });
            // Fall back to DB values - don't crash
          }
        }
      } catch (err) {
        console.error("[auth/session] failed to read user_billing for userId=%s", userId, err);
      }
    }
  }

  const stripeEnabled = Boolean((process.env.STRIPE_SECRET_KEY || "").trim());
  const sessionCredits = stripeEnabled ? 0 : ((passkeyLoggedIn || allowAnon) ? (sess?.creditsAvailable ?? 0) : 0);
  const combinedCredits = (passkeyLoggedIn || allowAnon) ? (sessionCredits + dbCredits) : 0;

  // Override entitlement fields if user has subscription
  const plan = userBilling?.plan || sess?.plan || "none";
  const includedQuota = userBilling?.included_quota ?? INCLUDED_RENDERS_PER_MONTH;
  const rendersUsed = userBilling?.renders_used ?? sess?.rendersUsed ?? 0;
  const periodStart = userBilling?.current_period_start ? parseInt(userBilling.current_period_start, 10) : (sess?.periodStart ?? null);
  const periodEnd = userBilling?.current_period_end ? parseInt(userBilling.current_period_end, 10) : (sess?.periodEnd ?? null);

  // Compute derived fields
  const subscriptionRemaining = Math.max(0, includedQuota - rendersUsed);

  // Rule B: Pro active means user is in a paid period (or period end is unknown/future)
  const periodEndMs = (periodEnd && typeof periodEnd === "number") ? periodEnd * 1000 : NaN;
  const nowMs = Date.now();
  const proActiveNow = plan === "pro" && (Number.isNaN(periodEndMs) || nowMs < periodEndMs);

  // Top-ups are only usable while Pro is active
  const effectiveTopups = proActiveNow ? combinedCredits : 0;
  const topupsExpireAt = periodEnd;

  if (passkeyLoggedIn) {
    console.log("[auth/session] entitlement snapshot", {
      userId,
      plan,
      dbCredits,
      sessionCredits,
      combinedCredits,
      includedQuota,
      rendersUsed,
      periodStart,
      periodEnd,
      proActiveNow,
      subscriptionRemaining,
      effectiveTopups,
    });
  }

  res.setHeader("Cache-Control", "no-store");

  // Check if dev debug mode is enabled
  const devToolsOn =
    /^true$/i.test(process.env.DEV_TOOLS || "") ||
    /(^|[?&])dev(=1|&|$)/.test(req.url);
  const sharedSecret = process.env.SHARED_SECRET || "";
  const providedSecret = (req.query.secret as string) || req.header("X-Shared-Secret") || "";
  const isDevDebug = devToolsOn && sharedSecret && providedSecret === sharedSecret;

  // Build base response
  const response: any = {
    invited,
    hasInviteCode: Boolean((process.env.INVITE_CODE || "").trim()),
    enforceAuthGate: /^true$/i.test(process.env.ENFORCE_AUTH_GATE || ""),
    userId,
    passkey: {
      registered: Boolean(sess?.credentialId),
      loggedIn: passkeyLoggedIn,
    },
    entitlement: {
      plan,
      included_quota: includedQuota,
      renders_used: rendersUsed,
      credits_available: combinedCredits,
      period_start: periodStart,
      period_end: periodEnd,
      subscription_remaining: subscriptionRemaining,
      topup_balance: effectiveTopups,
      topups_expire_at: topupsExpireAt,
    },
  };

  // Add dev debug fields if authorized
  if (isDevDebug && userBilling) {
    const periodEndISO = userBilling.current_period_end
      ? new Date(parseInt(userBilling.current_period_end, 10) * 1000).toISOString()
      : null;

    response.debug = {
      stripe_customer_id: userBilling.stripe_customer_id,
      stripe_subscription_id: userBilling.stripe_subscription_id,
      stripe_sub_status: userBilling.status,
      stripe_current_period_end: periodEndISO,
    };
  }

  res.json(response);
});

// --- POST /auth/enter-code ---------------------------------------------------
// Body: { "code": "<value>" }.
// If INVITE_CODE is unset, it's a no-op (204). If set and matches, set httpOnly cookie.
router.post("/enter-code", express.json(), (req, res) => {
  if (!INVITE_CODE) return res.status(204).end();

  const { code } = (req.body || {}) as { code?: string };
  if (typeof code !== "string") return res.status(400).json({ ok: false, error: "missing_code" });
  if (code.trim() !== INVITE_CODE) return res.status(401).json({ ok: false, error: "invalid_code" });

  const isHttps =
    (req.headers["x-forwarded-proto"] === "https") ||
    (req.protocol === "https");

  res.cookie("ob_invite", "ok", {
    httpOnly: true,
    sameSite: "lax",
    secure: !!isHttps, // ngrok is HTTPS -> true
    // cookie lasts for the browser session; adjust later if needed
  });

  return res.json({ ok: true });
});

// --- POST /auth/signout ------------------------------------------------------
router.post("/signout", (req, res) => {
  res.clearCookie("ob_invite");

  const sess = req.session as Sess;
  if (sess) {
    sess.loggedIn = false;

    // Clear passkey + linking state so "link another device" works cleanly
    delete sess.credentialId;
    delete sess.userId;
    delete sess.authChallenge;
    delete sess.regChallenge;
    delete sess.regUserHandle;
    delete sess.pendingLinkUserId;
    delete sess.pendingLinkCode;
  }

  return res.json({ ok: true });
});

// --- DEVICE LINK CODE: START -------------------------------------------------
// POST /auth/device-link/start
// Generates a link code for the current passkey user to link another device
router.post("/device-link/start", async (req, res) => {
  const sess = ensureSessionDefaults(req);

  // Require passkey logged in
  if (!sess.loggedIn || !sess.userId) {
    return res.status(401).json({ ok: false, error: "not_logged_in" });
  }

  // Require recent authentication
  const last = typeof sess.lastAuthAt === "number" ? sess.lastAuthAt : 0;
  const age = Date.now() - last;
  if (!last || age > REAUTH_WINDOW_MS) {
    console.log("[device-link] reauth_required user=%s age_ms=%s", sess.userId, age);
    return res.status(401).json({
      ok: false,
      error: "reauth_required",
      reauth_window_sec: Math.floor(REAUTH_WINDOW_MS / 1000),
      age_sec: Math.floor(age / 1000)
    });
  }

  // Check cooldown: don't allow creating codes too frequently
  try {
    const lastCode = await dbGet<{ created_at: string }>(
      "SELECT created_at FROM device_link_codes WHERE user_id = ? ORDER BY created_at DESC LIMIT 1",
      [sess.userId]
    );

    if (lastCode && lastCode.created_at) {
      const lastCreatedAt = new Date(lastCode.created_at).getTime();
      const now = Date.now();
      const elapsed = now - lastCreatedAt;

      if (elapsed < COOLDOWN_MS) {
        const retryAfterMs = COOLDOWN_MS - elapsed;
        const retryAfterS = Math.ceil(retryAfterMs / 1000);
        console.log("[device-link] cooldown uid=%s retry_after_s=%s", sess.userId, retryAfterS);
        return res.status(429).json({ ok: false, error: "cooldown", retry_after_s: retryAfterS });
      }
    }
  } catch (err) {
    console.error("[auth] Failed to check link code cooldown:", err);
    // Continue anyway - don't block code generation on cooldown check failure
  }

  // Generate 8-char code (ABCD-EFGH format, no ambiguous chars)
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // No O, I, 1, 0
  let code = "";
  for (let i = 0; i < 8; i++) {
    code += chars[Math.floor(Math.random() * chars.length)];
  }
  const formattedCode = `${code.slice(0, 4)}-${code.slice(4)}`;

  // Expires in 10 minutes
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
  const expiresAtStr = expiresAt.toISOString();

  try {
    await dbRun(
      "INSERT INTO device_link_codes (code, user_id, expires_at, used_at) VALUES (?, ?, ?, NULL)",
      [formattedCode, sess.userId, expiresAtStr]
    );

    return res.json({
      ok: true,
      code: formattedCode,
      expires_in_sec: 600
    });
  } catch (err) {
    console.error("[auth] Failed to create link code:", err);
    return res.status(500).json({ ok: false, error: "failed_to_create_code" });
  }
});

// --- DEVICES: LIST ---------------------------------------------------------
// GET /auth/devices
router.get("/devices", async (req, res) => {
  const sess = ensureSessionDefaults(req);
  if (!sess.userId) return res.status(401).json({ ok: false, error: "not_signed_in" });

  try {
    const rows = await dbAll<{ id: string; credential_id: string; created_at: any }>(
      "SELECT id, credential_id, created_at FROM webauthn_credentials WHERE user_id = ? ORDER BY created_at ASC",
      [sess.userId]
    );

    return res.json({
      ok: true,
      currentCredentialId: sess.credentialId || null,
      devices: rows.map(r => ({
        id: r.id,
        credentialId: r.credential_id,
        createdAt: r.created_at
      }))
    });
  } catch (err) {
    console.error("[auth] /devices failed:", err);
    return res.status(500).json({ ok: false, error: "failed_to_list_devices" });
  }
});

// --- DEVICES: REVOKE -------------------------------------------------------
// POST /auth/devices/revoke  { credentialId }
router.post("/devices/revoke", async (req, res) => {
  const sess = ensureSessionDefaults(req);
  if (!sess.userId) return res.status(401).json({ ok: false, error: "not_signed_in" });

  const { credentialId } = (req.body || {}) as { credentialId?: string };
  if (!credentialId) return res.status(400).json({ ok: false, error: "missing_credential_id" });

  // Don't allow revoking the current device (UI won't show the button for it anyway)
  if (sess.credentialId && credentialId === sess.credentialId) {
    return res.status(400).json({ ok: false, error: "cannot_revoke_current_device" });
  }

  try {
    await dbRun(
      "DELETE FROM webauthn_credentials WHERE user_id = ? AND credential_id = ?",
      [sess.userId, credentialId]
    );
    return res.json({ ok: true });
  } catch (err) {
    console.error("[auth] /devices/revoke failed:", err);
    return res.status(500).json({ ok: false, error: "failed_to_revoke_device" });
  }
});

// --- DEVICE LINK CODE: CLAIM -------------------------------------------------
// POST /auth/device-link/claim
// Claims a link code to link this device to an existing account
router.post("/device-link/claim", async (req, res) => {
  const sess = ensureSessionDefaults(req);
  const { code } = (req.body || {}) as { code?: string };

  if (!code || typeof code !== "string") {
    return res.status(400).json({ ok: false, error: "missing_code" });
  }

  try {
    // Look up the code
    const row = await dbGet<{ user_id: string; expires_at: string; used_at: string | null }>(
      "SELECT user_id, expires_at, used_at FROM device_link_codes WHERE code = ?",
      [code.trim().toUpperCase()]
    );

    if (!row) {
      return res.status(404).json({ ok: false, error: "invalid_code" });
    }

    // Check expiration
    const expiresAt = new Date(row.expires_at);
    if (Date.now() > expiresAt.getTime()) {
      return res.status(400).json({ ok: false, error: "code_expired" });
    }

    // Check if already used
    if (row.used_at) {
      return res.status(409).json({ ok: false, error: "code_already_used" });
    }

    // Store the user_id and code in session for the upcoming registration
    // Code will be consumed atomically during register/finish
    const normalizedCode = code.trim().toUpperCase();
    sess.pendingLinkUserId = row.user_id;
    sess.pendingLinkCode = normalizedCode;

    const count = await countPasskeysForUser(row.user_id);
    return res.json({ ok: true, count, max: MAX_PASSKEYS_PER_USER });
  } catch (err) {
    console.error("[auth] Failed to claim link code:", err);
    return res.status(500).json({ ok: false, error: "failed_to_claim_code" });
  }
});

// --- PASSKEY REGISTER: START --------------------------------------------------
// POST /auth/passkey/register/start
// Body optional: { userId?: string, userName?: string, displayName?: string }
// For solo dev we default to a single tester identity.
router.post("/passkey/register/start", (req, res) => {
  const sess = ensureSessionDefaults(req);

  const rpId = getRpId(req);
  const challenge = genChallenge();

  const body = (req.body || {}) as { userName?: string; displayName?: string };

  // Generate a per-session registration user handle (WebAuthn "user.id").
  // This is NOT our DB userId; our DB userId is derived from credentialId after finish.
  if (!sess.regUserHandle) {
    sess.regUserHandle = `ob_${crypto.randomUUID()}`;
  }
  const userHandle = sess.regUserHandle;

  const userName = (body.userName || `user-${userHandle.slice(3, 11)}@offbook.local`);
  const displayName = (body.displayName || "OffBook User");

  // Minimal PublicKeyCredentialCreationOptions (no libs)
  const options: any = {
    rp: { id: rpId, name: "OffBook (Dev)" },
    user: {
      id: Buffer.from(userHandle).toString("base64url"),
      name: userName,
      displayName,
    },
    challenge,
    pubKeyCredParams: [
      { type: "public-key", alg: -7 },   // ES256
      { type: "public-key", alg: -257 }, // RS256 (optional)
    ],
    timeout: 60000,
    attestation: "none",
    authenticatorSelection: {
      residentKey: "required",
      userVerification: "preferred",
      authenticatorAttachment: "platform", // Face ID / Touch ID
    },
  };

  sess.regChallenge = challenge;
  return res.json({ options });
});

// --- PASSKEY REGISTER: FINISH (DEV MODE) -------------------------------------
// POST /auth/passkey/register/finish
// Body: { id, rawId, response: { clientDataJSON, attestationObject? }, type }
router.post("/passkey/register/finish", express.json({ limit: "1mb" }), async (req, res) => {
  const sess = ensureSessionDefaults(req);
  const priorUserId = sess.userId;

  if (!sess.regChallenge) {
    return res.status(400).json({ ok: false, error: "no_challenge" });
  }

  const { id, rawId, response, type } = (req.body || {}) as any;
  if (!id || !rawId || !response?.clientDataJSON) {
    return res.status(400).json({ ok: false, error: "malformed_payload" });
  }

  let clientData: any;
  try {
    const cbuf = b64urlToBuf(response.clientDataJSON);
    clientData = JSON.parse(cbuf.toString("utf8"));
  } catch {
    return res.status(400).json({ ok: false, error: "bad_clientDataJSON" });
  }

  const allowedOrigin = getAllowedOrigin(req);
  const challengeOk = timingSafeEq(String(clientData.challenge || ""), sess.regChallenge);
  const typeOk = (type === "public-key") && (clientData.type === "webauthn.create");
  const originOk = (clientData.origin === allowedOrigin);

  if (!challengeOk) return res.status(400).json({ ok: false, error: "challenge_mismatch" });
  if (!typeOk)      return res.status(400).json({ ok: false, error: "type_mismatch" });
  if (!originOk)    return res.status(400).json({ ok: false, error: "origin_mismatch", expected: allowedOrigin, got: clientData.origin });

  const credentialId = String(id);

  // Determine stable userId: use pendingLinkUserId if linking, otherwise derive from credential
  const stableUserId = sess.pendingLinkUserId || deriveUserId({ ...sess, credentialId }) || "passkey:registered";

  // Identify the target account for the new credential
  const targetUserId = sess.pendingLinkUserId ?? stableUserId;

  // If we're linking, atomically consume the link code now (after FaceID success)
  if (sess.pendingLinkCode) {
    const normalized = sess.pendingLinkCode.trim().toUpperCase();

    const linkRow = await dbGet<{ expires_at: string; used_at: string | null }>(
      "SELECT expires_at, used_at FROM device_link_codes WHERE code = ?",
      [normalized]
    );

    if (!linkRow) {
      return res.status(404).json({ ok: false, error: "invalid_code" });
    }

    const expiresAt = new Date(linkRow.expires_at);
    if (Date.now() > expiresAt.getTime()) {
      return res.status(400).json({ ok: false, error: "code_expired" });
    }

    if (linkRow.used_at) {
      return res.status(409).json({ ok: false, error: "code_already_used" });
    }

    const usedAt = new Date().toISOString();
    const upd = await dbRun(
      "UPDATE device_link_codes SET used_at = ? WHERE code = ? AND used_at IS NULL",
      [usedAt, normalized]
    );

    const changed = (upd?.rowCount ?? upd?.changes ?? 0);
    if (changed === 0) {
      return res.status(409).json({ ok: false, error: "code_already_used" });
    }
  }

  // Enforce device cap only when this is adding a *new* credential to an existing account
  if (targetUserId) {
    const existing = await dbGet<{ "1": number }>(
      "SELECT 1 FROM webauthn_credentials WHERE credential_id = ? LIMIT 1",
      [String(id)]
    );

    if (!existing) {
      const n = await countPasskeysForUser(targetUserId);
      if (n >= MAX_PASSKEYS_PER_USER) {
        return res.status(409).json({ ok: false, error: "device_cap_reached", max: MAX_PASSKEYS_PER_USER });
      }
    }
  }

  // Store credential in DB
  try {
    const credId = crypto.randomUUID();
    await dbRun(
      "INSERT INTO webauthn_credentials (id, user_id, credential_id, public_key, counter) VALUES (?, ?, ?, ?, ?)",
      [credId, targetUserId, credentialId, "dev", 0]
    );
  } catch (err) {
    console.error("[auth] Failed to store credential:", err);
    return res.status(500).json({ ok: false, error: "failed_to_store_credential" });
  }

  sess.credentialId = credentialId;
  sess.userId = stableUserId;
  sess.loggedIn = true;
  sess.lastAuthAt = Date.now();
  delete sess.regChallenge;
  delete sess.regUserHandle;
  delete sess.pendingLinkUserId;
  delete sess.pendingLinkCode;

  // Migrate anon data to passkey user (first-time register flow)
  if (priorUserId && stableUserId && priorUserId.startsWith("anon:") && priorUserId !== stableUserId) {
    try {
      await dbRun("UPDATE scripts SET user_id = ? WHERE user_id = ?", [stableUserId, priorUserId]);

      const hasDestCredits = await dbGet<{ "1": number }>(
        "SELECT 1 FROM user_credits WHERE user_id = ? LIMIT 1",
        [stableUserId]
      );
      if (!hasDestCredits) {
        await dbRun("UPDATE user_credits SET user_id = ? WHERE user_id = ?", [stableUserId, priorUserId]);
      }

      const hasDestGallery = await dbGet<{ "1": number }>(
        "SELECT 1 FROM gallery_takes WHERE user_id = ? LIMIT 1",
        [stableUserId]
      );
      if (!hasDestGallery) {
        await dbRun("UPDATE gallery_takes SET user_id = ? WHERE user_id = ?", [stableUserId, priorUserId]);
      }

      console.log("[auth] migrated anon data from %s to %s (register)", priorUserId, stableUserId);
    } catch (err) {
      console.error("[auth] failed to migrate anon data from %s to %s (register)", priorUserId, stableUserId, err);
    }
  }

  return res.json({ ok: true, userId: sess.userId, credentialId: sess.credentialId, autoSignedIn: true });
});

// --- PASSKEY LOGIN: START -----------------------------------------------------
// POST /auth/passkey/login/start
// Body optional: { userId?: string } -- kept for parity; allowCredentials omitted for dev.
router.post("/passkey/login/start", (req, res) => {
  const sess = ensureSessionDefaults(req);

  const rpId = getRpId(req);
  const challenge = genChallenge();

  // Minimal PublicKeyCredentialRequestOptions
  const options: any = {
    challenge,
    rpId,
    timeout: 60000,
    userVerification: "preferred",
    // allowCredentials: [] // Omitted -> discoverable credentials allowed
  };

  sess.authChallenge = challenge;
  return res.json({ options });
});

// --- PASSKEY LOGIN: FINISH (DEV MODE) ----------------------------------------
// POST /auth/passkey/login/finish
// Body: { id, rawId, response: { clientDataJSON, authenticatorData?, signature?, userHandle? }, type }
router.post("/passkey/login/finish", express.json({ limit: "1mb" }), async (req, res) => {
  const sess = ensureSessionDefaults(req);

  if (!sess.authChallenge) {
    return res.status(400).json({ ok: false, error: "no_challenge" });
  }

  const { id, response, type } = (req.body || {}) as any;
  if (!id || !response?.clientDataJSON) {
    return res.status(400).json({ ok: false, error: "malformed_payload" });
  }

  let clientData: any;
  try {
    const cbuf = b64urlToBuf(response.clientDataJSON);
    clientData = JSON.parse(cbuf.toString("utf8"));
  } catch {
    return res.status(400).json({ ok: false, error: "bad_clientDataJSON" });
  }

  const allowedOrigin = getAllowedOrigin(req);
  const challengeOk = timingSafeEq(String(clientData.challenge || ""), sess.authChallenge);
  const typeOk = (type === "public-key") && (clientData.type === "webauthn.get");
  const originOk = (clientData.origin === allowedOrigin);

  if (!challengeOk) return res.status(400).json({ ok: false, error: "challenge_mismatch" });
  if (!typeOk)      return res.status(400).json({ ok: false, error: "type_mismatch" });
  if (!originOk)    return res.status(400).json({ ok: false, error: "origin_mismatch", expected: allowedOrigin, got: clientData.origin });

  // Capture prior userId BEFORE marking logged in
  const priorUserId = req.session?.userId;

  const credentialId = String(id);

  // Look up userId from webauthn_credentials DB
  let stableUserId: string;
  try {
    const credRow = await dbGet<{ user_id: string }>(
      "SELECT user_id FROM webauthn_credentials WHERE credential_id = ? LIMIT 1",
      [credentialId]
    );

    if (credRow) {
      stableUserId = credRow.user_id;
    } else {
      // Fallback: derive from credential and insert mapping
      stableUserId = deriveUserId({ ...sess, credentialId }) || "passkey:unknown";

      // Enforce device cap before inserting new credential mapping
      const n = await countPasskeysForUser(stableUserId);
      if (n >= MAX_PASSKEYS_PER_USER) {
        return res.status(409).json({ ok: false, error: "device_cap_reached", max: MAX_PASSKEYS_PER_USER });
      }

      const credId = crypto.randomUUID();
      await dbRun(
        "INSERT INTO webauthn_credentials (id, user_id, credential_id, public_key, counter) VALUES (?, ?, ?, ?, ?)",
        [credId, stableUserId, credentialId, "dev", 0]
      );
      console.log("[auth] Created credential mapping for legacy login: %s -> %s", credentialId, stableUserId);
    }
  } catch (err) {
    console.error("[auth] Failed to lookup/create credential:", err);
    return res.status(500).json({ ok: false, error: "credential_lookup_failed" });
  }

  sess.credentialId = credentialId;
  sess.userId = stableUserId;
  sess.loggedIn = true;
  sess.lastAuthAt = Date.now();
  delete sess.authChallenge;

  // Migrate anon scripts to passkey user
  if (priorUserId && stableUserId && priorUserId.startsWith("anon:") && priorUserId !== stableUserId) {
    try {
      await dbRun("UPDATE scripts SET user_id = ? WHERE user_id = ?", [stableUserId, priorUserId]);
      console.log("[auth] migrated anon scripts from %s to %s", priorUserId, stableUserId);
    } catch (err) {
      console.error("[auth] failed to migrate anon scripts from %s to %s", priorUserId, stableUserId, err);
    }
  }

  return res.json({ ok: true, userId: stableUserId || null });
});

// --- DEV ONLY: Grant credits to current session ------------------------------
// Enabled only when URL has ?dev=1 OR ENV DEV_TOOLS=true (light guard).
router.post("/dev/grant-credits", express.json(), (req, res) => {
  const devToolsOn = /^true$/i.test(process.env.DEV_TOOLS || "") ||
                     /(^|[?&])dev(=1|&|$)/.test(req.url);
  if (!devToolsOn) return res.status(403).json({ ok: false, error: "dev_tools_disabled" });

  const sess = ensureSessionDefaults(req);
  const sid = sess.sid!;

  const amount = Number(req.body?.amount ?? 200) || 200;
  const before = typeof sess.creditsAvailable === "number"
    ? sess.creditsAvailable
    : 0;

  sess.creditsAvailable = before + amount;

  console.log(
    "[credits] dev grant: sid=%s before=%d amount=%d after=%d",
    sid,
    before,
    amount,
    sess.creditsAvailable
  );

  return res.json({
    ok: true,
    sid,
    credits_available: sess.creditsAvailable,
  });
});

router.post("/dev/use-credit", express.json(), async (req, res) => {
  const devToolsOn =
    /^true$/i.test(process.env.DEV_TOOLS || "") ||
    /(^|[?&])dev(=1|&|$)/.test(req.url);
  if (!devToolsOn) {
    return res
      .status(403)
      .json({ ok: false, error: "dev_tools_disabled" });
  }

  const sess = ensureSessionDefaults(req);
  const sid = sess.sid!;

  const beforeUsed =
    typeof sess.rendersUsed === "number" ? sess.rendersUsed : 0;
  const beforeSessionCredits =
    typeof sess.creditsAvailable === "number" ? sess.creditsAvailable : 0;

  const { passkeyLoggedIn, userId: signedInUserId } = getPasskeySession(
    req as any
  );

  // If a user is signed in, always debit DB credits first (no session fallback).
  if (passkeyLoggedIn && signedInUserId) {
    const beforeDb = await getAvailableCreditsForUser(signedInUserId);
    if (beforeDb <= 0) {
      return res.status(400).json({
        ok: false,
        error: "no_credits",
        renders_used: beforeUsed,
        credits_available: beforeDb,
      });
    }

    const updated = await spendUserCredits(signedInUserId, 1);
    const afterDb =
      updated?.total_credits && typeof updated.used_credits === "number"
        ? Math.max(0, updated.total_credits - updated.used_credits)
        : await getAvailableCreditsForUser(signedInUserId);

    sess.rendersUsed = beforeUsed + 1;

    console.log(
      "[credits] use-credit: userId=%s dbCredits %d→%d",
      signedInUserId,
      beforeDb,
      afterDb
    );

    return res.json({
      ok: true,
      sid,
      renders_used: sess.rendersUsed,
      credits_available: afterDb,
    });
  }

  // Primary user id for this session (passkey-based when available)
  const primaryUserId = sess.userId || `anon:${sid}`;

  let dbUserId: string | null = primaryUserId;
  let primaryDbCredits = 0;

  try {
    primaryDbCredits = await getAvailableCreditsForUser(primaryUserId);
  } catch (err) {
    console.error(
      "[credits] dev use-credit: failed to read db credits for userId=%s",
      primaryUserId,
      err
    );
  }

  const beforeDbCredits = primaryDbCredits;

  const totalBefore = beforeSessionCredits + beforeDbCredits;

  if (totalBefore <= 0) {
    // No credits anywhere (session or DB)
    return res.status(400).json({
      ok: false,
      error: "no_credits",
      renders_used: beforeUsed,
      credits_available: totalBefore,
    });
  }

  const used = beforeUsed + 1;
  let sessionCredits = beforeSessionCredits;
  let dbCreditsAfter = beforeDbCredits;

  if (beforeDbCredits > 0 && dbUserId) {
    // Prefer to spend from DB-backed credits.
    try {
      const updated = await spendUserCredits(dbUserId, 1);
      dbCreditsAfter = updated
        ? updated.total_credits - updated.used_credits
        : await getAvailableCreditsForUser(dbUserId);
    } catch (err) {
      console.error(
        "[credits] dev use-credit: db spend failed, falling back to session",
        err
      );
      sessionCredits = Math.max(0, sessionCredits - 1);
    }
  } else {
    // No DB credits; fall back to in-memory dev/session credits.
    sessionCredits = Math.max(0, sessionCredits - 1);
  }

  sess.rendersUsed = used;
  sess.creditsAvailable = sessionCredits;

  const totalAfter = sessionCredits + dbCreditsAfter;

  console.log(
    "[credits] dev use-credit: sid=%s used %d->%d session %d->%d db %d->%d total_after=%d primaryUserId=%s dbUserId=%s",
    sid,
    beforeUsed,
    used,
    beforeSessionCredits,
    sessionCredits,
    beforeDbCredits,
    dbCreditsAfter,
    totalAfter,
    primaryUserId,
    dbUserId
  );

  return res.json({
    ok: true,
    sid,
    renders_used: used,
    credits_available: totalAfter,
  });
});

// --- POST /billing/note_render_complete -----------------------------------------
// Count a render with idempotency protection
router.post("/billing/note_render_complete", express.json(), async (req, res) => {
  const { passkeyLoggedIn, userId } = getPasskeySession(req as any);

  if (!passkeyLoggedIn || !userId) {
    return res.status(401).json({ ok: false, error: "not_authenticated" });
  }

  const { source, idempotencyKey } = req.body || {};

  if (!source || !idempotencyKey) {
    return res.status(400).json({ ok: false, error: "missing_source_or_idempotency_key" });
  }

  if (typeof idempotencyKey !== "string" || idempotencyKey.length === 0) {
    return res.status(400).json({ ok: false, error: "invalid_idempotency_key" });
  }

  try {
    // Check if this idempotency key was already processed
    const existing = await dbGet<{ idempotency_key: string }>(
      "SELECT idempotency_key FROM render_idempotency WHERE idempotency_key = ? AND user_id = ?",
      [idempotencyKey, userId]
    );

    if (existing) {
      console.log("[billing/note_render_complete] duplicate idempotency key, skipping", {
        userId,
        source,
        idempotencyKey,
      });
      return res.json({ ok: true, duplicate: true });
    }

    // Record the idempotency key
    await dbRun(
      `INSERT INTO render_idempotency (idempotency_key, user_id, source, created_at)
       VALUES (?, ?, ?, ${USING_POSTGRES ? 'NOW()' : "datetime('now')"})`,
      [idempotencyKey, userId, source]
    );

    // Call the existing noteRenderComplete logic
    await noteRenderComplete(req);

    console.log("[billing/note_render_complete] render counted", {
      userId,
      source,
      idempotencyKey,
    });

    return res.json({ ok: true });
  } catch (err: any) {
    console.error("[billing/note_render_complete] error", err);
    return res.status(500).json({ ok: false, error: err?.message || "internal_error" });
  }
});



export default router;
