import express from "express";
import crypto from "node:crypto";
import { getAvailableCreditsForUser, spendUserCredits } from "../lib/credits";
import db, { dbGet, dbRun } from "../lib/db";

const INCLUDED_RENDERS_PER_MONTH = Number(process.env.INCLUDED_RENDERS_PER_MONTH || 0);
const DEV_STARTING_CREDITS = Number(process.env.DEV_STARTING_CREDITS || 0);

// Session type stored in req.session (extends cookie-session)
type Sess = {
  sid?: string;
  regChallenge?: string;
  authChallenge?: string;
  userId?: string;
  credentialId?: string;
  loggedIn?: boolean;
  regUserHandle?: string;

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

export async function noteRenderComplete(req: express.Request) {
  const sess = ensureSessionDefaults(req);
  const sid = sess.sid!;

  const beforeUsed =
    typeof sess.rendersUsed === "number" ? sess.rendersUsed : 0;
  const beforeCredits =
    typeof sess.creditsAvailable === "number" ? sess.creditsAvailable : 0;

  const used = beforeUsed + 1;
  let credits = beforeCredits;
  if (credits > 0) {
    credits = credits - 1;
  }

  sess.rendersUsed = used;
  sess.creditsAvailable = credits;

  console.log(
    "[credits] noteRenderComplete: sid=%s used %d→%d credits %d→%d",
    sid,
    beforeUsed,
    used,
    beforeCredits,
    credits
  );
  const userId = deriveUserId(sess) || sess.userId || `anon:${sid}`;
  try {
    const beforeDb = await getAvailableCreditsForUser(userId);
    if (beforeDb > 0) {
      const updated = await spendUserCredits(userId, 1);
      const afterDb = updated
        ? updated.total_credits - updated.used_credits
        : await getAvailableCreditsForUser(userId);

      console.log("[credits] db spend after render", {
        userId,
        beforeDb,
        afterDb,
      });
    } else {
      console.log("[credits] db spend after render: no db credits for user", userId);
    }
  } catch (err) {
    console.error("[credits] db spend after render failed", err);
  }
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

// Lightweight helper for other routes to read the passkey session state
export function getPasskeySession(req: express.Request) {
  const sess = ensureSessionDefaults(req);
  const passkeyLoggedIn = Boolean(sess.loggedIn);
  const allowAnon = !ENFORCE_AUTH_GATE;

  let userId: string | null = null;
  if (passkeyLoggedIn) {
    userId = deriveUserId(sess);
  } else if (allowAnon) {
    userId = sess.userId || `anon:${sess.sid}`;
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

  // Ensure anon identity is stable
  if (allowAnon && sess && !sess.userId) {
    sess.userId = `anon:${sid}`;
  }

  let userId: string | null = null;
  if (passkeyLoggedIn) {
    userId = deriveUserId(sess);
  } else if (allowAnon) {
    userId = sess.userId || `anon:${sid}`;
  }

  // One-time migration: move legacy solo-tester + old anon data to this user
  if (userId && userId !== "solo-tester") {
    try {
      // Determine legacy anon id from session
      const anonLegacy = (sess && typeof sess.userId === "string" && sess.userId.startsWith("anon:") && sess.userId !== userId)
        ? sess.userId
        : null;

      // Build list of legacy IDs to check (dedupe and skip current userId)
      const legacyIds = ["solo-tester", anonLegacy]
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
  }

  const stripeEnabled = Boolean((process.env.STRIPE_SECRET_KEY || "").trim());
  const sessionCredits = stripeEnabled ? 0 : ((passkeyLoggedIn || allowAnon) ? (sess?.creditsAvailable ?? 0) : 0);
  const combinedCredits = (passkeyLoggedIn || allowAnon) ? (sessionCredits + dbCredits) : 0;

  if (passkeyLoggedIn) {
    console.log("[auth/session] entitlement snapshot", {
      userId,
      dbCredits,
      sessionCredits,
      combinedCredits,
    });
  }

  res.setHeader("Cache-Control", "no-store");

  res.json({
    invited,
    hasInviteCode: Boolean((process.env.INVITE_CODE || "").trim()),
    enforceAuthGate: /^true$/i.test(process.env.ENFORCE_AUTH_GATE || ""),
    userId,
    passkey: {
      registered: Boolean(sess?.credentialId),
      loggedIn: passkeyLoggedIn,
    },
    entitlement: {
      plan: sess?.plan || "none",
      included_quota: INCLUDED_RENDERS_PER_MONTH,
      renders_used: sess?.rendersUsed ?? 0,
      credits_available: combinedCredits,
      period_start: sess?.periodStart || null,
      period_end: sess?.periodEnd || null,
    },
  });
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
  }

  return res.json({ ok: true });
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

  // Avoid duplicate credentials on the same device during dev:
  // if we already have a credentialId for this session, tell the browser to exclude it.
  if (sess.credentialId) {
    options.excludeCredentials = [
      {
        type: "public-key",
        id: sess.credentialId,     // base64url string (client will convert to ArrayBuffer)
        transports: ["internal"],  // platform authenticator (Face ID / Touch ID)
      },
    ];
  }

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

  sess.credentialId = String(id);
  const stableUserId = deriveUserId(sess) || "passkey:registered";
  sess.userId = stableUserId;
  sess.loggedIn = true;
  delete sess.regChallenge;
  delete sess.regUserHandle;

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

  // Accept credentialId from the payload (survives restarts)
  sess.credentialId = String(id);
  sess.loggedIn = true;
  delete sess.authChallenge;

  const stableUserId = deriveUserId(sess);
  if (stableUserId) sess.userId = stableUserId;

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



export default router;
