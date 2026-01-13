import "dotenv/config";
import express, { Request, Response } from "express";
import cors from "cors";
import path from "path";
import * as fs from "fs";
import multer from "multer";
import { createRequire } from "module";
import cookieParser from "cookie-parser";
import cookieSession from "cookie-session";
import Stripe from "stripe";
import authRouter, { getPasskeySession, noteRenderComplete, ensureSid } from "./routes/auth";
import db, { ensureSchema, dbGet, dbAll, dbRun, USING_POSTGRES, getUserBilling, upsertUserBilling } from "./lib/db";
import { addUserCredits, getAvailableCredits } from "./lib/credits";
import { isSttEnabled, transcribeChunk } from "./lib/stt";
import { makeAuditMiddleware } from "./lib/audit";
import { makeRateLimiters } from "./middleware/rateLimit";
import { r2Enabled, r2GetObjectStream, r2PutFile } from "./lib/r2";

const app = express();
const PORT = Number(process.env.PORT || 3010);
const OPENAI_API_KEY = process.env.OPENAI_API_KEY || "";
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || "";
const stripe =
  STRIPE_SECRET_KEY
    ? new Stripe(STRIPE_SECRET_KEY)
    : null;
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || "";

// Track http-routes mount status for debugging
let ROUTES_MOUNT_STATUS = { mounted: false, error: null as string | null };

function stripDataUrlPrefix(data: string): { base64: string; mimeFromHeader?: string } {
  const trimmed = data.trim();
  if (!trimmed.startsWith("data:")) {
    return { base64: trimmed };
  }

  const commaIndex = trimmed.indexOf(",");
  if (commaIndex === -1) {
    // Malformed data URL; just return as-is
    return { base64: trimmed };
  }

  const header = trimmed.slice(5, commaIndex); // between "data:" and ","
  // header example: "audio/webm;codecs=opus;base64"
  const parts = header.split(";");
  const mimePart = parts[0]?.trim();
  const mimeFromHeader = mimePart && mimePart.length > 0 ? mimePart : undefined;

  const base64 = trimmed.slice(commaIndex + 1);
  return { base64, mimeFromHeader };
}

// --- tiny helper: safe fetch with timeout ---
async function fetchWithTimeout(input: RequestInfo, init: RequestInit & { timeoutMs?: number } = {}) {
  const { timeoutMs = 15000, ...rest } = init;
  const ac = new AbortController();
  const id = setTimeout(() => ac.abort(), timeoutMs);
  try {
    // @ts-ignore Node 18+ global fetch
    const res = await fetch(input as any, { ...rest, signal: ac.signal } as any);
    return res;
  } finally {
    clearTimeout(id);
  }
}

app.use(cors());

// Use JSON for most routes, but skip it for the Stripe webhook so we can
// access the raw request body for signature verification.
const jsonParser = express.json({ limit: "5mb" });
app.use((req, res, next) => {
  if (req.originalUrl === "/billing/webhook") {
    return next();
  }
  return jsonParser(req, res, next);
});

app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Static UI
app.use("/public", express.static(path.join(process.cwd(), "public")));
app.use("/", express.static(path.join(process.cwd(), "public")));

if (typeof app?.set === "function") { app.set("trust proxy", 1); }

app.use(cookieSession({
  name: "ob_sess",
  secret: process.env.SESSION_SECRET || "dev-secret-change-me",
  sameSite: "lax",
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  maxAge: 1000 * 60 * 60 * 24 * 30, // 30 days
}));

app.use("/auth", authRouter);

const audit = makeAuditMiddleware();
const { debugLimiter, renderLimiter } = makeRateLimiters();

function getSharedSecret(): string | undefined {
  const s = (process.env.SHARED_SECRET || "").trim();
  return s.length > 0 ? s : undefined;
}

type RequestWithCookies = import("express").Request & {
  cookies?: Record<string, unknown>;
};

type ExtractDebug = {
  header: string | undefined;
  query: string | undefined;
  cookie: string | undefined;
};

function extractProvidedSecret(req: import("express").Request): { value: string | undefined; debug: ExtractDebug } {
  // Header: check both X-Shared-Secret and x-shared-secret
  const h = (req.header("X-Shared-Secret") || req.header("x-shared-secret") || "").trim() || undefined;

  // Query param: handle both string and array cases
  const qRaw = (req.query as any)?.secret;
  const q = typeof qRaw === "string" ? qRaw.trim()
          : Array.isArray(qRaw) && typeof qRaw[0] === "string" ? qRaw[0].trim()
          : undefined;

  // Cookie: if cookie-parser is active
  const cookies = (req as RequestWithCookies).cookies;
  const rawCookie = cookies?.["ob_secret"];
  const c = typeof rawCookie === "string" ? rawCookie.trim() : undefined;

  const debug: ExtractDebug = { header: h, query: q, cookie: c };
  const value = h || q || c || undefined;

  return { value, debug };
}

function requireSharedSecret(): import("express").RequestHandler {
  return (req, res, next) => {
    const expected = getSharedSecret();
    if (!expected) return next();

    const { value: provided, debug } = extractProvidedSecret(req);

    if (provided === expected) {
      if (!req.headers["x-shared-secret"]) {
        req.headers["x-shared-secret"] = provided;
      }
      return next();
    }

    res.status(401).json({
      error: "unauthorized",
      reason: "missing_or_invalid_secret",
      got: {
        header: !!debug.header,
        query: !!debug.query,
        cookie: !!debug.cookie,
        expectedSet: !!expected
      }
    });
  };
}

const sharedSecretMiddleware = requireSharedSecret();
app.use("/debug", sharedSecretMiddleware, debugLimiter);
const requireSecret = sharedSecretMiddleware;

function requireAdmin(): import("express").RequestHandler {
  return (req, res, next) => {
    const adminSecret = process.env.ADMIN_SECRET;
    if (!adminSecret || !adminSecret.trim()) {
      return res.status(404).json({ error: "not_found" });
    }

    const provided = (req.headers["x-admin-secret"] as string | undefined)?.trim();
    if (provided === adminSecret.trim()) {
      return next();
    }

    res.status(404).json({ error: "not_found" });
  };
}

// Health
app.get("/health", (_req, res) =>
  res.json({ ok: true, env: { PORT, has_shared_secret: !!getSharedSecret() } })
);
app.get("/health/tts", (_req, res) =>
  res.json({ engine: "openai", has_key: !!OPENAI_API_KEY })
);

// Billing — Phase 1: real Stripe Checkout (test mode)
app.post("/billing/create_checkout", express.json(), async (req: Request, res: Response) => {
  try {
    if (!stripe) {
      return res.status(500).json({
        ok: false,
        error: "stripe_not_configured",
      });
    }

    const body = (req.body || {}) as { planId?: string };
    const planId = body.planId || "credits-100";

    const { passkeyLoggedIn, userId } = getPasskeySession(req);
    if (!passkeyLoggedIn || !userId) {
      return res.status(401).json({
        error: "Sign in with a passkey before purchasing credits.",
      });
    }

    const successUrl =
      process.env.STRIPE_SUCCESS_URL ||
      "https://example.com/offbook-success";
    const cancelUrl =
      process.env.STRIPE_CANCEL_URL ||
      "https://example.com/offbook-cancel";

    // Handle Pro Monthly subscription
    if (planId === "pro-monthly") {
      const priceId = process.env.STRIPE_PRICE_PRO_MONTHLY;
      if (!priceId) {
        return res.status(500).json({
          ok: false,
          error: "missing_stripe_price_pro_monthly",
        });
      }

      const metadata = {
        userId,
        planId,
        purchaseType: "subscription",
      };

      const session = await stripe.checkout.sessions.create({
        mode: "subscription",
        line_items: [
          {
            price: priceId,
            quantity: 1,
          },
        ],
        success_url: successUrl,
        cancel_url: cancelUrl,
        client_reference_id: userId,
        metadata,
        subscription_data: {
          metadata,
        },
      });

      console.log("[billing] stripe checkout session=%s plan=%s mode=subscription", session.id, planId);

      return res.json({
        ok: true,
        checkout_url: session.url,
        mode: "stripe_subscription",
      });
    }

    // Handle top-up credits (existing behavior)
    // Rule B: Top-ups only available while Pro is active
    const userBilling = await getUserBilling(userId);
    const plan = userBilling?.plan || "none";
    const periodEnd = userBilling?.current_period_end ? parseInt(userBilling.current_period_end, 10) : null;

    const periodEndMs = periodEnd ? periodEnd * 1000 : NaN;
    const nowMs = Date.now();
    const proActiveNow = plan === "pro" && (Number.isNaN(periodEndMs) || nowMs < periodEndMs);

    if (!proActiveNow) {
      return res.status(403).json({
        ok: false,
        error: "subscription_required",
        message: "Top-ups are only available while Pro is active.",
      });
    }

    const priceId = process.env.STRIPE_PRICE_TOPUP_100;
    if (!priceId) {
      return res.status(500).json({
        ok: false,
        error: "missing_price_id",
      });
    }

    const metadata = {
      userId,
      planId,
      purchaseType: "topup",
      credits: "100",
      priceId,
    };

    const session = await stripe.checkout.sessions.create({
      mode: "payment",
      line_items: [
        {
          price: priceId,
          quantity: 1,
        },
      ],
      success_url: successUrl,
      cancel_url: cancelUrl,
      client_reference_id: userId,
      metadata,
      payment_intent_data: {
        metadata,
      },
    });

    console.log("[billing] stripe checkout session=%s plan=%s", session.id, planId);

    return res.json({
      ok: true,
      checkout_url: session.url,
      mode: "stripe_test",
    });
  } catch (e: any) {
    console.error("[billing] create_checkout error", e);
    const msg = e?.message || String(e);
    return res.status(500).json({
      ok: false,
      error: msg.slice(0, 200),
    });
  }
});

// Customer portal session endpoint
app.post("/billing/create_portal", express.json(), async (req: Request, res: Response) => {
  try {
    if (!stripe) {
      return res.status(500).json({
        ok: false,
        error: "stripe_not_configured",
      });
    }

    const { passkeyLoggedIn, userId } = getPasskeySession(req);
    if (!passkeyLoggedIn || !userId) {
      return res.status(401).json({
        error: "Sign in with a passkey to manage your subscription.",
      });
    }

    // Load stripe_customer_id from user_billing
    const userBilling = await getUserBilling(userId);

    const stripeCustomerId = userBilling?.stripe_customer_id;
    if (!stripeCustomerId) {
      // If user is marked Pro/active but missing stripe_customer_id, likely post test→live cleanup
      if (userBilling?.plan === "pro" || userBilling?.status === "active") {
        return res.status(409).json({
          ok: false,
          error: "relink_required",
          message: "This account was linked to a Stripe Test subscription. Please subscribe again to create a Live subscription.",
        });
      }

      // Otherwise, user has no subscription at all
      return res.status(400).json({
        ok: false,
        error: "no_customer",
        message: "No active subscription found. Tap Go Pro monthly to subscribe.",
      });
    }

    // Determine return URL
    const returnUrl = process.env.STRIPE_PORTAL_RETURN_URL ||
                     process.env.STRIPE_SUCCESS_URL ||
                     "https://example.com/offbook";

    // Create portal session
    let portalSession;
    try {
      portalSession = await stripe.billingPortal.sessions.create({
        customer: stripeCustomerId,
        return_url: returnUrl,
      });
    } catch (e: any) {
      // Detect stale customer ID (test→live cutover) broadly
      const errMsg = (e?.raw?.message || e?.message || String(e));
      const errCode = (e?.raw?.code || e?.code);
      const errParam = (e?.raw?.param || e?.param);

      const isStaleCustomer =
        /no such customer/i.test(errMsg) ||
        (errCode === "resource_missing" && errParam === "customer");

      if (isStaleCustomer) {
        console.log("[billing] stale customer id, clearing mapping", { userId, stripeCustomerId });

        // Clear stripe IDs (use defaults for missing values)
        await upsertUserBilling({
          user_id: userId,
          plan: userBilling?.plan ?? "free",
          status: userBilling?.status ?? "inactive",
          stripe_customer_id: null,
          stripe_subscription_id: null,
        });

        return res.status(409).json({
          ok: false,
          error: "relink_required",
          message: "This account was linked to a Stripe Test subscription. Please subscribe again to create a Live subscription.",
        });
      }

      // Re-throw other errors to outer catch
      throw e;
    }

    console.log("[billing] created portal session", {
      userId,
      stripeCustomerId,
      portalSessionId: portalSession.id,
    });

    return res.json({
      ok: true,
      url: portalSession.url,
    });
  } catch (e: any) {
    console.error("[billing] create_portal error", e);
    const msg = e?.message || String(e);
    return res.status(500).json({
      ok: false,
      error: msg.slice(0, 200),
    });
  }
});

// Helper to record billing events with idempotency
async function recordBillingEventOnce(
  eventId: string,
  eventType: string,
  userId: string
): Promise<boolean> {
  try {
    if (USING_POSTGRES) {
      const result = await dbRun(
        "INSERT INTO billing_events (event_id, event_type, user_id) VALUES ($1, $2, $3) ON CONFLICT (event_id) DO NOTHING",
        [eventId, eventType, userId]
      );
      return (result.rowCount || 0) > 0;
    } else {
      const result = await dbRun(
        "INSERT OR IGNORE INTO billing_events (event_id, event_type, user_id) VALUES (?, ?, ?)",
        [eventId, eventType, userId]
      );
      return (result.changes || 0) > 0;
    }
  } catch (err) {
    console.error("[billing] failed to record billing event", err);
    throw err;
  }
}

// Helper to safely convert period timestamps to string or null for BIGINT columns
// NEVER returns empty string - only valid string number or null
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

function stripeId(val: any): string | null {
  if (!val) return null;
  if (typeof val === "string") return val;
  if (typeof val === "object" && typeof val.id === "string") return val.id;
  return null;
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
        console.warn("[billing] failed to retrieve preferred subscription", {
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
      console.log("[billing] no active-ish subscriptions found", { stripeCustomerId });
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
    console.error("[billing] resolveBestSubscription failed", {
      stripeCustomerId,
      preferredSubscriptionId,
      error: (err as any)?.message || String(err),
    });
    return null;
  }
}

async function refreshStripePeriodForUser(opts: {
  stripe: Stripe;
  userId: string;
  stripeCustomerId: string;
  stripeSubscriptionId: string | null;
}) {
  const { stripe, userId, stripeCustomerId, stripeSubscriptionId } = opts;

  if (!stripe) return null;

  try {
    // Use resolveBestSubscription to get the correct active subscription
    const sub = await resolveBestSubscription(stripe, stripeCustomerId, stripeSubscriptionId);

    if (!sub) {
      console.log("[billing] no active subscription found", { userId, stripeCustomerId });
      return null;
    }

    const subId = sub.id;
    const { start, end } = getSubscriptionPeriodFromItems(sub);
    const cps = toBigintOrNull(start);
    const cpe = toBigintOrNull(end);

    // Required clear log line
    const startISO = cps ? new Date(parseInt(cps, 10) * 1000).toISOString() : null;
    const endISO = cpe ? new Date(parseInt(cpe, 10) * 1000).toISOString() : null;
    console.log(`[billing] resolved stripe sub=${subId} status=${sub.status} period=${startISO}..${endISO}`);

    // Only write if we actually got valid numbers back
    if (cps && cpe) {
      if (USING_POSTGRES) {
        await dbRun(
          `UPDATE user_billing
           SET stripe_subscription_id = $2,
               current_period_start = $3,
               current_period_end = $4
           WHERE user_id = $1`,
          [userId, subId, cps, cpe]
        );
      } else {
        await dbRun(
          `UPDATE user_billing
           SET stripe_subscription_id = ?,
               current_period_start = ?,
               current_period_end = ?
           WHERE user_id = ?`,
          [subId, cps, cpe, userId]
        );
      }
    }

    return { subId, cps, cpe, status: sub.status };
  } catch (e: any) {
    console.warn("[billing] stripe period refresh failed", {
      userId,
      stripeCustomerId,
      stripeSubscriptionId: opts.stripeSubscriptionId,
      msg: e?.message || String(e),
    });
    return null;
  }
}

// Shared function to process Stripe billing events
async function processStripeBillingEvent(event: Stripe.Event): Promise<{ processed: boolean; reason?: string }> {
  if (!stripe) {
    return { processed: false, reason: "stripe_not_configured" };
  }

  const eventType = event.type;
  const eventId = event.id;

  // Handle checkout.session.completed
  if (eventType === "checkout.session.completed") {
    const session = event.data.object as Stripe.Checkout.Session;

    // Determine userId from session (prefer metadata first)
    const userIdFromMetadata =
      (session.metadata && (session.metadata as any).userId) || null;
    const userIdFromClientRef = session.client_reference_id;
    const userId = (userIdFromMetadata || userIdFromClientRef || "").toString().trim();

    if (!userId) {
      console.warn("[billing] webhook: missing userId on session", session.id);
      return { processed: false, reason: "missing_userId" };
    }

    // Read purchaseType and credits from metadata early
    const purchaseType = (session.metadata?.purchaseType || "topup").toString().trim();
    const creditsStr = (session.metadata?.credits || "100").toString().trim();
    const credits = parseInt(creditsStr, 10);

    // Determine if this is a subscription checkout
    const isSubscription = session.mode === "subscription" || purchaseType === "subscription";

    // Handle subscription checkout (idempotent upsert first, then record event)
    if (isSubscription) {
      let stripeCustomerId = session.customer ? session.customer.toString() : null;
      let stripeSubscriptionId = session.subscription ? session.subscription.toString() : null;

      // Fallback: if customer or subscription is missing, retrieve session with expand
      if (!stripeCustomerId || !stripeSubscriptionId) {
        console.log("[billing] subscription checkout missing customer or subscription, retrieving with expand", {
          eventId,
          userId,
          sessionId: session.id,
        });

        try {
          const expandedSession = await stripe.checkout.sessions.retrieve(session.id, {
            expand: ['subscription', 'customer']
          });

          stripeCustomerId = stripeCustomerId || (expandedSession.customer ? expandedSession.customer.toString() : null);
          stripeSubscriptionId = stripeSubscriptionId || (expandedSession.subscription ? expandedSession.subscription.toString() : null);

          console.log("[billing] retrieved expanded session", {
            eventId,
            userId,
            stripeCustomerId,
            stripeSubscriptionId,
          });
        } catch (err) {
          console.error("[billing] failed to retrieve expanded session", err);
        }
      }

      if (!stripeCustomerId || !stripeSubscriptionId) {
        console.error("[billing] subscription checkout still missing customer or subscription after expand", {
          eventId,
          userId,
          stripeCustomerId,
          stripeSubscriptionId,
        });
        return { processed: false, reason: "missing_subscription_data" };
      }

      // Retrieve subscription to get period info (optional - proceed even if fails)
      let subscription: Stripe.Subscription | null = null;
      try {
        subscription = await stripe.subscriptions.retrieve(stripeSubscriptionId);
        const { start, end } = getSubscriptionPeriodFromItems(subscription);
        console.log("[billing] retrieved subscription for checkout", {
          eventId,
          userId,
          stripeSubscriptionId,
          status: subscription.status,
          current_period_start: start,
          current_period_end: end,
        });
      } catch (err) {
        console.warn("[billing] failed to retrieve subscription, proceeding with defaults", {
          eventId,
          userId,
          stripeSubscriptionId,
          error: (err as any)?.message || String(err),
        });
      }

      const status = subscription?.status || "active";
      // Use helper to ensure period fields are never empty strings
      const { start, end } = getSubscriptionPeriodFromItems(subscription);
      const currentPeriodStart = toBigintOrNull(start);
      const currentPeriodEnd = toBigintOrNull(end);

      // Always upsert user_billing record (idempotent - runs even on retries)
      await upsertUserBilling({
        user_id: userId,
        plan: "pro",
        status,
        stripe_customer_id: stripeCustomerId,
        stripe_subscription_id: stripeSubscriptionId,
        current_period_start: currentPeriodStart,
        current_period_end: currentPeriodEnd,
        included_quota: 120,
        renders_used: 0,
      });

      // After successful upsert, record billing event for duplicate tracking
      try {
        const isNewEvent = await recordBillingEventOnce(eventId, eventType, userId);
        if (!isNewEvent) {
          console.log("[billing] subscription duplicate event detected (state already applied)", {
            eventId,
            userId,
          });
        }
      } catch (err) {
        console.error("[billing] failed to record billing event (state already applied)", err);
      }

      console.log("[billing] subscription created", {
        userId,
        stripeCustomerId,
        stripeSubscriptionId,
        status,
        currentPeriodStart,
        currentPeriodEnd,
        eventId,
      });

      return { processed: true };
    }

    // For topup checkouts: check idempotency BEFORE crediting
    let isNewEvent = false;
    try {
      isNewEvent = await recordBillingEventOnce(eventId, eventType, userId);
    } catch (err) {
      console.error("[billing] failed to record billing event", err);
      throw err;
    }

    // If duplicate event, return success without crediting
    if (!isNewEvent) {
      console.log("[billing] webhook duplicate topup event detected", {
        eventId,
        userId,
      });
      return { processed: true, reason: "duplicate_event" };
    }

    // Only credit if purchaseType === "topup" AND credits > 0
    if (purchaseType === "topup" && credits > 0) {
      const updated = await addUserCredits(userId, credits);

      const totalCredits = updated.total_credits;
      const usedCredits = updated.used_credits;
      const availableCredits = getAvailableCredits(updated);

      console.log("[billing] webhook credited", {
        userId,
        creditsAdded: credits,
        totalCredits,
        usedCredits,
        availableCredits,
        stripeEventId: eventId,
        purchaseType,
      });
      return { processed: true };
    } else {
      console.log("[billing] webhook: skipped crediting (not a topup or credits=0)", {
        userId,
        purchaseType,
        credits,
        eventId,
      });
      return { processed: false, reason: "not_topup_or_zero_credits" };
    }
  }

  // Handle charge.refunded
  if (eventType === "charge.refunded") {
    const charge = event.data.object as Stripe.Charge;

    // Read userId and credits from charge metadata
    let userId = (charge.metadata?.userId || "").toString().trim();
    let creditsStr = (charge.metadata?.credits || "").toString().trim();

    // Fallback to PaymentIntent metadata if charge metadata is empty
    if ((!userId || !creditsStr) && charge.payment_intent && stripe) {
      try {
        // Determine piId (can be string or object)
        const piId = typeof charge.payment_intent === "string"
          ? charge.payment_intent
          : (charge.payment_intent as any).id;

        if (piId) {
          const pi = await stripe.paymentIntents.retrieve(piId);
          userId = userId || (pi.metadata?.userId || "").toString().trim();
          creditsStr = creditsStr || (pi.metadata?.credits || "").toString().trim();

          console.log("[billing] refund metadata fallback", {
            chargeId: charge.id,
            piId,
            hasUserId: !!userId,
            hasCredits: !!creditsStr,
          });
        }
      } catch (err) {
        console.error("[billing] failed to retrieve payment intent for refund fallback", err);
      }
    }

    const credits = parseInt(creditsStr, 10);

    if (!userId || !creditsStr || isNaN(credits)) {
      console.log("[billing] refund missing metadata", {
        eventId,
        chargeId: charge.id,
        payment_intent: charge.payment_intent,
      });
      return { processed: false, reason: "missing_metadata" };
    }

    // Calculate proportional credit reversal for partial refunds
    const chargeAmount = charge.amount || 0;
    const amountRefunded = charge.amount_refunded || 0;

    if (chargeAmount === 0) {
      console.log("[billing] refund charge amount is zero", {
        eventId,
        chargeId: charge.id,
        userId,
      });
      return { processed: false, reason: "charge_amount_zero" };
    }

    const ratio = amountRefunded / chargeAmount;
    const creditsToReverse = Math.round(credits * ratio);

    if (creditsToReverse <= 0) {
      console.log("[billing] refund credits to reverse is zero or negative", {
        eventId,
        chargeId: charge.id,
        userId,
        credits,
        chargeAmount,
        amountRefunded,
        ratio,
        creditsToReverse,
      });
      return { processed: false, reason: "credits_to_reverse_zero" };
    }

    // Record billing event first for idempotency
    let isNewEvent = false;
    try {
      isNewEvent = await recordBillingEventOnce(eventId, eventType, userId);
    } catch (err) {
      console.error("[billing] failed to record billing event", err);
      throw err;
    }

    // If duplicate event, return success without reversing credits
    if (!isNewEvent) {
      console.log("[billing] webhook duplicate refund event detected", {
        eventId,
        userId,
        chargeId: charge.id,
      });
      return { processed: false, reason: "duplicate_event" };
    }

    // Reverse the top-up credits by adding negative credits (proportional for partial refunds)
    const updated = await addUserCredits(userId, -creditsToReverse);

    const totalCredits = updated.total_credits;
    const usedCredits = updated.used_credits;
    const availableCredits = getAvailableCredits(updated);

    console.log("[billing] refund reversed credits", {
      userId,
      originalCredits: credits,
      creditsReversed: creditsToReverse,
      chargeAmount,
      amountRefunded,
      ratio,
      totalCredits,
      usedCredits,
      availableCredits,
      eventId,
      chargeId: charge.id,
    });
    return { processed: true };
  }

  // Handle invoice.payment_succeeded (subscription renewal)
  if (eventType === "invoice.payment_succeeded") {
    const invoice = event.data.object as Stripe.Invoice;
    const stripeSubscriptionId = (invoice as any).subscription ? (invoice as any).subscription.toString() : null;

    if (!stripeSubscriptionId) {
      console.log("[billing] invoice.payment_succeeded without subscription", { eventId });
      return { processed: false, reason: "no_subscription" };
    }

    // Retrieve subscription to get userId from metadata
    let subscription: Stripe.Subscription | null = null;
    try {
      subscription = await stripe.subscriptions.retrieve(stripeSubscriptionId);
    } catch (err) {
      console.error("[billing] failed to retrieve subscription for invoice", err);
      return { processed: false, reason: "subscription_retrieval_failed" };
    }

    const userId = (subscription.metadata?.userId || "").toString().trim();
    if (!userId) {
      console.error("[billing] subscription missing userId in metadata", {
        eventId,
        stripeSubscriptionId,
      });
      return { processed: false, reason: "missing_userId" };
    }

    // Record billing event for idempotency
    let isNewEvent = false;
    try {
      isNewEvent = await recordBillingEventOnce(eventId, eventType, userId);
    } catch (err) {
      console.error("[billing] failed to record billing event", err);
      throw err;
    }

    if (!isNewEvent) {
      console.log("[billing] webhook duplicate invoice event detected", {
        eventId,
        userId,
      });
      return { processed: false, reason: "duplicate_event" };
    }

    // Update subscription status and reset monthly counter
    const status = subscription.status || "active";
    // Use helper to ensure period fields are never empty strings
    const currentPeriodStart = toBigintOrNull((subscription as any)?.current_period_start);
    const currentPeriodEnd = toBigintOrNull((subscription as any)?.current_period_end);

    console.log("[billing] subscription period data for invoice", {
      eventId,
      userId,
      stripeSubscriptionId,
      current_period_start: (subscription as any)?.current_period_start,
      current_period_end: (subscription as any)?.current_period_end,
      currentPeriodStart,
      currentPeriodEnd,
    });

    await upsertUserBilling({
      user_id: userId,
      plan: "pro",
      status,
      current_period_start: currentPeriodStart,
      current_period_end: currentPeriodEnd,
      included_quota: 120,
      renders_used: 0,
    });

    console.log("[billing] invoice.payment_succeeded - subscription renewed", {
      userId,
      stripeSubscriptionId,
      status,
      currentPeriodStart,
      currentPeriodEnd,
      eventId,
    });

    return { processed: true };
  }

  // Handle invoice.payment_failed
  if (eventType === "invoice.payment_failed") {
    const invoice = event.data.object as Stripe.Invoice;
    const stripeSubscriptionId = (invoice as any).subscription ? (invoice as any).subscription.toString() : null;

    if (!stripeSubscriptionId) {
      console.log("[billing] invoice.payment_failed without subscription", { eventId });
      return { processed: false, reason: "no_subscription" };
    }

    // Retrieve subscription to get userId from metadata
    let subscription: Stripe.Subscription | null = null;
    try {
      subscription = await stripe.subscriptions.retrieve(stripeSubscriptionId);
    } catch (err) {
      console.error("[billing] failed to retrieve subscription for failed invoice", err);
      return { processed: false, reason: "subscription_retrieval_failed" };
    }

    const userId = (subscription.metadata?.userId || "").toString().trim();
    if (!userId) {
      console.error("[billing] subscription missing userId in metadata", {
        eventId,
        stripeSubscriptionId,
      });
      return { processed: false, reason: "missing_userId" };
    }

    // Record billing event for idempotency
    let isNewEvent = false;
    try {
      isNewEvent = await recordBillingEventOnce(eventId, eventType, userId);
    } catch (err) {
      console.error("[billing] failed to record billing event", err);
      throw err;
    }

    if (!isNewEvent) {
      console.log("[billing] webhook duplicate invoice failed event detected", {
        eventId,
        userId,
      });
      return { processed: false, reason: "duplicate_event" };
    }

    // Mark subscription as past_due using helper
    await upsertUserBilling({
      user_id: userId,
      plan: "pro",
      status: "past_due",
    });

    console.log("[billing] invoice.payment_failed - subscription marked past_due", {
      userId,
      stripeSubscriptionId,
      eventId,
    });

    return { processed: true };
  }

  // Handle customer.subscription.deleted
  if (eventType === "customer.subscription.deleted") {
    const subscription = event.data.object as Stripe.Subscription;
    const userId = (subscription.metadata?.userId || "").toString().trim();

    if (!userId) {
      console.error("[billing] subscription.deleted missing userId in metadata", {
        eventId,
        subscriptionId: subscription.id,
      });
      return { processed: false, reason: "missing_userId" };
    }

    // Record billing event for idempotency
    let isNewEvent = false;
    try {
      isNewEvent = await recordBillingEventOnce(eventId, eventType, userId);
    } catch (err) {
      console.error("[billing] failed to record billing event", err);
      throw err;
    }

    if (!isNewEvent) {
      console.log("[billing] webhook duplicate subscription.deleted event detected", {
        eventId,
        userId,
      });
      return { processed: false, reason: "duplicate_event" };
    }

    // Mark subscription as canceled but keep customer_id using helper
    await upsertUserBilling({
      user_id: userId,
      plan: "none",
      status: "canceled",
    });

    console.log("[billing] subscription.deleted - subscription canceled", {
      userId,
      subscriptionId: subscription.id,
      eventId,
    });

    return { processed: true };
  }

  return { processed: false, reason: "unhandled_event_type" };
}

// Billing — Stripe webhook (test mode, signature-verified)
app.post(
  "/billing/webhook",
  // Stripe requires the raw request body for signature verification.
  express.raw({ type: "application/json" }),
  async (req: Request, res: Response) => {

    try {
      if (!stripe || !STRIPE_WEBHOOK_SECRET) {
        console.warn(
          "[billing] webhook misconfigured (missing stripe or STRIPE_WEBHOOK_SECRET)"
        );
        // Return 200 so Stripe does not endlessly retry in dev.
        return res.status(200).json({
          ok: true,
          ignored: true,
          reason: "billing_not_configured",
        });
      }

      const sig = req.header("stripe-signature") || "";
      const rawBody = req.body as Buffer;

      let event: Stripe.Event;
      try {
        event = stripe.webhooks.constructEvent(
          rawBody,
          sig,
          STRIPE_WEBHOOK_SECRET
        );
      } catch (err: any) {
        console.error(
          "[billing] webhook signature verification failed",
          err?.message || err
        );
        return res.status(400).send("Webhook signature verification failed");
      }

      const eventType = event.type;
      const eventId = event.id;

      console.log("[billing] webhook raw hit", {
        path: req.path,
        stripeSignature: sig,
        eventType,
        eventId,
      });

      // Process the event using shared logic
      let result;
      try {
        result = await processStripeBillingEvent(event);
      } catch (err: any) {
        console.error("[billing] webhook processing error", {
          eventId,
          eventType,
          error: err?.message || String(err),
        });
        return res.status(500).json({
          ok: false,
          error: "webhook_error",
          eventId,
          eventType,
          message: (err?.message || String(err)).slice(0, 200),
        });
      }

      return res.json({
        received: true,
        processed: result.processed,
        reason: result.reason || null,
      });
    } catch (e: any) {
      console.error("[billing] webhook error", e);
      return res.status(500).json({ ok: false, error: "webhook_error" });
    }
  }
);

// Debug endpoint to replay a Stripe event by ID
app.get("/debug/billing/replay_event", requireSecret, async (req: Request, res: Response) => {
  try {
    const event_id = String(req.query.event_id || "").trim();

    if (!event_id) {
      return res.status(400).json({ ok: false, error: "missing_event_id" });
    }

    if (!stripe) {
      return res.status(400).json({ ok: false, error: "stripe_not_configured" });
    }

    // Retrieve the event from Stripe
    let event: Stripe.Event;
    try {
      event = await stripe.events.retrieve(event_id);
    } catch (err: any) {
      console.error("[billing] replay_event failed to retrieve event", err);
      return res.status(404).json({
        ok: false,
        error: "event_not_found",
        message: err?.message || String(err),
      });
    }

    console.log("[billing] replay_event", { event_id, type: event.type });

    // Process the event using shared logic (idempotency is handled inside)
    const result = await processStripeBillingEvent(event);

    return res.json({
      ok: true,
      event_id,
      event_type: event.type,
      processed: result.processed,
      reason: result.reason,
    });
  } catch (e: any) {
    console.error("[billing] replay_event error", e);
    return res.status(500).json({
      ok: false,
      error: "replay_failed",
      message: e?.message || String(e),
    });
  }
});

// Debug endpoint to replay a refund using a Stripe charge ID
app.get("/debug/billing/replay_refund_by_charge", async (req: Request, res: Response) => {
  try {
    // Production safety gate
    if (process.env.ENABLE_BILLING_ADMIN_TOOLS !== "1") {
      return res.status(404).send("Not Found");
    }

    // Billing admin secret check (separate from SHARED_SECRET)
    const billingAdminSecret = process.env.BILLING_ADMIN_SECRET;
    if (!billingAdminSecret || !billingAdminSecret.trim()) {
      return res.status(404).send("Not Found");
    }

    const providedSecret = (req.query.admin_secret as string) || req.header("X-Billing-Admin-Secret");
    if (!providedSecret || providedSecret.trim() !== billingAdminSecret.trim()) {
      return res.status(401).json({ ok: false, error: "unauthorized" });
    }

    const charge_id = String(req.query.charge_id || "").trim();

    if (!charge_id) {
      return res.status(400).json({ ok: false, error: "missing_charge_id" });
    }

    if (!stripe) {
      return res.status(400).json({ ok: false, error: "stripe_not_configured" });
    }

    // Retrieve the charge with expanded payment_intent
    let charge: Stripe.Charge;
    try {
      charge = await stripe.charges.retrieve(charge_id, {
        expand: ['payment_intent']
      });
    } catch (err: any) {
      console.error("[billing] replay_refund_by_charge failed to retrieve charge", err);
      return res.status(404).json({
        ok: false,
        error: "charge_not_found",
        message: err?.message || String(err),
      });
    }

    // Verify the charge is refunded
    if (!charge.refunded && (!charge.amount_refunded || charge.amount_refunded === 0)) {
      return res.status(400).json({
        ok: false,
        error: "charge_not_refunded",
        message: "Charge has not been refunded",
      });
    }

    // Read metadata from expanded payment_intent first, fallback to charge metadata
    let userId = "";
    let creditsStr = "";

    // Try payment_intent metadata first
    if (charge.payment_intent && typeof charge.payment_intent === 'object') {
      const pi = charge.payment_intent as Stripe.PaymentIntent;
      userId = (pi.metadata?.userId || "").toString().trim();
      creditsStr = (pi.metadata?.credits || "").toString().trim();
    }

    // Fallback to charge metadata if needed
    if (!userId || !creditsStr) {
      userId = userId || (charge.metadata?.userId || "").toString().trim();
      creditsStr = creditsStr || (charge.metadata?.credits || "").toString().trim();
    }

    const credits = parseInt(creditsStr, 10);

    if (!userId || !creditsStr || isNaN(credits)) {
      return res.status(400).json({
        ok: false,
        error: "missing_metadata",
        message: "Missing userId or credits in metadata",
      });
    }

    // Calculate proportional credit reversal for partial refunds
    const chargeAmount = charge.amount || 0;
    const amountRefunded = charge.amount_refunded || 0;

    if (chargeAmount === 0) {
      return res.json({
        ok: true,
        charge_id,
        userId,
        creditsDelta: 0,
        skipped: true,
        reason: "charge_amount_zero"
      });
    }

    const ratio = amountRefunded / chargeAmount;
    const creditsToReverse = Math.round(credits * ratio);

    if (creditsToReverse <= 0) {
      return res.json({
        ok: true,
        charge_id,
        userId,
        creditsDelta: 0,
        skipped: true,
        reason: "credits_to_reverse_zero"
      });
    }

    // Idempotency: use unique key for manual refund replay
    const eventId = `manual_refund:${charge_id}`;
    const eventType = "manual_refund_replay";

    let isNewEvent = false;
    try {
      isNewEvent = await recordBillingEventOnce(eventId, eventType, userId);
    } catch (err) {
      console.error("[billing] replay_refund_by_charge failed to record event", err);
      return res.status(500).json({ ok: false, error: "event_recording_failed" });
    }

    // If duplicate, return early
    if (!isNewEvent) {
      console.log("[billing] replay_refund_by_charge duplicate detected", {
        charge_id,
        userId,
      });
      return res.json({
        ok: true,
        charge_id,
        userId,
        originalCredits: credits,
        creditsReversed: creditsToReverse,
        chargeAmount,
        amountRefunded,
        ratio,
        skippedDuplicate: true,
      });
    }

    // Reverse the credits proportionally
    const updated = await addUserCredits(userId, -creditsToReverse);

    console.log("[billing] replay_refund_by_charge reversed credits", {
      charge_id,
      userId,
      originalCredits: credits,
      creditsReversed: creditsToReverse,
      chargeAmount,
      amountRefunded,
      ratio,
      totalCredits: updated.total_credits,
      usedCredits: updated.used_credits,
      availableCredits: getAvailableCredits(updated),
    });

    return res.json({
      ok: true,
      charge_id,
      userId,
      originalCredits: credits,
      creditsReversed: creditsToReverse,
      chargeAmount,
      amountRefunded,
      ratio,
      skippedDuplicate: false,
    });
  } catch (e: any) {
    console.error("[billing] replay_refund_by_charge error", e);
    return res.status(500).json({
      ok: false,
      error: "replay_failed",
      message: e?.message || String(e),
    });
  }
});

// Debug endpoint to repair subscription period dates
app.get("/debug/billing/repair_period", requireSecret, async (req: Request, res: Response) => {
  try {
    const { userId: sessionUserId } = getPasskeySession(req);
    if (!sessionUserId) {
      return res.status(401).json({ ok: false, error: "not_authenticated" });
    }

    const billing = await getUserBilling(sessionUserId);
    if (!billing?.stripe_customer_id) {
      return res.json({ ok: true, repaired: false, reason: "missing_stripe_customer_id" });
    }

    if (!stripe) {
      return res.status(500).json({ ok: false, error: "stripe_not_configured" });
    }

    const out = await refreshStripePeriodForUser({
      stripe,
      userId: sessionUserId,
      stripeCustomerId: billing.stripe_customer_id,
      stripeSubscriptionId: billing.stripe_subscription_id || null,
    });

    const billing2 = await getUserBilling(sessionUserId);
    return res.json({ ok: true, repaired: true, out, billing: billing2 });
  } catch (e: any) {
    console.error("[billing] repair_period error", e);
    return res.status(500).json({
      ok: false,
      error: "repair_failed",
      message: e?.message || String(e),
    });
  }
});

// Debug endpoint to attach a Stripe subscription to current user
app.get("/debug/billing/attach_subscription", requireSecret, async (req: Request, res: Response) => {
  try {
    const { userId } = getPasskeySession(req);
    if (!userId) {
      return res.status(401).json({ ok: false, error: "not_authenticated" });
    }

    if (!stripe) {
      return res.status(500).json({ ok: false, error: "stripe_not_configured" });
    }

    const sub_id = String(req.query.sub_id || "").trim();
    if (!sub_id) {
      return res.status(400).json({ ok: false, error: "missing_sub_id" });
    }

    // Retrieve the subscription
    const sub = await stripe.subscriptions.retrieve(sub_id);

    // Extract customer ID (handle both string and object)
    const customerId = stripeId(sub.customer);
    if (!customerId) {
      return res.status(400).json({ ok: false, error: "missing_customer_id" });
    }

    // Extract period dates from subscription items
    const { start, end } = getSubscriptionPeriodFromItems(sub);
    const cps = toBigintOrNull(start);
    const cpe = toBigintOrNull(end);

    // Best-effort: update customer metadata with userId
    try {
      await stripe.customers.update(customerId, {
        metadata: { userId },
      });
    } catch (err) {
      console.warn("[billing] attach_subscription: failed to update customer metadata", {
        customerId,
        userId,
        error: (err as any)?.message,
      });
      // Don't fail - continue
    }

    // Upsert user billing (omit renders_used to preserve existing value)
    await upsertUserBilling({
      user_id: userId,
      plan: "pro",
      status: sub.status || "active",
      stripe_customer_id: customerId,
      stripe_subscription_id: sub.id,
      current_period_start: cps,
      current_period_end: cpe,
      included_quota: 120,
    });

    console.log("[billing] attach_subscription: linked subscription to user", {
      userId,
      customerId,
      subscriptionId: sub.id,
      status: sub.status,
      cps,
      cpe,
    });

    return res.json({
      ok: true,
      userId,
      customerId,
      subscriptionId: sub.id,
      status: sub.status,
      current_period_start: cps,
      current_period_end: cpe,
    });
  } catch (e: any) {
    console.error("[billing] attach_subscription error", e);
    return res.status(500).json({
      ok: false,
      error: "attach_failed",
      message: e?.message || String(e),
    });
  }
});

// ---- In-memory store (fallback + rendered assets)
type Line = { speaker: string; text: string };
type Scene = { id: string; title: string; lines: Line[] };
type Script = { id: string; title: string; scenes: Scene[]; voices: Record<string, string> };

type RenderJob = {
  status: "queued" | "complete" | "error";
  url?: string;
  err?: string;
  accounted?: boolean;
  manifest_url?: string;
};

type RenderManifest = {
  render_id: string;
  script_id: string;
  scene_id: string;
  role: string;
  created_at: string;
  segments: Array<{
    segment_index: number;
    script_line_index: number;
    speaker: string;
    text: string;
    url: string;
  }>;
};

const mem = {
  scripts: new Map<string, Script>(),
  renders: new Map<string, RenderJob>(),
  assets: new Map<string, Buffer>(), // id -> MP3 bytes (for renders and single-line TTS)
};
const ASSETS_DIR = path.join(process.cwd(), "assets");
if (!fs.existsSync(ASSETS_DIR)) fs.mkdirSync(ASSETS_DIR, { recursive: true });
const upload = multer({ storage: multer.memoryStorage() });

function genId(prefix: string) {
  return prefix + "-" + Math.random().toString(36).slice(2, 10);
}

// ---------- Normalization & parsing ----------
function normalizePdfText(raw: string): string {
  if (!raw) return "";
  let t = raw.replace(/\r\n/g, "\n");
  t = t.replace(/-\n/g, ""); // dehyphenate line breaks
  t = t.replace(/\b(?:[A-Z]\s){2,}[A-Z]\b/g, s => s.replace(/\s+/g, "")); // J A N E -> JANE
  t = t.replace(/[ \t]{2,}/g, " ");
  return t;
}

// Common non-character headings/directions seen in OCR
const NON_CHAR_TOKENS = new Set([
  "INSERT","MORE","HERE","CONTINUED","CONT'D","CONT’D",
  "ANGLE","ANGLE ON","CLOSE","CLOSE ON","WIDER","WIDE",
  "CUT TO","CUT TO:","DISSOLVE TO","SMASH CUT","FADE IN","FADE OUT",
  "CORNER OF THE ROOM","CORNER","ROOM","POV","MOMENTS LATER","LATER",
  "DAY","NIGHT","MORNING","EVENING","DAWN","DUSK",
]);
function looksLikePageNumber(l: string) { return /^\d+\.?$/.test(l.trim()); }
function endsWithPeriodWord(l: string) { return /^[A-Z0-9 .,'\-()]+?\.$/.test(l.trim()); }
function containsHeadingPhrases(l: string) {
  const s = l.trim().toUpperCase();
  if (s.includes(" OF THE ")) return true;
  if (/^(INSERT|ANGLE|CLOSE|WIDER|WIDE)\b/.test(s)) return true;
  return false;
}
function isSceneHeader(l: string) {
  return /^(INT\.|EXT\.|INT\/EXT\.|SCENE|SHOT|MONTAGE|CUT TO:|FADE (IN|OUT):?)/i.test(l);
}
function isNonCharacterLabel(s: string) {
  const trimmed = (s || "").trim();
  const core = trimmed.replace(/[().]/g, "").replace(/\s+/g, " ").trim().toUpperCase();
  if (!core) return true;
  if (NON_CHAR_TOKENS.has(core)) return true;
  if (looksLikePageNumber(core)) return true;
  if (endsWithPeriodWord(trimmed)) return true;
  if (containsHeadingPhrases(core)) return true;
  if (core.split(" ").length >= 3 && /\b(OF|THE|ROOM|INT|EXT|CUT|TO|ON)\b/.test(core)) return true;
  return false;
}
function isAllCapsName(l: string) {
  const s = l.trim();
  if (!s) return false;
  if (!/^[A-Z0-9 .,'\-()]+$/.test(s)) return false;
  if (/[a-z]/.test(s)) return false;
  if (s.length > 40) return false;
  if (isSceneHeader(s)) return false;
  if (isNonCharacterLabel(s)) return false;
  return true;
}
function isTitleCaseName(l: string) {
  const s = l.trim();
  if (containsHeadingPhrases(s)) return false;
  if (/^(Insert|Angle|Close|Wide|Exterior|Interior)\b/.test(s)) return false;
  return /^([A-Z][a-z]+\.?)(\s+[A-Z][a-z]+\.?){0,3}$/.test(s) && !isSceneHeader(s) && s.length <= 40;
}
function isParenthetical(l: string) { return /^\(.*\)$/.test(l.trim()); }
function colonNameMatch(l: string) {
  const m = l.match(/^([A-Za-z][A-Za-z0-9 .&()'\-]+)\s*:\s*(.+)$/);
  if (!m) return null;
  const speakerRaw = m[1].trim();
  if (isNonCharacterLabel(speakerRaw)) return null;
  const speaker = speakerRaw.replace(/[()]/g, "").trim();
  const text = m[2].trim();
  return { speaker, text };
}
function parseTextToScenes(title: string, raw: string): Scene[] {
  const scene: Scene = { id: genId("scn"), title: title || "Scene 1", lines: [] };
  const lines = (raw || "").split(/\n/).map(l => l.replace(/\t/g, " ").trim());
  let i = 0;
  while (i < lines.length) {
    let l = lines[i];
    if (!l || looksLikePageNumber(l) || isSceneHeader(l)) { i++; continue; }
    const colon = colonNameMatch(l);
    if (colon && colon.speaker && colon.text) {
      scene.lines.push({ speaker: colon.speaker.toUpperCase(), text: colon.text });
      i++; continue;
    }
    if (isAllCapsName(l) || isTitleCaseName(l)) {
      let speaker = l.replace(/[()]/g, "").trim();
      if (isNonCharacterLabel(speaker)) { i++; continue; }
      let j = i + 1;
      if (j < lines.length && isParenthetical(lines[j])) j++;
      const buf: string[] = [];
      while (j < lines.length) {
        const nxt = lines[j];
        if (!nxt || isSceneHeader(nxt) || isAllCapsName(nxt) || isTitleCaseName(nxt)) break;
        if (isParenthetical(nxt)) { j++; continue; }
        if (/^[A-Z0-9 .,'\-()]+?\.$/.test(nxt) && !/[a-z]/.test(nxt)) { j++; continue; }
        buf.push(nxt);
        j++;
      }
      const text = buf.join(" ").replace(/\s{2,}/g, " ").trim();
      if (speaker && text) scene.lines.push({ speaker: speaker.toUpperCase(), text });
      i = j + (lines[j] === "" ? 1 : 0);
      continue;
    }
    if (/^[A-Z0-9 .,'\-()]{3,}$/.test(l) && !/[a-z]/.test(l)) { i++; continue; }
    scene.lines.push({ speaker: "NARRATOR", text: l });
    i++;
  }
  return [scene];
}
function uniqueSpeakers(sc: Scene) {
  const set = new Set<string>();
  for (const ln of sc.lines) set.add(ln.speaker);
  set.delete("NARRATOR"); set.delete("SYSTEM");
  return Array.from(set);
}
const isBoilerplate = (txt: string) => {
  const s = (txt || "").trim().toLowerCase();
  if (!s) return true;
  if (/^[-–—]+$/.test(s)) return true;
  if (/^\d{1,4}$/.test(s)) return true;
  if (/^page\s*\d+(\s*of\s*\d+)?$/.test(s)) return true;
  if (/^cont'?d\.?$/.test(s) || /^continued$/.test(s)) return true;
  if (s.includes("sides by breakdown services") || s.includes("actors access") || s.includes("do not share") || s.includes("copyright")) return true;
  return false;
};

// ---------- OpenAI TTS ----------
async function openaiTts(text: string, voice = "alloy", model = "tts-1"): Promise<Buffer> {
  const res = await fetchWithTimeout("https://api.openai.com/v1/audio/speech", {
    method: "POST",
    timeoutMs: 30000,
    headers: {
      "Authorization": `Bearer ${OPENAI_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ model, voice, input: text, format: "mp3" }),
  });
  if (!res.ok) {
    const msg = await res.text().catch(() => res.statusText);
    throw new Error(`OpenAI TTS HTTP ${res.status}: ${msg.slice(0, 200)}`);
  }
  const buf = Buffer.from(await res.arrayBuffer());
  return buf;
}

// Tiny health probe
async function openaiTtsProbe(opts?: { text?: string; voice?: string; model?: string }) {
  if (!OPENAI_API_KEY) return { ok: false, error: "OPENAI_API_KEY not set" };
  try {
    await openaiTts(opts?.text ?? "test", opts?.voice ?? "alloy", opts?.model ?? "tts-1");
    return { ok: true, provider: "openai", model: opts?.model ?? "tts-1", voice: opts?.voice ?? "alloy" };
  } catch (e: any) {
    return { ok: false, error: e?.message || String(e) };
  }
}

// Concatenate MP3 buffers (naive but works for same-encoder MP3)
function concatMp3(parts: Buffer[]): Buffer {
  if (parts.length === 1) return parts[0];
  return Buffer.concat(parts);
}

function getUserIdForRequest(req: Request): string | null {
  try {
    const { userId } = getPasskeySession(req as any);
    if (userId && typeof userId === "string" && userId.trim()) {
      return userId.trim();
    }
  } catch (e) {
    console.warn("[auth] getUserIdForRequest: error getting session", (e as any)?.message || e);
  }
  return null;
}

// Helper that ensures anon userId exists for script uploads
function getEffectiveUserId(req: Request): string | null {
  try {
    const { passkeyLoggedIn, userId } = getPasskeySession(req as any);

    // If passkey user, return it
    if (passkeyLoggedIn && userId) {
      return userId;
    }

    // Check if anon is allowed (ENFORCE_AUTH_GATE not set or false)
    const ENFORCE_AUTH_GATE = /^true$/i.test(process.env.ENFORCE_AUTH_GATE || "");
    if (!ENFORCE_AUTH_GATE) {
      // Ensure session.sid exists
      ensureSid(req, null as any);

      // Get session userId (should be anon:<sid> from ensureSessionDefaults)
      const sess = (req as any).session;
      if (sess?.userId) {
        return sess.userId;
      }
    }
  } catch (e) {
    console.warn("[auth] getEffectiveUserId: error getting session", (e as any)?.message || e);
  }
  return null;
}

async function persistScriptToDb(
  id: string,
  userId: string,
  title: string,
  scenes: Scene[]
): Promise<void> {
  try {
    const cleanId = (id || "").trim();
    if (!cleanId) return;

    const cleanTitle = (title || "Sides").trim();
    const safeScenes = Array.isArray(scenes) ? scenes : [];
    const scenesJson = JSON.stringify(safeScenes);
    const sceneCount = safeScenes.length;

    // Check if script exists and verify ownership
    const existing = await dbGet<{ id: string; user_id: string | null }>(
      "SELECT id, user_id FROM scripts WHERE id = ?",
      [cleanId]
    );

    if (existing) {
      // Prevent cross-user ownership stealing
      const existingOwner = existing.user_id;
      if (existingOwner && existingOwner.trim() && existingOwner !== userId) {
        throw new Error("not_owner");
      }

      // Update existing script (only if owner matches OR owner is null/empty)
      await dbRun(
        "UPDATE scripts SET user_id = ?, title = ?, scene_count = ?, scenes_json = ? WHERE id = ?",
        [userId, cleanTitle, sceneCount, scenesJson, cleanId]
      );
    } else {
      // Insert new script
      await dbRun(
        "INSERT INTO scripts (id, user_id, title, scene_count, scenes_json) VALUES (?, ?, ?, ?, ?)",
        [cleanId, userId, cleanTitle, sceneCount, scenesJson]
      );
    }

    console.log("[scripts] persisted script", {
      id: cleanId,
      userId,
      title: cleanTitle,
      sceneCount,
    });
  } catch (e: any) {
    console.error("[scripts] failed to persist script", {
      id,
      title,
      error: e?.message || e,
    });
    // Re-throw ownership errors so callers can handle them
    if (e?.message === "not_owner") {
      throw e;
    }
  }
}

type ScriptRow = {
  id: string;
  user_id: string | null;
  title: string | null;
  scene_count: number | null;
  scenes_json: string | null;
  created_at?: string;
  updated_at?: string;
};

async function loadScriptFromDb(id: string, userId: string): Promise<ScriptRow | null> {
  if (!id || !id.trim() || !userId || !userId.trim()) return null;
  try {
    const row = await dbGet<ScriptRow>(
      "SELECT id, user_id, title, scene_count, scenes_json, created_at, updated_at FROM scripts WHERE id = ? AND user_id = ?",
      [id.trim(), userId.trim()]
    );
    return row ?? null;
  } catch (e) {
    console.error("[scripts] failed to load script from DB", {
      id,
      userId,
      error: (e as any)?.message || e,
    });
    return null;
  }
}

// Script ownership helpers
function scriptCacheKey(userId: string, scriptId: string): string {
  return `${userId}:${scriptId}`;
}

async function getOwnedScriptOrNull(userId: string, scriptId: string): Promise<Script | null> {
  const cacheKey = scriptCacheKey(userId, scriptId);

  // Try cache first
  let script = mem.scripts.get(cacheKey);
  if (script) return script;

  // Load from DB
  const row = await loadScriptFromDb(scriptId, userId);
  if (!row) return null;

  // Parse scenes
  let scenes: Scene[] = [];
  if (row.scenes_json) {
    try {
      scenes = JSON.parse(row.scenes_json) as Scene[];
    } catch (e) {
      console.error("[scripts] failed to parse scenes_json from DB", {
        id: scriptId,
        userId,
        error: (e as any)?.message || e,
      });
    }
  }

  // Build script object
  script = {
    id: row.id,
    title: row.title || "Sides",
    scenes,
    voices: {},
  };

  // Cache and return
  mem.scripts.set(cacheKey, script);
  return script;
}

/* -------------------- ALWAYS-ON ROUTES -------------------- */
// 1) TTS health (safe)
app.get("/debug/tts_check", requireSecret, async (_req: Request, res: Response) => {
  const result = await openaiTtsProbe({ text: "test", voice: "alloy" });
  if (!result.ok) return res.status(500).json(result);
  res.json(result);
});

// 2) Voices probe for UI (curated list; UI will accept any entries)
app.get("/debug/voices_probe", requireSecret, (_req: Request, res: Response) => {
  res.json({
    ok: true,
    voices: ["alloy", "ash", "ballad", "coral", "echo", "fable", "onyx", "nova", "sage", "shimmer", "verse"],
  });
});

// 2.5) Admin scripts diagnostics
app.get("/debug/admin_scripts_diag", requireSecret, requireAdmin(), async (req: Request, res: Response) => {
  try {
    // Get script count by user
    const countsByUserRows = await dbAll<{ user_id: string; n: number }>(
      "SELECT user_id, COUNT(*) AS n FROM scripts GROUP BY user_id ORDER BY n DESC"
    );
    const counts_by_user = countsByUserRows.map((row) => ({
      user_id: row.user_id,
      n: typeof row.n === "number" ? row.n : 0,
    }));

    // Get recent scripts
    const orderClause = USING_POSTGRES
      ? "ORDER BY updated_at DESC"
      : "ORDER BY datetime(updated_at) DESC";

    const recentRows = await dbAll<{ id: string; user_id: string; title: string; updated_at: string }>(
      `SELECT id, user_id, title, updated_at FROM scripts ${orderClause} LIMIT 25`
    );
    const recent = recentRows.map((row) => ({
      id: row.id,
      user_id: row.user_id,
      title: row.title,
      updated_at: row.updated_at,
    }));

    res.json({
      ok: true,
      using_postgres: USING_POSTGRES,
      db_hint: USING_POSTGRES ? "postgres" : "sqlite",
      counts_by_user,
      recent,
    });
  } catch (err) {
    console.error("[debug/admin_scripts_diag] failed", err);
    res.status(500).json({ error: "diagnostics_failed" });
  }
});

// 2.6) Admin merge scripts between users
app.post("/debug/admin_merge_scripts", requireSecret, requireAdmin(), express.json(), async (req: Request, res: Response) => {
  try {
    const from_user_id = String(req.body?.from_user_id || "").trim();
    const to_user_id = String(req.body?.to_user_id || "").trim();
    const dry_run = Boolean(req.body?.dry_run);

    // Validate
    if (!from_user_id || !to_user_id) {
      return res.status(400).json({ error: "from_user_id and to_user_id are required" });
    }
    if (from_user_id === to_user_id) {
      return res.status(400).json({ error: "from_user_id and to_user_id must be different" });
    }

    // Count scripts before
    const countRow = await dbGet<{ n: number }>(
      "SELECT COUNT(*) AS n FROM scripts WHERE user_id = ?",
      [from_user_id]
    );
    const scripts_before = countRow?.n ?? 0;

    let scripts_moved = 0;

    if (!dry_run) {
      // Perform the merge
      const result = await dbRun(
        "UPDATE scripts SET user_id = ? WHERE user_id = ?",
        [to_user_id, from_user_id]
      );
      scripts_moved = result.changes ?? 0;
    } else {
      // Dry run: scripts_moved would be the same as scripts_before
      scripts_moved = scripts_before;
    }

    res.json({
      ok: true,
      using_postgres: USING_POSTGRES,
      from_user_id,
      to_user_id,
      scripts_before,
      scripts_moved,
    });
  } catch (err) {
    console.error("[debug/admin_merge_scripts] failed", err);
    res.status(500).json({ error: "merge_failed" });
  }
});

// 2.7) Admin orphan scripts diagnostics
app.get("/debug/admin_orphan_scripts", requireSecret, requireAdmin(), async (req: Request, res: Response) => {
  try {
    // Count orphan scripts (user_id IS NULL OR user_id = '')
    const countRow = await dbGet<{ n: number }>(
      "SELECT COUNT(*) AS n FROM scripts WHERE user_id IS NULL OR user_id = ''"
    );
    const orphan_count = countRow?.n ?? 0;

    // Get recent orphan scripts
    const orderClause = USING_POSTGRES
      ? "ORDER BY updated_at DESC"
      : "ORDER BY datetime(updated_at) DESC";

    const recentRows = await dbAll<{ id: string; user_id: string | null; title: string; updated_at: string }>(
      `SELECT id, user_id, title, updated_at FROM scripts WHERE user_id IS NULL OR user_id = '' ${orderClause} LIMIT 25`
    );
    const recent = recentRows.map((row) => ({
      id: row.id,
      user_id: row.user_id,
      title: row.title,
      updated_at: row.updated_at,
    }));

    res.json({
      ok: true,
      orphan_count,
      recent,
    });
  } catch (err) {
    console.error("[debug/admin_orphan_scripts] failed", err);
    res.status(500).json({ error: "diagnostics_failed" });
  }
});

// 2.8) Debug whoami - session diagnostics
app.get("/debug/whoami", requireSecret, (req: Request, res: Response) => {
  try {
    const sess = (req as any).session;
    const sid = sess?.sid || null;
    const session_user_id = sess?.userId || null;
    const resolved_user_id = getUserIdForRequest(req);
    const ENFORCE_AUTH_GATE = /^true$/i.test(process.env.ENFORCE_AUTH_GATE || "");

    res.json({
      ok: true,
      has_session: !!sess,
      sid,
      session_user_id,
      resolved_user_id,
      enforce_auth_gate: ENFORCE_AUTH_GATE,
    });
  } catch (err) {
    console.error("[debug/whoami] failed", err);
    res.status(500).json({ error: "diagnostics_failed" });
  }
});

// HTTP routes mount status (for debugging on devices without console access)
app.get("/debug/mount_status", requireSecret, (_req: Request, res: Response) => {
  res.json(ROUTES_MOUNT_STATUS);
});

// 2.9) Debug my_scripts as admin - read-only script query for specific user
app.get("/debug/my_scripts_as_admin", requireSecret, requireAdmin(), async (req: Request, res: Response) => {
  try {
    const user_id = String(req.query.user_id || "").trim();
    if (!user_id) {
      return res.status(400).json({ error: "user_id query param required" });
    }

    const orderClause = USING_POSTGRES
      ? "ORDER BY updated_at DESC"
      : "ORDER BY datetime(updated_at) DESC";

    const query = `SELECT id, user_id, title, scene_count, updated_at FROM scripts WHERE user_id = ? ${orderClause}`;
    const rows = await dbAll<{ id: string; user_id: string; title: string; scene_count: number; updated_at: string }>(
      query,
      [user_id]
    );

    const seen = new Set<string>();
    const scripts = rows
      .filter((row) => {
        if (!row || !row.id) return false;
        if (seen.has(row.id)) return false;
        seen.add(row.id);
        return true;
      })
      .map((row) => ({
        id: row.id,
        title: row.title,
        sceneCount: typeof row.scene_count === "number" ? row.scene_count : 0,
        updatedAt: row.updated_at,
      }));

    res.json({
      ok: true,
      user_id,
      scripts,
    });
  } catch (err) {
    console.error("[debug/my_scripts_as_admin] failed", err);
    res.status(500).json({ error: "query_failed" });
  }
});

// 3) Single-line TTS for Rehearse/Diagnostics
app.post("/debug/tts_line", requireSecret, async (req: Request, res: Response) => {
  try {
    if (!OPENAI_API_KEY) return res.status(500).json({ error: "OPENAI_API_KEY not set" });
    const VOICES = ["alloy", "ash", "ballad", "coral", "echo", "fable", "onyx", "nova", "sage", "shimmer", "verse"];
    const LEGACY_VOICES = new Set(["alloy", "echo", "fable", "onyx", "nova", "shimmer"]);
    const voiceRaw = String((req.body as any)?.voice || "alloy").trim();
    const voice = VOICES.includes(voiceRaw) ? voiceRaw : "alloy";
    const modelRaw = String((req.body as any)?.model || "tts-1");
    const allowedModels = new Set(["tts-1", "tts-1-hd", "gpt-4o-mini-tts"]);
    let model = allowedModels.has(modelRaw) ? modelRaw : "tts-1";
    if (VOICES.includes(voice) && !LEGACY_VOICES.has(voice)) {
      model = "gpt-4o-mini-tts";
    }
    const text = String((req.body as any)?.text || "").trim();
    if (!text) return res.status(400).json({ error: "missing text" });

    const buf = await openaiTts(text, voice, model);
    const id = genId("tts");
    mem.assets.set(id, buf);
    return res.json({ ok: true, url: `/api/assets/${id}` });
  } catch (e: any) {
    const msg = e?.message || String(e);
    return res.status(500).json({ error: msg.slice(0, 200) });
  }
});

// STT stub: accept a small audio chunk and return a dummy transcript.
// This does NOT call OpenAI yet; it's only to prove wiring.
app.post(
  "/debug/stt_transcribe_chunk",
  requireSecret,
  audit("/debug/stt_transcribe_chunk"),
  express.json({ limit: "2mb" }),
  async (req: Request, res: Response) => {
    try {
      const body = (req as any).body || {};
      const rawAudioB64 = typeof body.audio_b64 === "string" ? body.audio_b64.trim() : "";

      if (!rawAudioB64) {
        return res.status(400).json({
          ok: false,
          error: "missing_audio",
        });
      }

      const { base64: cleanBase64, mimeFromHeader } = stripDataUrlPrefix(rawAudioB64);

      const mimeRaw =
        typeof body.mime === "string" && body.mime.trim() ? (body.mime as string) : mimeFromHeader;

      const mime = mimeRaw && mimeRaw.trim().length > 0 ? mimeRaw.trim() : "audio/webm";

      const audioBuffer = Buffer.from(cleanBase64, "base64");
      if (!audioBuffer || audioBuffer.length === 0) {
        return res.status(400).json({
          ok: false,
          error: "invalid_audio",
        });
      }

      console.log("[stt] /stt_transcribe_chunk request:", {
        rawMime: body.mime || null,
        headerMime: mimeFromHeader || null,
        effectiveMime: mime,
        hasDataUrlPrefix: rawAudioB64.startsWith("data:"),
        base64Length: cleanBase64.length,
        bytes: audioBuffer.length,
      });

      if (!isSttEnabled()) {
        return res.status(200).json({
          ok: false,
          error: "stt_disabled",
        });
      }

      const script_id =
        typeof body.script_id === "string" ? body.script_id.trim() : "";
      const scene_id =
        typeof body.scene_id === "string" ? body.scene_id.trim() : "";
      const line_id =
        typeof body.line_id === "string" ? body.line_id.trim() : "";
      void script_id;
      void scene_id;
      void line_id;

      try {
        const result = await transcribeChunk({
          audio: audioBuffer,
          mime,
        });

        return res.status(200).json({
          ok: true,
          text: result.text,
          partial: false,
        });
      } catch (err: any) {
        let code = "stt_failed";
        let message: string | undefined;

        const anyErr: any = err || {};
        const oaiErr = anyErr.error || anyErr.response?.data?.error;

        if (typeof oaiErr?.code === "string") {
          code = oaiErr.code;
        } else if (typeof anyErr.code === "string") {
          code = anyErr.code;
        } else if (typeof anyErr.message === "string") {
          code = anyErr.message;
        }

        if (typeof oaiErr?.message === "string") {
          message = oaiErr.message;
        } else if (typeof anyErr.message === "string") {
          message = anyErr.message;
        }

        console.error("[stt] transcribe_chunk error:", {
          code,
          message,
          mime,
          bytes: audioBuffer.length,
          raw: anyErr,
        });

        return res.status(500).json({
          ok: false,
          error: code,
          message,
          meta: {
            mime,
            bytes: audioBuffer.length,
          },
        });
      }
    } catch (err: any) {
      console.error("[stt] transcribe_chunk error:", err);
      const code =
        err?.code ||
        err?.error?.code ||
        err?.status ||
        "stt_failed";
      const message =
        err?.error?.message || err?.message || "Audio file might be corrupted or unsupported";

      res.json({
        ok: false,
        error: code,
        message,
      });
    }
  }
);
/* ---------------------------------------------------------- */

app.get("/api/my_scripts", async (req: Request, res: Response) => {
  try {
    const userId = getUserIdForRequest(req);

    // Diagnostic logging
    console.log("[my_scripts] resolved_user_id=", userId, "sid=", (req as any).session?.sid, "session_user_id=", (req as any).session?.userId);

    if (!userId) {
      return res.status(401).json({ error: "unauthorized" });
    }

    const orderClause = USING_POSTGRES
      ? "ORDER BY updated_at DESC"
      : "ORDER BY datetime(updated_at) DESC";

    const query = `SELECT id, user_id, title, scene_count, updated_at FROM scripts WHERE user_id = ? ${orderClause}`;

    const rows = await dbAll<{ id: string; user_id: string; title: string; scene_count: number; updated_at: string }>(
      query,
      [userId]
    );

    const seen = new Set<string>();
    const scripts = rows
      .filter((row) => {
        if (!row || !row.id) return false;
        if (seen.has(row.id)) return false;
        seen.add(row.id);
        return true;
      })
      .map((row) => ({
        id: row.id,
        title: row.title,
        sceneCount:
          typeof row.scene_count === "number" ? row.scene_count : 0,
        updatedAt: row.updated_at,
      }));

    console.log("[scripts] /api/my_scripts", {
      userId,
      count: scripts.length,
    });

    res.json({ scripts });
  } catch (e: any) {
    console.error("[scripts] /api/my_scripts failed:", e?.message || e);
    res.status(500).json({ error: "failed_to_list_scripts" });
  }
});

app.get("/api/scripts/:id", async (req: Request, res: Response) => {
  const id = (req.params.id || "").trim();
  if (!id) {
    return res.status(400).json({ error: "missing_id" });
  }

  const userId = getUserIdForRequest(req);
  if (!userId) {
    return res.status(401).json({ error: "unauthorized" });
  }

  const script = await getOwnedScriptOrNull(userId, id);
  if (!script) {
    return res.status(404).json({ error: "not_found" });
  }

  return res.json({
    id: script.id,
    title: script.title,
    scenes: script.scenes,
    voices: script.voices || {},
  });
});

app.post("/api/scripts/:id/save", async (req: Request, res: Response) => {
  try {
    const userId = getUserIdForRequest(req);
    if (!userId) {
      return res.status(401).json({ error: "unauthorized" });
    }

    const id = (req.params.id || "").trim();
    if (!id) {
      return res.status(400).json({ error: "missing_script_id" });
    }

    const body = req.body || {};
    const rawTitle =
      typeof body.title === "string" ? (body.title as string).trim() : "";
    const scenesRaw = body.scenes;
    const scenes = Array.isArray(scenesRaw) ? (scenesRaw as Scene[]) : [];

    // Check ownership BEFORE saving
    const existingRow = await dbGet<{ user_id: string | null; title: string }>(
      "SELECT user_id, title FROM scripts WHERE id = ?",
      [id]
    );

    if (existingRow) {
      const existingOwner = existingRow.user_id;
      if (existingOwner && existingOwner.trim() && existingOwner !== userId) {
        // Return 404 to avoid ID enumeration
        return res.status(404).json({ error: "not_found" });
      }
    }

    const existingTitle = existingRow?.title || "";
    const finalTitle = rawTitle || existingTitle || "Sides";

    // Persist new title + scenes to DB
    await persistScriptToDb(id, userId, finalTitle, scenes);

    return res.json({ ok: true });
  } catch (e: any) {
    console.error("[scripts] POST /api/scripts/:id/save failed:", e?.message || e);
    return res.status(500).json({ error: "failed_to_save_script" });
  }
});

app.delete("/api/scripts/:id", async (req: Request, res: Response) => {
  try {
    const userId = getUserIdForRequest(req);
    if (!userId) {
      return res.status(401).json({ error: "unauthorized" });
    }

    const id = (req.params.id || "").trim();
    if (!id) {
      return res.status(400).json({ error: "missing_script_id" });
    }

    const result = await dbRun("DELETE FROM scripts WHERE id = ? AND user_id = ?", [id, userId]);

    if ((result.changes || 0) === 0) {
      // Nothing deleted: either it never existed or was already removed.
      return res.status(404).json({ ok: false, error: "script_not_found" });
    }

    return res.json({ ok: true });
  } catch (e: any) {
    console.error("[scripts] DELETE /api/scripts/:id failed:", e?.message || e);
    return res.status(500).json({ error: "failed_to_delete_script" });
  }
});

// ---------- Routes ----------
function mountFallbackDebugRoutes() {
  app.get("/debug/ping", requireSecret, (_req, res) => res.json({ ok: true }));
  app.get("/debug/whoami", requireSecret, (req: Request, res: Response) => {
    res.json({ ok: true, marker: "fallback/server.ts" });
  });

  app.post(
    "/debug/upload_script_text",
    requireSecret,
    audit("/debug/upload_script_text"),
    async (req: Request, res: Response) => {
      const userId = getEffectiveUserId(req);
      if (!userId) {
        return res.status(401).json({ error: "unauthorized" });
      }

      const title = String(req.body?.title || "Script");
      const text = String(req.body?.text || "");
      const id = genId("scr");
      const scenes = parseTextToScenes(title, text);
      const speakers = uniqueSpeakers(scenes[0]);

      const cacheKey = scriptCacheKey(userId, id);
      mem.scripts.set(cacheKey, { id, title, scenes, voices: {} });
      await persistScriptToDb(id, userId, title, scenes);

      res.json({ script_id: id, scene_count: scenes.length, speakers });
    }
  );

  // Robust PDF (text) import
  app.post(
    "/debug/upload_script_upload",
    requireSecret,
    audit("/debug/upload_script_upload"),
    upload.single("pdf"),
    async (req: Request, res: Response) => {
      const userId = getEffectiveUserId(req);
      if (!userId) {
        return res.status(401).json({ error: "unauthorized" });
      }

      const title = String((req.body as any)?.title || "PDF");
      const pdfBuf = (req as any).file?.buffer as Buffer | undefined;
      if (!pdfBuf) return res.status(400).json({ error: "missing pdf file" });

      try {
        let pdfParseFn: any = null;
        try {
          const modA: any = await import("pdf-parse");
          pdfParseFn = modA?.default || modA;
        } catch {}
        if (!pdfParseFn) {
          const reqr = createRequire(import.meta.url);
          const modB: any = reqr("pdf-parse");
          pdfParseFn = modB?.default || modB;
        }
        if (typeof pdfParseFn !== "function") {
          throw new Error("pdf-parse load failed (no function export)");
        }

        const data = await pdfParseFn(pdfBuf);
        let text = String(data?.text || "");
        const textLenRaw = text.length;

        if (textLenRaw < 20) {
          const id = genId("scr");
          const scenes: Scene[] = [
            {
              id: genId("scn"),
              title,
              lines: [
                {
                  speaker: "SYSTEM",
                  text: "PDF appears to be image-only. Paste script text for best parsing (OCR later).",
                },
              ],
            },
          ];
          const cacheKey = scriptCacheKey(userId, id);
          mem.scripts.set(cacheKey, { id, title, scenes, voices: {} });
          await persistScriptToDb(id, userId, title, scenes);
          return res.json({
            script_id: id,
            scene_count: scenes.length,
            note: "image-only",
            textLen: textLenRaw,
          });
        }

        text = normalizePdfText(text);
        const scenes = parseTextToScenes(title, text);
        const speakers = uniqueSpeakers(scenes[0]);

        const id = genId("scr");
        const cacheKey = scriptCacheKey(userId, id);
        mem.scripts.set(cacheKey, { id, title, scenes, voices: {} });
        await persistScriptToDb(id, userId, title, scenes);
        return res.json({
          script_id: id,
          scene_count: scenes.length,
          speakers,
          textLen: text.length,
        });
      } catch (e: any) {
        const msg = (e?.message || String(e)).slice(0, 200);
        console.error("[pdf] extract failed:", msg);
        const id = genId("scr");
        const scenes: Scene[] = [
          {
            id: genId("scn"),
            title,
            lines: [
              {
                speaker: "SYSTEM",
                text: "Could not parse PDF text. Please paste script text. (Error logged on server.)",
              },
            ],
          },
        ];
        const cacheKey = scriptCacheKey(userId, id);
        mem.scripts.set(cacheKey, { id, title, scenes, voices: {} });
        await persistScriptToDb(id, userId, title, scenes);
        return res.json({
          script_id: id,
          scene_count: scenes.length,
          note: "parse-error",
          error: msg,
        });
      }
    }
  );

  app.get(
    "/debug/scenes",
    requireSecret,
    audit("/debug/scenes"),
    async (req: Request, res: Response) => {
      const userId = getUserIdForRequest(req);
      if (!userId) {
        return res.status(401).json({ error: "unauthorized" });
      }

      const script_id = String(req.query.script_id || "").trim();
      if (!script_id) {
        return res.status(400).json({ error: "missing_script_id" });
      }

      const script = await getOwnedScriptOrNull(userId, script_id);
      if (!script) {
        return res.status(404).json({ error: "not_found" });
      }

      return res.json({ script_id, scenes: script.scenes });
    }
  );

  app.post(
    "/debug/stt",
    requireSecret,
    audit("/debug/stt"),
    (req: Request, res: Response) => {
      try {
        const body = (req.body || {}) as any;
        const script_id =
          typeof body.script_id === "string" ? body.script_id.trim() : "";
        const scene_id =
          typeof body.scene_id === "string" ? body.scene_id.trim() : "";
        const line_id =
          typeof body.line_id === "string" ? body.line_id.trim() : "";
        const text = typeof body.text === "string" ? body.text : "";
        const audio_ms =
          typeof body.audio_ms === "number" && Number.isFinite(body.audio_ms)
            ? body.audio_ms
            : null;

        // For now, pretend STT heard exactly the provided text, or a stub.
        const transcript = text.trim() || "stub transcript";

        return res.json({
          ok: true,
          script_id,
          scene_id,
          line_id,
          transcript,
          confidence: 0.9,
          received_ms: audio_ms,
          decided_at: Date.now(),
        });
      } catch (err) {
        console.error("[debug/stt] error:", err);
        return res.status(500).json({ ok: false, error: "stt_stub_failed" });
      }
    }
  );

  app.post("/debug/set_voice", requireSecret, audit("/debug/set_voice"), async (req: Request, res: Response) => {
    const userId = getUserIdForRequest(req);
    if (!userId) {
      return res.status(401).json({ error: "unauthorized" });
    }

    const script_id = String((req.body as any)?.script_id || "");
    const voice_map = (req.body as any)?.voice_map || {};

    const script = await getOwnedScriptOrNull(userId, script_id);
    if (!script) {
      return res.status(404).json({ error: "not_found" });
    }

    Object.assign(script.voices, voice_map);
    res.json({ ok: true });
  });

  // REAL: Render partner-only reader MP3 with OpenAI
  app.post("/debug/render", requireSecret, renderLimiter, audit("/debug/render"), async (req: Request, res: Response) => {
    const userId = getUserIdForRequest(req);
    if (!userId) {
      return res.status(401).json({ error: "unauthorized" });
    }

    const script_id = String((req.body as any)?.script_id || "");
    const myRole = String((req.body as any)?.my_role || "").toUpperCase();
    const paceMs = Number((req.body as any)?.pace_ms || 0);

    const s = await getOwnedScriptOrNull(userId, script_id);
    if (!s) return res.status(404).json({ error: "script not found" });
    if (!OPENAI_API_KEY) return res.status(500).json({ error: "OPENAI_API_KEY not set" });

    const rid = genId("rnd");
    const job: RenderJob = { status: "queued", accounted: false };
    mem.renders.set(rid, job);

    (async () => {
      try {
        const scene = s.scenes[0];

        // Normalize role for case-insensitive comparison
        const roleNorm = myRole.trim().toUpperCase();

        // Build case-insensitive voice map
        const voiceMapNorm: Record<string, string> = {};
        for (const [k, v] of Object.entries(s.voices)) {
          voiceMapNorm[k.trim().toUpperCase()] = v;
        }

        // Build partner lines with original indices
        const partnerLinesWithIndices: Array<{ line: Line; originalIndex: number }> = [];
        for (let i = 0; i < scene.lines.length; i++) {
          const ln = scene.lines[i];
          if (!ln || !ln.speaker || ln.speaker === "NARRATOR" || ln.speaker === "SYSTEM") continue;
          const speakerNorm = (ln.speaker ?? "").trim().toUpperCase();
          if (speakerNorm === roleNorm) continue;
          if (isBoilerplate(ln.text)) continue;
          partnerLinesWithIndices.push({ line: ln, originalIndex: i });
        }

        const voiceFor = (name: string) => {
          const nameNorm = name.trim().toUpperCase();
          return voiceMapNorm[nameNorm] || "alloy";
        };

        // Validate partner lines exist
        if (partnerLinesWithIndices.length === 0) {
          job.status = "error";
          job.err = "no_partner_lines";
          return;
        }

        // Log first few partner lines for debugging
        const firstPartners = partnerLinesWithIndices.slice(0, 3).map(({ line }) => ({
          speaker: line.speaker,
          speakerNorm: (line.speaker ?? "").trim().toUpperCase(),
          voice: voiceFor(line.speaker),
        }));
        console.log(`[render] partnerLines=${partnerLinesWithIndices.length} role=${myRole} firstPartners=${JSON.stringify(firstPartners)}`);

        // Create render directory for segments
        const renderDir = path.join(process.cwd(), "assets", "renders", rid);
        fs.mkdirSync(renderDir, { recursive: true });

        const chunks: Buffer[] = [];
        const manifestSegments: RenderManifest["segments"] = [];

        for (let segIdx = 0; segIdx < partnerLinesWithIndices.length; segIdx++) {
          const { line: ln, originalIndex } = partnerLinesWithIndices[segIdx];
          const voice = voiceFor(ln.speaker);
          const b = await openaiTts(ln.text, voice, "tts-1");
          chunks.push(b);

          // Save individual segment
          const segPath = path.join(renderDir, `seg_${String(segIdx).padStart(3, "0")}.mp3`);
          fs.writeFileSync(segPath, b);
          if (r2Enabled()) {
            const r2Key = `renders/${rid}/seg_${String(segIdx).padStart(3, "0")}.mp3`;
            await r2PutFile(r2Key, segPath, "audio/mpeg");
          }

          // Add to manifest
          manifestSegments.push({
            segment_index: segIdx,
            script_line_index: originalIndex,
            speaker: ln.speaker,
            text: ln.text,
            url: `/api/assets/${rid}/segment/${segIdx}`,
          });

          if (paceMs > 0) {
            // optional silence could be inserted later
          }
        }

        // Save manifest
        const manifest: RenderManifest = {
          render_id: rid,
          script_id: script_id,
          scene_id: scene.id,
          role: myRole,
          created_at: new Date().toISOString(),
          segments: manifestSegments,
        };
        const manifestPath = path.join(renderDir, "manifest.json");
        fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
        if (r2Enabled()) {
          const r2Key = `renders/${rid}/manifest.json`;
          await r2PutFile(r2Key, manifestPath, "application/json");
        }

        // Create combined MP3 (existing behavior)
        const mp3 = concatMp3(chunks.length ? chunks : [await openaiTts(" ", "alloy", "tts-1")]);

        // Save combined MP3 to file (moved from mem.assets)
        const mp3Path = path.join(process.cwd(), "assets", "renders", `${rid}.mp3`);
        fs.writeFileSync(mp3Path, mp3);

        job.status = "complete";
        job.url = `/api/assets/${rid}`;
        job.manifest_url = `/api/assets/${rid}/manifest`;
      } catch (e: any) {
        const msg = e?.message || String(e);
        job.status = "error";
        job.err = msg;
      }
    })();

    res.json({ render_id: rid, status: "queued" });
  });

  // NEW: Render individual MP3 segments for each partner line
  app.post("/debug/render_segments", requireSecret, renderLimiter, audit("/debug/render_segments"), async (req: Request, res: Response) => {
    try {
      const userId = getUserIdForRequest(req);
      if (!userId) {
        return res.status(401).json({ error: "unauthorized" });
      }

      const script_id = String((req.body as any)?.script_id || "");
      const scene_id = String((req.body as any)?.scene_id || "");
      const role = String((req.body as any)?.role || "").toUpperCase();
      const pace = String((req.body as any)?.pace || "normal");

      if (!script_id || !scene_id || !role) {
        return res.status(400).json({ error: "script_id, scene_id, and role are required" });
      }

      const s = await getOwnedScriptOrNull(userId, script_id);
      if (!s) return res.status(404).json({ error: "script not found" });
      if (!OPENAI_API_KEY) return res.status(500).json({ error: "OPENAI_API_KEY not set" });

      // Find the scene
      const scene = s.scenes.find(sc => sc.id === scene_id) || s.scenes[0];
      if (!scene) {
        return res.status(404).json({ error: "scene not found" });
      }

      // Normalize role for case-insensitive comparison
      const roleNorm = role.trim().toUpperCase();

      // Build case-insensitive voice map
      const voiceMapNorm: Record<string, string> = {};
      for (const [k, v] of Object.entries(s.voices)) {
        voiceMapNorm[k.trim().toUpperCase()] = v;
      }

      // Build partner lines (lines where speaker !== role)
      const partnerLines = scene.lines
        .filter(ln => ln && ln.speaker && ln.speaker !== "NARRATOR" && ln.speaker !== "SYSTEM")
        .filter(ln => {
          const speakerNorm = (ln.speaker ?? "").trim().toUpperCase();
          return speakerNorm !== roleNorm;
        })
        .filter(ln => !isBoilerplate(ln.text));

      // Validate partner lines exist
      if (partnerLines.length === 0) {
        return res.status(422).json({ error: "no_partner_lines" });
      }

      // Hard cap: max 30 segments
      if (partnerLines.length > 30) {
        return res.status(400).json({
          error: `Too many partner lines (${partnerLines.length}). Maximum 30 segments allowed.`
        });
      }

      const voiceFor = (name: string) => {
        const nameNorm = name.trim().toUpperCase();
        return voiceMapNorm[nameNorm] || "alloy";
      };

      // Log first few partner lines for debugging
      const firstPartners = partnerLines.slice(0, 3).map(ln => ({
        speaker: ln.speaker,
        speakerNorm: (ln.speaker ?? "").trim().toUpperCase(),
        voice: voiceFor(ln.speaker),
      }));
      console.log(`[render] partnerLines=${partnerLines.length} role=${role} firstPartners=${JSON.stringify(firstPartners)}`);
      const segments: Array<{
        index: number;
        speaker: string;
        text: string;
        render_id: string;
        url: string;
      }> = [];

      // Generate each segment
      for (let i = 0; i < partnerLines.length; i++) {
        const ln = partnerLines[i];
        const segmentRenderId = genId("seg");
        const voice = voiceFor(ln.speaker);

        console.log(`[render_segments] Generating segment ${i + 1}/${partnerLines.length}: speaker=${ln.speaker}, render_id=${segmentRenderId}`);

        // Generate TTS for this line
        const audioBuffer = await openaiTts(ln.text, voice, "tts-1");

        // Store segment (R2 or local disk)
        if (r2Enabled()) {
          // Write to temp file first
          const tmpDir = path.join(process.cwd(), "tmp");
          if (!fs.existsSync(tmpDir)) {
            fs.mkdirSync(tmpDir, { recursive: true });
          }
          const tmpPath = path.join(tmpDir, `${segmentRenderId}.mp3`);
          fs.writeFileSync(tmpPath, audioBuffer);

          try {
            const r2Key = `renders/${segmentRenderId}.mp3`;
            await r2PutFile(r2Key, tmpPath, "audio/mpeg");
            console.log(`[render_segments] Uploaded to R2: ${r2Key}`);

            // Clean up temp file
            fs.unlinkSync(tmpPath);
          } catch (r2Err: any) {
            console.error(`[render_segments] R2 upload failed: ${r2Err.message || r2Err}`);
            // Clean up temp file even on error
            if (fs.existsSync(tmpPath)) {
              fs.unlinkSync(tmpPath);
            }
            return res.status(500).json({ error: "r2_upload_failed" });
          }
        } else {
          // Local storage mode - write to data/renders/
          const rendersDir = path.join(process.cwd(), "data", "renders");
          if (!fs.existsSync(rendersDir)) {
            fs.mkdirSync(rendersDir, { recursive: true });
          }
          const localPath = path.join(rendersDir, `${segmentRenderId}.mp3`);
          fs.writeFileSync(localPath, audioBuffer);
          console.log(`[render_segments] Saved to local disk: ${localPath}`);
        }

        segments.push({
          index: i,
          speaker: ln.speaker,
          text: ln.text,
          render_id: segmentRenderId,
          url: `/api/assets/${segmentRenderId}`
        });
      }

      res.json({ ok: true, segments });
    } catch (err: any) {
      console.error("[render_segments] Error:", err);
      return res.status(500).json({ error: err?.message || "internal_error" });
    }
  });
  app.get("/debug/render_status", requireSecret, audit("/debug/render_status"), async (req: Request, res: Response) => {
    const render_id = String(req.query.render_id || "");

    // DEBUG: see if this route is being hit and what cookies we have
    console.log("[debug] /debug/render_status request:", {
      render_id,
      cookies: (req as any).cookies || null,
      hasSidCookie: Boolean((req as any).cookies?.ob_sid),
    });

    const job = mem.renders.get(render_id);
    if (!job) {
      return res.status(404).json({ error: "not found" });
    }

    console.log(
      "[debug] fallback render_status hit: rid=%s status=%s accounted=%s",
      render_id,
      job.status,
      (job as any).accounted
    );

    // When a render first reaches "complete", account for it exactly once.
    if (job.status === "complete" && !job.accounted) {
      try {
        console.log("[credits] render complete: accounting usage; rid=%s", render_id);
        await noteRenderComplete(req);
        job.accounted = true;
      } catch (err) {
        console.error("[credits] noteRenderComplete failed:", err);
      }
    }

    // Return a minimal, stable shape (with optional manifest_url)
    const response: any = {
      status: job.status,
      url: job.url,
      err: job.err,
    };
    if (job.status === "complete" && job.manifest_url) {
      response.manifest_url = job.manifest_url;
    }
    res.json(response);
  });

  console.log("[fallback] /debug/* routes active (in-memory, robust PDF import + strict speaker guard)");
}

// Prefer real project routes if present
async function tryMountProjectHttpRoutes() {
  try {
    const mod =
      (await import("./http-routes.js").catch(() => null)) ||
      (await import("./http-routes").catch(() => null));
    if (mod && (typeof (mod as any).registerHttpRoutes === "function" || typeof (mod as any).default === "function")) {
      const fn = ((mod as any).registerHttpRoutes || (mod as any).default) as (app: express.Express) => void;
      fn(app);
      console.log("[http-routes] mounted real handlers");
      ROUTES_MOUNT_STATUS = { mounted: true, error: null };
      return true;
    }
    if (mod) {
      const msg = "http-routes present but no handler export detected";
      console.warn("[http-routes]", msg);
      ROUTES_MOUNT_STATUS = { mounted: false, error: msg };
    } else {
      const msg = "http-routes module not found";
      ROUTES_MOUNT_STATUS = { mounted: false, error: msg };
    }
  } catch (e) {
    const errorMsg = String(e);
    console.warn("[http-routes] failed to import, using fallback:", e);
    ROUTES_MOUNT_STATUS = { mounted: false, error: errorMsg };
  }
  return false;
}

// Always-on assets route (in-memory first, then disk)
app.get("/api/assets/:render_id", async (req: Request, res: Response) => {
  try {
    const rid = String(req.params.render_id || "");
    const range = req.headers.range;

    const sendBuffer = (buf: Buffer) => {
      const total = buf.length;
      if (range && range.startsWith("bytes=")) {
        const parts = range.replace(/bytes=/, "").split("-");
        const start = Number(parts[0]) || 0;
        const end = parts[1] ? Number(parts[1]) : total - 1;
        if (start >= total || start < 0 || start > end) {
          res.status(416).set("Content-Range", `bytes */${total}`).end();
          return;
        }
        const clampedEnd = Math.min(end, total - 1);
        const chunk = buf.subarray(start, clampedEnd + 1);
        res.status(206);
        res.setHeader("Content-Range", `bytes ${start}-${clampedEnd}/${total}`);
        res.setHeader("Accept-Ranges", "bytes");
        res.setHeader("Content-Length", chunk.length);
        res.setHeader("Content-Type", "audio/mpeg");
        res.setHeader("Cache-Control", "no-store");
        return res.end(chunk);
      }
      res.setHeader("Content-Type", "audio/mpeg");
      res.setHeader("Cache-Control", "no-store");
      res.setHeader("Content-Length", total);
      return res.end(buf);
    };

    const inMem = mem.assets.get(rid);
    if (inMem) return sendBuffer(inMem);

    const filePath = path.join(ASSETS_DIR, `${rid}.mp3`);
    if (fs.existsSync(filePath)) {
      const stat = fs.statSync(filePath);
      const total = stat.size;
      res.setHeader("Content-Type", "audio/mpeg");
      res.setHeader("Cache-Control", "no-store");
      if (range && range.startsWith("bytes=")) {
        const parts = range.replace(/bytes=/, "").split("-");
        const start = Number(parts[0]) || 0;
        const end = parts[1] ? Number(parts[1]) : total - 1;
        if (start >= total || start < 0 || start > end) {
          res.status(416).set("Content-Range", `bytes */${total}`).end();
          return;
        }
        const clampedEnd = Math.min(end, total - 1);
        res.status(206);
        res.setHeader("Content-Range", `bytes ${start}-${clampedEnd}/${total}`);
        res.setHeader("Accept-Ranges", "bytes");
        res.setHeader("Content-Length", clampedEnd - start + 1);
        return fs.createReadStream(filePath, { start, end: clampedEnd }).pipe(res);
      }
      res.setHeader("Content-Length", total);
      return fs.createReadStream(filePath).pipe(res);
    }

    // Try R2 if enabled
    if (r2Enabled()) {
      const r2Key = `renders/${rid}.mp3`;
      const rangeHeader = req.headers.range;

      try {
        const { stream, contentType, contentLength, contentRange, statusCode } =
          await r2GetObjectStream(r2Key, rangeHeader);

        res.setHeader("Accept-Ranges", "bytes");
        res.setHeader("Content-Type", contentType || "audio/mpeg");
        res.setHeader("Cache-Control", "no-store");

        if (contentLength !== undefined) {
          res.setHeader("Content-Length", contentLength);
        }

        if (contentRange) {
          res.setHeader("Content-Range", contentRange);
        }

        res.status(statusCode);
        return stream.pipe(res);
      } catch (r2Err: any) {
        // R2 object not found - fall through to 404
        console.error(`[assets/server] R2 fetch failed for ${r2Key}: ${r2Err.message || r2Err}`);
      }
    }

    return res.status(404).json({ error: "asset not found" });
  } catch (err) {
    console.error("[assets/server] Error in GET /api/assets/:render_id", err);
    return res.status(500).json({ error: "internal_error" });
  }
});

// Manifest endpoint
app.get("/api/assets/:render_id/manifest", async (req: Request, res: Response) => {
  try {
    const renderId = String(req.params.render_id || "");
    const manifestPath = path.join(ASSETS_DIR, "renders", renderId, "manifest.json");

    console.log("[api/assets/manifest]", { renderId, manifestPath });

    if (!fs.existsSync(manifestPath)) {
      if (r2Enabled()) {
        const r2Key = `renders/${renderId}/manifest.json`;
        try {
          const { stream, contentType, contentLength, statusCode } = await r2GetObjectStream(r2Key);
          res.status(statusCode);
          res.setHeader("Content-Type", contentType || "application/json");
          res.setHeader("Cache-Control", "no-store");
          if (contentLength !== undefined) {
            res.setHeader("Content-Length", contentLength);
          }
          return stream.pipe(res);
        } catch (r2Err: any) {
          console.error(`[api/assets/manifest] R2 fetch failed for ${r2Key}: ${r2Err.message || r2Err}`);
        }
      }
      return res.status(404).json({ error: "manifest_not_found" });
    }

    const manifestData = fs.readFileSync(manifestPath, "utf-8");
    const manifest = JSON.parse(manifestData);

    res.setHeader("Content-Type", "application/json");
    res.setHeader("Cache-Control", "no-store");
    return res.json(manifest);
  } catch (err) {
    console.error("[api/assets/manifest] error", err);
    return res.status(500).json({ error: "internal_error" });
  }
});

// Segment endpoint
app.get("/api/assets/:render_id/segment/:segment_index", async (req: Request, res: Response) => {
  try {
    const renderId = String(req.params.render_id || "");
    const segmentIndex = String(req.params.segment_index || "");
    const range = req.headers.range;
    const segmentPath = path.join(
      ASSETS_DIR,
      "renders",
      renderId,
      `seg_${segmentIndex.padStart(3, "0")}.mp3`
    );

    console.log("[api/assets/segment]", { renderId, segmentIndex, segmentPath, hasRange: !!range });

    if (!fs.existsSync(segmentPath)) {
      if (r2Enabled()) {
        const r2Key = `renders/${renderId}/seg_${segmentIndex.padStart(3, "0")}.mp3`;
        try {
          const { stream, contentType, contentLength, contentRange, statusCode } =
            await r2GetObjectStream(r2Key, range);

          res.setHeader("Accept-Ranges", "bytes");
          res.setHeader("Content-Type", contentType || "audio/mpeg");
          res.setHeader("Cache-Control", "no-store");

          if (contentLength !== undefined) {
            res.setHeader("Content-Length", contentLength);
          }

          if (contentRange) {
            res.setHeader("Content-Range", contentRange);
          }

          res.status(statusCode);
          return stream.pipe(res);
        } catch (r2Err: any) {
          console.error(`[api/assets/segment] R2 fetch failed for ${r2Key}: ${r2Err.message || r2Err}`);
        }
      }
      return res.status(404).json({ error: "segment_not_found" });
    }

    const stat = fs.statSync(segmentPath);
    const total = stat.size;

    res.setHeader("Content-Type", "audio/mpeg");
    res.setHeader("Accept-Ranges", "bytes");
    res.setHeader("Cache-Control", "no-store");

    // Handle Range requests
    if (range && range.startsWith("bytes=")) {
      const parts = range.replace(/bytes=/, "").split("-");
      const start = Number(parts[0]) || 0;
      const end = parts[1] ? Number(parts[1]) : total - 1;

      // Invalid range
      if (start >= total || start < 0 || start > end) {
        res.status(416).set("Content-Range", `bytes */${total}`).end();
        return;
      }

      const clampedEnd = Math.min(end, total - 1);
      res.status(206);
      res.setHeader("Content-Range", `bytes ${start}-${clampedEnd}/${total}`);
      res.setHeader("Content-Length", clampedEnd - start + 1);
      return fs.createReadStream(segmentPath, { start, end: clampedEnd }).pipe(res);
    }

    // No range - send full file
    res.status(200);
    res.setHeader("Content-Length", total);
    return fs.createReadStream(segmentPath).pipe(res);
  } catch (err) {
    console.error("[api/assets/segment] error", err);
    return res.status(500).json({ error: "internal_error" });
  }
});

// Ensure database schema before starting server
await ensureSchema();

await tryMountProjectHttpRoutes().then((mounted) => { if (!mounted) mountFallbackDebugRoutes(); });

// Start
app.listen(PORT, () => {
  console.log(`OffBook MVP listening on http://localhost:${PORT}`);
  const shared = getSharedSecret();
  if (shared) console.log(`Debug routes require header X-Shared-Secret: ${shared}`);
  console.log("UI tip: open /app-tabs.html?secret=" + (shared || "(none)"));
});
