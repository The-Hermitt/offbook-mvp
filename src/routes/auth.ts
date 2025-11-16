import express from "express";
import crypto from "node:crypto";

const INCLUDED_RENDERS_PER_MONTH = Number(process.env.INCLUDED_RENDERS_PER_MONTH || 0);
const DEV_STARTING_CREDITS = Number(process.env.DEV_STARTING_CREDITS || 0);

// In-memory session store for single-tester dev
type Sess = {
  regChallenge?: string;
  authChallenge?: string;
  userId?: string;
  credentialId?: string;
  loggedIn?: boolean;

  // — Entitlements (dev placeholders) —
  plan?: "none" | "dev";
  rendersUsed?: number;
  creditsAvailable?: number;
  periodStart?: string;
  periodEnd?: string;
};
const sessions = new Map<string, Sess>();

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

function setCookie(res: express.Response, name: string, value: string, req: express.Request) {
  const isHttps = (req.headers["x-forwarded-proto"] === "https") || (req.protocol === "https");
  res.cookie(name, value, {
    httpOnly: true,
    sameSite: "lax",
    secure: !!isHttps,
  });
}

function getOrCreateSid(req: express.Request, res: express.Response) {
  const cookies = parseCookies(req);
  let sid = cookies["ob_sid"];
  if (!sid) {
    sid = crypto.randomUUID();
    setCookie(res, "ob_sid", sid, req);
  }
  if (!sessions.has(sid)) {
    const now = new Date();
    const start = new Date(now.getFullYear(), now.getMonth(), 1);
    const end = new Date(now.getFullYear(), now.getMonth() + 1, 1);
    sessions.set(sid, {
      plan: "none",
      rendersUsed: 0,
      creditsAvailable: DEV_STARTING_CREDITS,
      periodStart: start.toISOString(),
      periodEnd: end.toISOString(),
    });
  }
  return sid;
}

export function noteRenderComplete(req: express.Request) {
  const cookies = parseCookies(req);
  const sid = cookies["ob_sid"];
  if (!sid) {
    console.log("[credits] noteRenderComplete: missing ob_sid cookie");
    return;
  }

  const sess = sessions.get(sid);
  if (!sess) {
    console.log("[credits] noteRenderComplete: no session for sid", sid);
    return;
  }

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

// --- GET /auth/session -------------------------------------------------------
router.get("/session", (req, res) => {
  const cookies = parseCookies(req);
  const invited = (process.env.INVITE_CODE || "").trim()
    ? cookies["ob_invite"] === "ok"
    : true;

  const sid = cookies["ob_sid"];
  const sess = sid ? sessions.get(sid) : undefined;

  res.json({
    invited,
    hasInviteCode: Boolean((process.env.INVITE_CODE || "").trim()),
    enforceAuthGate: /^true$/i.test(process.env.ENFORCE_AUTH_GATE || ""),
    userId: sess?.userId || null,
    passkey: {
      registered: Boolean(sess?.credentialId),
      loggedIn: Boolean(sess?.loggedIn),
    },
    entitlement: {
      plan: sess?.plan || "none",
      included_quota: INCLUDED_RENDERS_PER_MONTH,
      renders_used: sess?.rendersUsed ?? 0,
      credits_available: sess?.creditsAvailable ?? 0,
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
router.post("/signout", (_req, res) => {
  res.clearCookie("ob_invite");
  return res.json({ ok: true });
});

// --- PASSKEY REGISTER: START --------------------------------------------------
// POST /auth/passkey/register/start
// Body optional: { userId?: string, userName?: string, displayName?: string }
// For solo dev we default to a single tester identity.
router.post("/passkey/register/start", (req, res) => {
  const sid = getOrCreateSid(req, res);
  const sess = sessions.get(sid)!;

  const rpId = getRpId(req);
  const challenge = genChallenge();

  // Single tester defaults; can be moved to DB later
  const body = (req.body || {}) as { userId?: string; userName?: string; displayName?: string };
  const userId = (body.userId || "solo-tester");
  const userName = (body.userName || "solo@tester.example");
  const displayName = (body.displayName || "Solo Tester");

  // Minimal PublicKeyCredentialCreationOptions (no libs)
  const options: any = {
    rp: { id: rpId, name: "OffBook (Dev)" },
    user: {
      id: Buffer.from(userId).toString("base64url"),
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
router.post("/passkey/register/finish", express.json({ limit: "1mb" }), (req, res) => {
  const sid = getOrCreateSid(req, res);
  const sess = sessions.get(sid)!;

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
  sess.userId = sess.userId || "solo-tester";
  sess.loggedIn = true;
  delete sess.regChallenge;

  // Auto sign-in after successful registration
  const sid2 = getOrCreateSid(req, res);
  const postSess = sessions.get(sid2) || {};
  postSess.loggedIn = true;
  postSess.userId = postSess.userId || `passkey:${(postSess.credentialId || "").slice(0, 8)}`;
  sessions.set(sid2, postSess);

  return res.json({ ok: true, userId: sess.userId, credentialId: sess.credentialId, autoSignedIn: true });
});

// --- PASSKEY LOGIN: START -----------------------------------------------------
// POST /auth/passkey/login/start
// Body optional: { userId?: string } -- kept for parity; allowCredentials omitted for dev.
router.post("/passkey/login/start", (req, res) => {
  const sid = getOrCreateSid(req, res);
  const sess = sessions.get(sid)!;

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
router.post("/passkey/login/finish", express.json({ limit: "1mb" }), (req, res) => {
  const sid = getOrCreateSid(req, res);
  const sess = sessions.get(sid)!;

  if (!sess.authChallenge) {
    return res.status(400).json({ ok: false, error: "no_challenge" });
  }
  if (!sess.credentialId) {
    return res.status(400).json({ ok: false, error: "no_registered_credential" });
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
  const credOk = (String(id) === sess.credentialId);

  if (!challengeOk) return res.status(400).json({ ok: false, error: "challenge_mismatch" });
  if (!typeOk)      return res.status(400).json({ ok: false, error: "type_mismatch" });
  if (!originOk)    return res.status(400).json({ ok: false, error: "origin_mismatch", expected: allowedOrigin, got: clientData.origin });
  if (!credOk)      return res.status(401).json({ ok: false, error: "unknown_credential" });

  sess.loggedIn = true;
  delete sess.authChallenge;

  return res.json({ ok: true, userId: sess.userId || "solo-tester" });
});

// --- DEV ONLY: Grant credits to current session ------------------------------
// Enabled only when URL has ?dev=1 OR ENV DEV_TOOLS=true (light guard).
router.post("/dev/grant-credits", express.json(), (req, res) => {
  const devToolsOn = /^true$/i.test(process.env.DEV_TOOLS || "") ||
                     /(^|[?&])dev(=1|&|$)/.test(req.url);
  if (!devToolsOn) return res.status(403).json({ ok: false, error: "dev_tools_disabled" });

  const sid = getOrCreateSid(req, res);
  const sess = sessions.get(sid)!;

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

router.post("/dev/use-credit", express.json(), (req, res) => {
  const devToolsOn = /^true$/i.test(process.env.DEV_TOOLS || "") ||
                     /(^|[?&])dev(=1|&|$)/.test(req.url);
  if (!devToolsOn) {
    return res.status(403).json({ ok: false, error: "dev_tools_disabled" });
  }

  const sid = getOrCreateSid(req, res);
  const sess = sessions.get(sid)!;

  const beforeUsed =
    typeof sess.rendersUsed === "number" ? sess.rendersUsed : 0;
  const beforeCredits =
    typeof sess.creditsAvailable === "number" ? sess.creditsAvailable : 0;

  if (beforeCredits <= 0) {
    return res.status(400).json({
      ok: false,
      error: "no_credits",
      renders_used: beforeUsed,
      credits_available: beforeCredits,
    });
  }

  const used = beforeUsed + 1;
  const credits = beforeCredits - 1;

  sess.rendersUsed = used;
  sess.creditsAvailable = credits;

  console.log(
    "[credits] dev use-credit: sid=%s used %d→%d credits %d→%d",
    sid,
    beforeUsed,
    used,
    beforeCredits,
    credits
  );

  return res.json({
    ok: true,
    sid,
    renders_used: used,
    credits_available: credits,
  });
});

export default router;
