import { Router } from "express";
import { v4 as uuidv4 } from "uuid";
import Database from "better-sqlite3";
import crypto from "crypto";
import {
  verifyRegistrationResponse,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import { dbGet, dbRun } from "../lib/db";

const rpName = "OffBook MVP";
const rpID = process.env.RP_ID || "localhost";
const origin = process.env.RP_ORIGIN || "http://localhost:3010";
const inviteCodeEnv = (process.env.INVITE_CODE || "").trim(); // optional gate

// Schema bootstrap is now handled by ensureSchema() in src/lib/db.ts

function sess(req: any) { return req.session || (req.session = {}); }

export function makeAuthRouter(_db?: Database.Database) {
  const r = Router();

  // Begin registration (requires access code if INVITE_CODE is set)
  r.post("/begin-register", (req: any, res) => {
    const { accessCode, email } = req.body || {};
    if (inviteCodeEnv && accessCode !== inviteCodeEnv) {
      return res.status(401).json({ error: "Invalid invite code" });
    }
    const userId = uuidv4();
    const challenge = crypto.randomBytes(32).toString("base64url");
    const options = {
      rp: { name: rpName, id: rpID },
      user: {
        id: Buffer.from(userId).toString("base64url"),
        name: email || `user-${userId}`,
        displayName: email || `user-${userId}`,
      },
      challenge,
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },
        { type: "public-key", alg: -257 },
      ],
      timeout: 60000,
      attestation: "none",
      authenticatorSelection: { residentKey: "preferred", userVerification: "preferred" },
    };
    const s = sess(req);
    s.regChallenge = challenge;
    s.tmpUserId = userId;
    s.tmpEmail = email || null;
    return res.json(options);
  });

  // Finish registration
  r.post("/finish-register", async (req: any, res) => {
    const s = sess(req);
    try {
      const verification = await verifyRegistrationResponse({
        response: req.body,
        expectedChallenge: s.regChallenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
      });
      if (!verification.verified || !verification.registrationInfo) {
        return res.status(400).json({ error: "Registration failed" });
      }
      const regInfo = verification.registrationInfo;
      const credentialID = regInfo.credential.id;
      const credentialPublicKey = regInfo.credential.publicKey;
      const counter = regInfo.credential.counter;

      const userId = s.tmpUserId || uuidv4();
      const email = s.tmpEmail || null;
      const now = Date.now();

      // Insert user (ignore if exists)
      const existingUser = await dbGet<{ id: string }>("SELECT id FROM users WHERE id = ?", [userId]);
      if (!existingUser) {
        await dbRun("INSERT INTO users (id, email, created_at) VALUES (?, ?, ?)", [userId, email, now]);
      }

      // Insert credential
      await dbRun(
        "INSERT INTO webauthn_credentials (id, user_id, public_key, counter, created_at) VALUES (?, ?, ?, ?, ?)",
        [
          Buffer.from(credentialID).toString("base64url"),
          userId,
          Buffer.from(credentialPublicKey).toString("base64url"),
          counter,
          now,
        ]
      );

      s.userId = userId;
      delete s.regChallenge; delete s.tmpUserId; delete s.tmpEmail;
      res.json({ ok: true, userId });
    } catch {
      res.status(400).json({ error: "Registration error" });
    }
  });

  // Begin login
  r.post("/begin-login", (_req: any, res) => {
    const challenge = crypto.randomBytes(32).toString("base64url");
    const options = {
      challenge,
      timeout: 60000,
      rpId: rpID,
      userVerification: "preferred",
    };
    sess(_req).authChallenge = challenge;
    return res.json(options);
  });

  // Finish login
  r.post("/finish-login", async (req: any, res) => {
    const s = sess(req);
    try {
      const credId = Buffer.from(req.body.rawId || "", "base64").toString("base64url");
      const cred = await dbGet<{ id: string; user_id: string; public_key: string; counter: number }>(
        "SELECT * FROM webauthn_credentials WHERE id = ?",
        [credId]
      );
      if (!cred) return res.status(401).json({ error: "Unknown credential" });
      const verification = await verifyAuthenticationResponse({
        response: req.body,
        expectedChallenge: s.authChallenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
        credential: {
          id: cred.id,
          publicKey: new Uint8Array(Buffer.from(cred.public_key, "base64url")),
          counter: cred.counter,
        },
      });
      if (!verification.verified || !verification.authenticationInfo) {
        return res.status(401).json({ error: "Login failed" });
      }
      await dbRun("UPDATE webauthn_credentials SET counter = ? WHERE id = ?", [
        verification.authenticationInfo.newCounter,
        cred.id,
      ]);
      s.userId = cred.user_id;
      delete s.authChallenge;
      res.json({ ok: true, userId: cred.user_id });
    } catch {
      res.status(400).json({ error: "Login error" });
    }
  });

  // Session probe
  r.get("/session", (req: any, res) => {
    const userId = req.session?.userId || null;
    res.json({ userId, hasSecret: Boolean(process.env.SHARED_SECRET) });
  });

  // Logout
  r.post("/logout", (req: any, res) => {
    req.session = null;
   res.json({ ok: true });
  });

  return r;
}
