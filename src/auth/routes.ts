import { Router } from "express";
import { v4 as uuidv4 } from "uuid";
import Database from "better-sqlite3";
import crypto from "crypto";
import {
  verifyRegistrationResponse,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import db from "../lib/db";

const rpName = "OffBook MVP";
const rpID = process.env.RP_ID || "localhost";
const origin = process.env.RP_ORIGIN || "http://localhost:3010";
const inviteCodeEnv = (process.env.INVITE_CODE || "").trim(); // optional gate

// DB helpers (idempotent bootstrap of tables)
const bootstrap = `
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT,
    created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id TEXT PRIMARY KEY,           -- credentialID (base64url)
    user_id TEXT NOT NULL,
    public_key TEXT NOT NULL,      -- base64url
    counter INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS idx_webauthn_user ON webauthn_credentials(user_id);
`;
db.exec(bootstrap);

const q = {
  insertUser: db.prepare("INSERT OR IGNORE INTO users (id, email, created_at) VALUES (@id, @email, @created_at)"),
  getCredById: db.prepare("SELECT * FROM webauthn_credentials WHERE id=@id"),
  getCredsByUser: db.prepare("SELECT * FROM webauthn_credentials WHERE user_id=@user_id"),
  insertCred: db.prepare(`INSERT INTO webauthn_credentials (id, user_id, public_key, counter, created_at)
                          VALUES (@id, @user_id, @public_key, @counter, @created_at)`),
  updateCounter: db.prepare("UPDATE webauthn_credentials SET counter=@counter WHERE id=@id"),
};

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
      const { credentialID, credentialPublicKey, counter } = verification.registrationInfo;
      const userId = s.tmpUserId || uuidv4();
      const email = s.tmpEmail || null;
      q.insertUser.run({ id: userId, email, created_at: Date.now() });
      q.insertCred.run({
        id: Buffer.from(credentialID).toString("base64url"),
        user_id: userId,
        public_key: Buffer.from(credentialPublicKey).toString("base64url"),
        counter,
        created_at: Date.now(),
      });
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
      const cred = q.getCredById.get({ id: credId });
      if (!cred) return res.status(401).json({ error: "Unknown credential" });
      const verification = await verifyAuthenticationResponse({
        response: req.body,
        expectedChallenge: s.authChallenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
        authenticator: {
          credentialID: Buffer.from(cred.id, "base64url"),
          credentialPublicKey: Buffer.from(cred.public_key, "base64url"),
          counter: cred.counter,
        },
      });
      if (!verification.verified || !verification.authenticationInfo) {
        return res.status(401).json({ error: "Login failed" });
      }
      q.updateCounter.run({ id: cred.id, counter: verification.authenticationInfo.newCounter });
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
