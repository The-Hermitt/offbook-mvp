// src/server.ts
import express, { Request, Response, NextFunction } from "express";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";

// Resolve __dirname in ESM
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Env
const PORT = Number(process.env.PORT || 3010);
const SHARED_SECRET = process.env.SHARED_SECRET || "";

// App
const app = express();
app.disable("x-powered-by");
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));

// Shared-secret guard for debug endpoints
function requireSecret(req: Request, res: Response, next: NextFunction) {
  const hdr = req.header("X-Shared-Secret") || "";
  if (!SHARED_SECRET) return next(); // no secret set -> allow
  if (hdr === SHARED_SECRET) return next();
  return res.status(401).json({ error: "unauthorized" });
}

// Static files (UI)
const publicDir = path.join(__dirname, "..", "public");
app.use(express.static(publicDir, { extensions: ["html"] }));

// Health
app.get("/health", (_req, res) => {
  res.json({
    ok: true,
    service: "offbook-mvp",
    node: process.version,
    openai: "openai",
    has_key: Boolean(process.env.OPENAI_API_KEY),
  });
});

app.get("/health/tts", (_req, res) => {
  res.json({
    ok: true,
    tts: "openai",
    has_key: Boolean(process.env.OPENAI_API_KEY),
  });
});

// Optionally mount project routes if present
(async () => {
  try {
    const mod = await import("./http-routes.ts").catch(() => null as any);
    if (mod) {
      if (typeof (mod as any).registerHttpRoutes === "function") {
        (mod as any).registerHttpRoutes(app, { requireSecret });
        console.log("[routes] registerHttpRoutes(app) mounted");
      } else if (typeof (mod as any).default === "function") {
        (mod as any).default(app, { requireSecret });
        console.log("[routes] default(app) mounted");
      } else {
        console.log("[routes] http-routes.ts present but no handler export detected");
      }
    } else {
      console.log("[routes] http-routes.ts not found; serving static UI + health only");
    }
  } catch (err) {
    console.error("[routes] failed to mount http routes:", err);
  }

  // Fallback: serve app-tabs.html on root
  app.get("/", (_req, res) => {
    const p = path.join(publicDir, "app-tabs.html");
    if (fs.existsSync(p)) return res.sendFile(p);
    return res.type("text/plain").send("OffBook MVP running. Public UI not found.");
  });

  // Start server
  app.listen(PORT, () => {
    console.log(`OffBook MVP listening on http://localhost:${PORT}`);
    if (SHARED_SECRET) {
      console.log(`Debug routes require header X-Shared-Secret: ${SHARED_SECRET}`);
      console.log(`UI tip: open /app-tabs.html?secret=${SHARED_SECRET}`);
    }
  });
})();
