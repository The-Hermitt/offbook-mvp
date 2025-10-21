// src/server.ts
import express from "express";
import path from "path";
import cors from "cors";
import morgan from "morgan";
import { fileURLToPath } from "url";
import { initHttpRoutes } from "./http-routes.js"; // ESM NodeNext style

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.set("trust proxy", true);

// --- Core middleware
app.use(cors());
app.use(express.json({ limit: "4mb" }));
app.use(express.urlencoded({ extended: true, limit: "4mb" }));
app.use(morgan("tiny"));

// --- Static (UI)
const publicDir = path.join(__dirname, "..", "public");
app.use(express.static(publicDir));

// --- Health endpoints
app.get("/health", (_req, res) => {
  res.json({ ok: true });
});

app.get("/health/tts", (_req, res) => {
  const hasKey = !!process.env.OPENAI_API_KEY;
  res.json({ provider: hasKey ? "openai" : "stub", has_key: hasKey });
});

// --- App / Debug / API routes
// (initHttpRoutes internally mounts /debug and /api regardless of NODE_ENV;
//   if SHARED_SECRET is set, /debug requires X-Shared-Secret)
initHttpRoutes(app);

// --- Default UI route
app.get("/", (_req, res) => {
  res.sendFile(path.join(publicDir, "app-tabs.html"));
});

// --- Error safety nets (avoid process crash → 502)
process.on("uncaughtException", (err) => {
  console.error("[fatal] uncaughtException:", err);
});
process.on("unhandledRejection", (reason) => {
  console.error("[fatal] unhandledRejection:", reason);
});

// --- Start server
const PORT = process.env.PORT ? Number(process.env.PORT) : 10000;
app.listen(PORT, () => {
  console.log(`[offbook] listening on ${PORT}`);
});

export default app;
