// src/server.ts
import express from "express";
import path from "node:path";
import morgan from "morgan";
import { fileURLToPath } from "node:url";
import { initMcpServer } from "./mcp-server.js";
// If your repo already has http routes in a helper, keep them:
import { initHttpRoutes } from "./http-routes.js"; // assumes it exists per project pack

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.disable("x-powered-by");
app.use(morgan("dev"));
app.use(express.json({ limit: "5mb" }));
app.use(express.urlencoded({ extended: true }));

// Health
app.get("/health", (_req, res) => res.json({ ok: true }));
app.get("/health/tts", (_req, res) =>
  res.json({ provider: "openai", has_key: Boolean(process.env.OPENAI_API_KEY) })
);

// Static UI
app.use(express.static(path.join(__dirname, "..", "public")));

// Existing debug/API routes (upload, scenes, set_voice, render, etc.)
if (typeof initHttpRoutes === "function") {
  initHttpRoutes(app);
}

// MCP
initMcpServer(app);

// Start
const PORT = Number(process.env.PORT || 3010);
const HOST = process.env.HOST || "0.0.0.0";
app.listen(PORT, HOST, () => {
  console.log(`[offbook] listening on http://${HOST}:${PORT}`);
});
