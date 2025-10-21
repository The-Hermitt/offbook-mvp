import express from "express";
import path from "path";
import cors from "cors";
import morgan from "morgan";
import { fileURLToPath } from "url";
import { initHttpRoutes } from "./http-routes"; // <— no .js; tsx resolves this

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// Core middleware
app.use(cors());
app.use(express.json({ limit: "4mb" }));
app.use(express.urlencoded({ extended: true, limit: "4mb" }));
app.use(morgan("tiny"));

// Static UI
const publicDir = path.join(__dirname, "..", "public");
app.use(express.static(publicDir));

// Health endpoints
app.get("/health", (_req, res) => res.json({ ok: true }));
app.get("/health/tts", (_req, res) => {
  res.json({ provider: "openai", has_key: !!process.env.OPENAI_API_KEY });
});

// Attach API/Debug routes
initHttpRoutes(app);

// 404 for API/Debug only
app.use((req, res, _next) => {
  if (req.path.startsWith("/api") || req.path.startsWith("/debug")) return res.status(404).send("Not Found");
  res.sendFile(path.join(publicDir, "app-tabs.html"));
});

const PORT = process.env.PORT ? Number(process.env.PORT) : 3000;
app.listen(PORT, () => console.log(`OffBook listening on :${PORT}`));

export default app;
