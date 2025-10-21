import express from "express";
import path from "path";
import cors from "cors";
import morgan from "morgan";
import { fileURLToPath } from "url";
import { initHttpRoutes } from "./http-routes";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// --- Core middleware
app.use(cors());
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));
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
  res.json({ provider: "openai", has_key: hasKey });
});

// --- App / Debug / API routes
initHttpRoutes(app);

// --- 404 fallback for non-static, non-API requests
app.use((req, res, _next) => {
  if (req.path.startsWith("/api") || req.path.startsWith("/debug")) {
    return res.status(404).send("Not Found");
  }
  // serve UI index if someone hits unknown paths in public
  res.sendFile(path.join(publicDir, "app-tabs.html"));
});

const PORT = process.env.PORT ? Number(process.env.PORT) : 3000;
app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`OffBook server listening on :${PORT}`);
});
