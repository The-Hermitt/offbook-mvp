// src/server.ts
import express, { Request, Response, NextFunction } from "express";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import type { IncomingHttpHeaders } from "http";
import { setTimeout as delay } from "timers/promises";

// Node 20+ has global fetch, but we vendor undici in package.json so both paths work.
const _fetch: typeof fetch = (globalThis as any).fetch;

// Resolve __dirname in ESM
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ---- ENV ----
const PORT = Number(process.env.PORT || 3010);
const HOST = process.env.HOST || "0.0.0.0";
const SHARED_SECRET = process.env.SHARED_SECRET || ""; // "1976" in your dev logs

// ---- APP ----
const app = express();
app.disable("x-powered-by");
app.use(express.json({ limit: "5mb" }));
app.use(express.urlencoded({ extended: true }));

// ---- MIDDLEWARE: optional shared-secret guard for debug routes ----
function requireSecret(req: Request, res: Response, next: NextFunction) {
  if (!SHARED_SECRET) return next(); // allow if secret not configured
  const hdr = req.header("X-Shared-Secret") || "";
  if (hdr === SHARED_SECRET) return next();
  return res.status(401).json({ error: "unauthorized", need: "X-Shared-Secret" });
}

// ---- STATIC UI ----
const publicDir = path.join(__dirname, "..", "public");
app.use(express.static(publicDir, { extensions: ["html"] }));

// Root convenience: serve tab UI if present
app.get("/", (_req, res) => {
  const p = path.join(publicDir, "app-tabs.html");
  if (fs.existsSync(p)) return res.sendFile(p);
  return res.type("text/plain").send("OffBook MVP running. Public UI not found.");
});

// ---- HEALTH ----
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

// ---- OPTIONAL: Mount your existing HTTP routes if present ----
// We support either: export function registerHttpRoutes(app, helpers) or export default(app, helpers)
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
        console.log("[routes] ./http-routes.ts found but no handler export detected");
      }
    } else {
      console.log("[routes] ./http-routes.ts not found; serving static UI + health only");
    }
  } catch (err) {
    console.error("[routes] failed to mount http routes:", err);
  }
})();

// ============================================================================
//                         MCP OVER HTTP (Descriptor + Call)
// ============================================================================

// Tool schemas (intentionally minimal & aligned to your debug endpoints)
const MCP_DESCRIPTOR = {
  name: "offbook-mcp",
  version: "1.0.0",
  tools: [
    {
      name: "upload_script",
      description: "Upload a script as plain text.",
      input_schema: {
        type: "object",
        properties: {
          title: { type: "string" },
          text: { type: "string" },
        },
        required: ["title", "text"],
      },
    },
    {
      name: "list_scenes",
      description: "List parsed scenes for a given script_id.",
      input_schema: {
        type: "object",
        properties: {
          script_id: { type: "string" },
        },
        required: ["script_id"],
      },
    },
    {
      name: "set_voice",
      description: "Assign AI voices to characters other than the user's role.",
      input_schema: {
        type: "object",
        properties: {
          script_id: { type: "string" },
          voice_map: { type: "object", additionalProperties: { type: "string" } },
        },
        required: ["script_id", "voice_map"],
      },
    },
    {
      name: "render_reader",
      description: "Render a reader track for a role (AI speaks partner lines only).",
      input_schema: {
        type: "object",
        properties: {
          script_id: { type: "string" },
          scene_id: { type: "string" },
          role: { type: "string" },
          pace: { type: "string", enum: ["slow", "normal", "fast"], default: "normal" },
        },
        required: ["script_id", "scene_id", "role"],
      },
    },
    {
      name: "render_status",
      description: "Check render status and get download URL when complete.",
      input_schema: {
        type: "object",
        properties: {
          render_id: { type: "string" },
        },
        required: ["render_id"],
      },
    },
  ],
} as const;

// Descriptor endpoint (used by ChatGPT to discover tools)
app.get("/mcp", (_req, res) => {
  res.json(MCP_DESCRIPTOR);
});

// Call dispatcher: forwards to existing debug REST
app.post("/mcp/call", express.json(), async (req: Request, res: Response) => {
  try {
    const { tool, args } = req.body || {};
    if (!tool || typeof tool !== "string") {
      return res.status(400).json({ error: "missing 'tool' name" });
    }
    const a = (args ?? {}) as Record<string, any>;

    // Forwarding base (loopback to this server)
    const base = `http://127.0.0.1:${PORT}`;
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (SHARED_SECRET) headers["X-Shared-Secret"] = SHARED_SECRET;

    let r: Response;
    switch (tool) {
      case "upload_script": {
        // POST /debug/upload_script_text {title, text}
        r = await _fetch(`${base}/debug/upload_script_text`, {
          method: "POST",
          headers,
          body: JSON.stringify({ title: a.title, text: a.text }),
        } as any);
        break;
      }
      case "list_scenes": {
        // GET /debug/scenes?script_id=...
        const url = new URL(`${base}/debug/scenes`);
        url.searchParams.set("script_id", a.script_id);
        r = await _fetch(url, { headers } as any);
        break;
      }
      case "set_voice": {
        // POST /debug/set_voice {script_id, voice_map}
        r = await _fetch(`${base}/debug/set_voice`, {
          method: "POST",
          headers,
          body: JSON.stringify({ script_id: a.script_id, voice_map: a.voice_map }),
        } as any);
        break;
      }
      case "render_reader": {
        // POST /debug/render {script_id, scene_id, role, pace}
        r = await _fetch(`${base}/debug/render`, {
          method: "POST",
          headers,
          body: JSON.stringify({
            script_id: a.script_id,
            scene_id: a.scene_id,
            role: a.role,
            pace: a.pace || "normal",
          }),
        } as any);
        break;
      }
      case "render_status": {
        // GET /debug/render_status?render_id=...
        const url = new URL(`${base}/debug/render_status`);
        url.searchParams.set("render_id", a.render_id);
        r = await _fetch(url, { headers } as any);
        break;
      }
      default:
        return res.status(400).json({ error: `unknown tool '${tool}'` });
    }

    const text = await (r as any).text();
    const ct = (r.headers.get("content-type") || "").toLowerCase();
    if (ct.includes("application/json")) {
      return res.status((r as any).status).type("application/json").send(text);
    }
    // Fallback: pass through as text
    return res.status((r as any).status).type("text/plain").send(text);
  } catch (err: any) {
    console.error("[/mcp/call] error", err);
    return res.status(500).json({ error: "mcp_call_failed", detail: String(err?.message || err) });
  }
});

// ============================================================================
//                                START SERVER
// ============================================================================
app.listen(PORT, HOST, () => {
  console.log(`✅ OffBook MVP listening on http://${HOST === "0.0.0.0" ? "localhost" : HOST}:${PORT}`);
  if (SHARED_SECRET) {
    console.log(`→ Shared secret required for /debug/* : X-Shared-Secret: ${SHARED_SECRET}`);
  }
  console.log("→ MCP descriptor: GET /mcp");
  console.log("→ MCP call:       POST /mcp/call {tool, args}");
});
