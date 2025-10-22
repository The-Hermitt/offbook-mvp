cat > src/server.ts <<'EOF'
// src/server.ts (MCP-enabled)
import express from "express";
import path from "path";
import cors from "cors";
import morgan from "morgan";
import { fileURLToPath } from "url";
import { request } from "undici";
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
app.get("/health", (_req, res) => res.json({ ok: true }));
app.get("/health/tts", (_req, res) => {
  const hasKey = !!process.env.OPENAI_API_KEY;
  res.json({ provider: hasKey ? "openai" : "stub", has_key: hasKey });
});

// --- App / Debug / API routes
initHttpRoutes(app);

// =============== MCP SHIM ===============
type ToolCall =
  | { tool: "upload_script"; args: { title: string; text: string } }
  | { tool: "list_scenes"; args: { script_id: string } }
  | { tool: "set_voice"; args: { script_id: string; voice_map: Record<string, string> } }
  | { tool: "render_reader"; args: { script_id: string; scene_id: string; role: string; pace?: string } }
  | { tool: "render_status"; args: { render_id: string } };

const PORT = Number(process.env.PORT || 3010);
const HOST = process.env.HOST || "0.0.0.0";
const FORWARD_BASE = process.env.MCP_FORWARD_BASE || `http://127.0.0.1:${PORT}`;
const SHARED_SECRET = process.env.SHARED_SECRET || "";

function jsonHeaders() {
  const h: Record<string, string> = { "Content-Type": "application/json" };
  if (SHARED_SECRET) h["X-Shared-Secret"] = SHARED_SECRET;
  return h;
}

// Full descriptor ChatGPT fetches
app.get("/mcp", (_req, res) => {
  console.log("[mcp] descriptor served");
  res.json({
    name: "offbook-mcp",
    version: "0.1.0",
    transport: "http",
    description: "OffBook MCP shim (dev). Forwards to /debug/* endpoints.",
    tools: [
      {
        name: "upload_script",
        description: "Upload script as plain text. Returns { script_id, scene_count }.",
        input_schema: {
          type: "object",
          required: ["title", "text"],
          properties: { title: { type: "string" }, text: { type: "string" } },
        },
      },
      {
        name: "list_scenes",
        description: "List parsed scenes for a script.",
        input_schema: {
          type: "object",
          required: ["script_id"],
          properties: { script_id: { type: "string" } },
        },
      },
      {
        name: "set_voice",
        description: "Set AI voice per role. Returns { ok:true }.",
        input_schema: {
          type: "object",
          required: ["script_id", "voice_map"],
          properties: {
            script_id: { type: "string" },
            voice_map: { type: "object", additionalProperties: { type: "string" } },
          },
        },
      },
      {
        name: "render_reader",
        description: "Render partner-only reader track. Returns { render_id, status }.",
        input_schema: {
          type: "object",
          required: ["script_id", "scene_id", "role"],
          properties: {
            script_id: { type: "string" },
            scene_id: { type: "string" },
            role: { type: "string" },
            pace: { type: "string", enum: ["slow", "normal", "fast"], default: "normal" },
          },
        },
      },
      {
        name: "render_status",
        description: "Check render status. Returns { status, download_url? }.",
        input_schema: {
          type: "object",
          required: ["render_id"],
          properties: { render_id: { type: "string" } },
        },
      },
    ],
  });
});

// Tool invoker → forwards to your existing /debug/* endpoints
app.post("/mcp/call", async (req, res) => {
  const body = req.body as ToolCall;
  try {
    let r;
    switch (body.tool) {
      case "upload_script":
        r = await request(`${FORWARD_BASE}/debug/upload_script_text`, {
          method: "POST",
          headers: jsonHeaders(),
          body: JSON.stringify({ title: body.args.title, text: body.args.text }),
        });
        break;

      case "list_scenes": {
        const url = `${FORWARD_BASE}/debug/scenes?script_id=${encodeURIComponent(body.args.script_id)}`;
        r = await request(url, { method: "GET", headers: jsonHeaders() });
        break;
      }

      case "set_voice":
        r = await request(`${FORWARD_BASE}/debug/set_voice`, {
          method: "POST",
          headers: jsonHeaders(),
          body: JSON.stringify({ script_id: body.args.script_id, voice_map: body.args.voice_map }),
        });
        break;

      case "render_reader":
        r = await request(`${FORWARD_BASE}/debug/render`, {
          method: "POST",
          headers: jsonHeaders(),
          body: JSON.stringify({
            script_id: body.args.script_id,
            scene_id: body.args.scene_id,
            role: body.args.role,
            pace: body.args.pace || "normal",
          }),
        });
        break;

      case "render_status": {
        const url = `${FORWARD_BASE}/debug/render_status?render_id=${encodeURIComponent(body.args.render_id)}`;
        r = await request(url, { method: "GET", headers: jsonHeaders() });
        break;
      }

      default:
        return res.status(400).json({ error: "unknown_tool" });
    }

    const status = r.statusCode || 500;
    const text = await r.body.text();
    try { return res.status(status).json(JSON.parse(text)); }
    catch { return res.status(status).send(text); }
  } catch (err: any) {
    return res.status(500).json({ error: "mcp_forward_error", message: String(err?.message || err) });
  }
});
// ============= END MCP SHIM =============

// Default UI route
app.get("/", (_req, res) => {
  res.sendFile(path.join(publicDir, "app-tabs.html"));
});

// Error safety nets
process.on("uncaughtException", (err) => console.error("[fatal] uncaughtException:", err));
process.on("unhandledRejection", (reason) => console.error("[fatal] unhandledRejection:", reason));

// Start server on 3010 / 0.0.0.0
app.listen(Number(process.env.PORT || 3010), process.env.HOST || "0.0.0.0", () => {
  console.log(`[offbook] listening on http://${process.env.HOST || "0.0.0.0"}:${Number(process.env.PORT || 3010)}`);
});

export default app;
EOF
