// src/mcp-server.ts
// Minimal MCP HTTP shim for local/dev.
// Exposes GET /mcp (descriptor) and POST /mcp/call to forward to existing /debug/* routes.
// No auth on MCP itself; if SHARED_SECRET is set, it's forwarded to /debug/* calls.

import type { Express, Request, Response } from "express";
import { request } from "undici";

type ToolCall =
  | { tool: "upload_script"; args: { title: string; text?: string } } // text path (PDF is not wired via MCP in this shim)
  | { tool: "list_scenes"; args: { script_id: string } }
  | { tool: "set_voice"; args: { script_id: string; voice_map: Record<string, string> } }
  | { tool: "render_reader"; args: { script_id: string; scene_id: string; role: string; pace?: string } }
  | { tool: "render_status"; args: { render_id: string } };

const SHARED_SECRET = process.env.SHARED_SECRET || "";
const FORWARD_BASE =
  process.env.MCP_FORWARD_BASE || `http://127.0.0.1:${process.env.PORT || 3010}`;

export function initMcpServer(app: Express) {
  // Descriptor for ChatGPT to fetch during connector creation
  app.get("/mcp", (_req: Request, res: Response) => {
    res.json({
      name: "offbook-mcp",
      version: "0.1.0",
      description:
        "OffBook MCP shim – forwards tool calls to existing /debug/* endpoints.",
      transport: "http",
      tools: [
        {
          name: "upload_script",
          description:
            "Upload script as plain text. Returns { script_id, scene_count }.",
          input_schema: {
            type: "object",
            required: ["title", "text"],
            properties: {
              title: { type: "string" },
              text: { type: "string" },
            },
          },
        },
        {
          name: "list_scenes",
          description:
            "List parsed scenes for a given script_id. Returns { script_id, scenes:[...] }.",
          input_schema: {
            type: "object",
            required: ["script_id"],
            properties: {
              script_id: { type: "string" },
            },
          },
        },
        {
          name: "set_voice",
          description:
            "Set AI voices per role. Returns { ok:true }.",
          input_schema: {
            type: "object",
            required: ["script_id", "voice_map"],
            properties: {
              script_id: { type: "string" },
              voice_map: {
                type: "object",
                additionalProperties: { type: "string" },
              },
            },
          },
        },
        {
          name: "render_reader",
          description:
            "Render partner-only reader track. Returns { render_id, status }.",
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
          description:
            "Check render status. Returns { status, download_url? }.",
          input_schema: {
            type: "object",
            required: ["render_id"],
            properties: {
              render_id: { type: "string" },
            },
          },
        },
      ],
    });
  });

  // Tool invoker – forwards to /debug/* routes that already exist
  app.post("/mcp/call", async (req: Request, res: Response) => {
    const body = req.body as ToolCall;
    try {
      const headers: Record<string, string> = {
        "Content-Type": "application/json",
      };
      if (SHARED_SECRET) headers["X-Shared-Secret"] = SHARED_SECRET;

      let r;
      switch (body.tool) {
        case "upload_script": {
          // text path only (most reliable); PDF upload is UI-only for now
          r = await request(`${FORWARD_BASE}/debug/upload_script_text`, {
            method: "POST",
            headers,
            body: JSON.stringify({
              title: body.args.title,
              text: body.args.text || "",
            }),
          });
          break;
        }
        case "list_scenes": {
          const url = `${FORWARD_BASE}/debug/scenes?script_id=${encodeURIComponent(
            body.args.script_id
          )}`;
          r = await request(url, { method: "GET", headers });
          break;
        }
        case "set_voice": {
          r = await request(`${FORWARD_BASE}/debug/set_voice`, {
            method: "POST",
            headers,
            body: JSON.stringify({
              script_id: body.args.script_id,
              voice_map: body.args.voice_map,
            }),
          });
          break;
        }
        case "render_reader": {
          r = await request(`${FORWARD_BASE}/debug/render`, {
            method: "POST",
            headers,
            body: JSON.stringify({
              script_id: body.args.script_id,
              scene_id: body.args.scene_id,
              role: body.args.role,
              pace: body.args.pace || "normal",
            }),
          });
          break;
        }
        case "render_status": {
          const url = `${FORWARD_BASE}/debug/render_status?render_id=${encodeURIComponent(
            body.args.render_id
          )}`;
          r = await request(url, { method: "GET", headers });
          break;
        }
        default:
          return res.status(400).json({ error: "Unknown tool" });
      }

      const text = await r.body.text();
      const status = r.statusCode || 500;
      // Try to parse JSON; fall back to text
      try {
        return res.status(status).json(JSON.parse(text));
      } catch {
        return res.status(status).send(text);
      }
    } catch (err: any) {
      return res
        .status(500)
        .json({ error: "mcp_forward_error", message: String(err?.message || err) });
    }
  });
}
