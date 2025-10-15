// src/mcp-server.ts
// OffBook MCP server: exposes tools that call the same code behind our REST debug routes.
// Tools:
// - upload_script(pdf_url, title) -> { script_id, title, scene_count }
// - list_scenes(script_id)        -> { script_id, scenes:[{id,title,ord,line_count}] }
// - set_voice(script_id, voice_map)
// - render_reader(script_id, scene_id, role, pace) -> { render_id, status }
// - render_status(render_id) -> { render_id, status, download_url? }

import { z } from "zod";
import fs from "node:fs";
import path from "node:path";

import {
  insertScript, insertScene, insertLine,
  getScenes, countScenes, countLines, getLines,
  upsertVoices, createRender, completeRender, getRender, failRender, getVoiceFor,
} from "./lib/db.js";

import { downloadPDF, parsePDF } from "./lib/pdf.js";
import { generateReaderMp3 } from "./lib/tts.js";

// MCP SDK (Typescript)
import {
  Server,
  type ToolHandler,
} from "@modelcontextprotocol/sdk/server/index.js";

// ————————————————————————————————————————————————————————————————————
// Schemas
// ————————————————————————————————————————————————————————————————————
const UploadScriptInput = z.object({
  pdf_url: z.string().url(),
  title: z.string().min(1).max(255),
});

const ListScenesInput = z.object({
  script_id: z.string().min(1),
});

const SetVoiceInput = z.object({
  script_id: z.string().min(1),
  voice_map: z.record(z.string().min(1)).min(1), // { CHARACTER: "voice" }
});

const RenderReaderInput = z.object({
  script_id: z.string().min(1),
  scene_id: z.string().min(1),
  role: z.string().min(1),
  pace: z.enum(["slow", "normal", "fast"]).default("normal"),
});

const RenderStatusInput = z.object({
  render_id: z.string().min(1),
});

// ————————————————————————————————————————————————————————————————————
// Tool handlers (mirror the REST logic)
// ————————————————————————————————————————————————————————————————————
const uploadScriptTool: ToolHandler = async (_ctx, args) => {
  const { pdf_url, title } = UploadScriptInput.parse(args);

  if (!/^https:\/\//i.test(pdf_url)) {
    throw new Error("Only https: URLs are allowed for pdf_url");
  }

  const pdfPath = await downloadPDF(pdf_url);
  const buf = fs.readFileSync(pdfPath);
  const parsed: any = await parsePDF(buf);

  if (!parsed || !Array.isArray(parsed.scenes)) {
    throw new Error("Parser returned unexpected shape (no scenes array).");
  }

  const script_id = insertScript(String(title), String(pdfPath));

  let sOrd = 0;
  for (const scene of parsed.scenes) {
    const scene_id = insertScene(
      script_id,
      String(scene?.title ?? `Scene ${sOrd + 1}`),
      sOrd++
    );
    let lOrd = 0;
    const lines = Array.isArray(scene?.lines) ? scene.lines : [];
    for (const ln of lines) {
      insertLine(
        scene_id,
        String(ln?.character ?? "UNKNOWN"),
        String(ln?.text ?? ""),
        lOrd++
      );
    }
  }

  return {
    script_id,
    title,
    scene_count: countScenes(script_id),
  };
};

const listScenesTool: ToolHandler = async (_ctx, args) => {
  const { script_id } = ListScenesInput.parse(args);
  const scenes = getScenes(script_id).map((s) => ({
    id: s.id,
    title: s.title,
    ord: s.ord,
    line_count: countLines(s.id),
  }));
  return { script_id, scenes };
};

const setVoiceTool: ToolHandler = async (_ctx, args) => {
  const { script_id, voice_map } = SetVoiceInput.parse(args);
  upsertVoices(script_id, voice_map);
  return { ok: true };
};

const renderReaderTool: ToolHandler = async (_ctx, args) => {
  const { script_id, scene_id, role, pace } = RenderReaderInput.parse(args);
  const render_id = createRender(script_id, scene_id, role, pace);

  // fire-and-forget background job (same as REST)
  setImmediate(async () => {
    try {
      const lines = getLines(scene_id);
      const voiceMap: Record<string, string> = {};
      const chars = Array.from(new Set(lines.map((l) => l.character)));
      for (const c of chars) {
        voiceMap[c] = getVoiceFor(script_id, c) || "alloy";
      }
      if (!voiceMap["UNKNOWN"]) voiceMap["UNKNOWN"] = "alloy";

      const outPath = await generateReaderMp3(
        lines.map((l) => ({ character: l.character, text: l.text })),
        voiceMap,
        role,
        pace
      );
      completeRender(render_id, outPath);
    } catch (err: any) {
      failRender(render_id, String(err?.message || err));
    }
  });

  return { render_id, status: "pending" };
};

const renderStatusTool: ToolHandler = async (_ctx, args) => {
  const { render_id } = RenderStatusInput.parse(args);
  const r = getRender(render_id);
  if (!r) throw new Error("render not found");

  const payload: any = { render_id, status: r.status };
  if (r.status === "complete" && r.audio_path) {
    payload.download_url = `/api/assets/${render_id}`;
  }
  if (r.status === "error") payload.message = r.message || "unknown error";
  return payload;
};

// ————————————————————————————————————————————————————————————————————
// Factory: create MCP server instance used by src/server.ts
// ————————————————————————————————————————————————————————————————————
export function createMcpServer() {
  const server = new Server({
    name: "offbook-mcp",
    version: "1.0.0",
  });

  server.addTool({
    name: "upload_script",
    description: "Upload a script PDF by URL and parse into scenes/lines.",
    inputSchema: {
      type: "object",
      properties: {
        pdf_url: { type: "string", description: "HTTPS URL to a PDF" },
        title: { type: "string", description: "Display title" },
      },
      required: ["pdf_url", "title"],
      additionalProperties: false,
    },
    handler: uploadScriptTool,
  });

  server.addTool({
    name: "list_scenes",
    description: "List scenes for a given script_id.",
    inputSchema: {
      type: "object",
      properties: {
        script_id: { type: "string" },
      },
      required: ["script_id"],
      additionalProperties: false,
    },
    handler: listScenesTool,
  });

  server.addTool({
    name: "set_voice",
    description:
      "Assign voices for characters in a script. Example: { \"UNKNOWN\": \"alloy\" }",
    inputSchema: {
      type: "object",
      properties: {
        script_id: { type: "string" },
        voice_map: {
          type: "object",
          additionalProperties: { type: "string" },
        },
      },
      required: ["script_id", "voice_map"],
      additionalProperties: false,
    },
    handler: setVoiceTool,
  });

  server.addTool({
    name: "render_reader",
    description:
      "Render a 'reader' audio for partner lines (skipping the chosen role). Returns render_id; poll render_status to obtain download_url.",
    inputSchema: {
      type: "object",
      properties: {
        script_id: { type: "string" },
        scene_id: { type: "string" },
        role: { type: "string" },
        pace: { type: "string", enum: ["slow", "normal", "fast"] },
      },
      required: ["script_id", "scene_id", "role"],
      additionalProperties: false,
    },
    handler: renderReaderTool,
  });

  server.addTool({
    name: "render_status",
    description:
      "Check a render job by render_id. Returns status and optional download_url.",
    inputSchema: {
      type: "object",
      properties: {
        render_id: { type: "string" },
      },
      required: ["render_id"],
      additionalProperties: false,
    },
    handler: renderStatusTool,
  });

  return server;
}
