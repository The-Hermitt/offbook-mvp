// src/server.ts
// @ts-nocheck
import "dotenv/config";
import express from "express";
import cors from "cors";
import fs from "fs";
import path from "path";
import mime from "mime";

import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { randomUUID } from "node:crypto";

import { createMcpServer } from "./mcp-server.js";
import debugRoutes from "./http-routes.js";
import { getRender } from "./lib/db.js";
import { ttsProvider } from "./lib/tts.js";

const app = express();
const PORT = Number(process.env.PORT || 3010);
const HOST = process.env.HOST || "0.0.0.0";

app.use(
  cors({
    origin: "*",
    exposedHeaders: ["Mcp-Session-Id"],
    allowedHeaders: ["Content-Type", "mcp-session-id"],
  })
);
app.use(express.json());

// REST debug routes
app.use("/debug", debugRoutes);

// MCP endpoint
const sessions: Record<string, StreamableHTTPServerTransport> = {};

app.post("/mcp", async (req, res) => {
  const sessionId = (req.headers["mcp-session-id"] as string) || "";
  let transport: StreamableHTTPServerTransport | undefined =
    sessionId && sessions[sessionId];

  if (!transport && isInitializeRequest(req.body)) {
    transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      onsessioninitialized: (sid) => {
        sessions[sid] = transport!;
        console.log(`✓ MCP session initialized: ${sid}`);
      },
      enableDnsRebindingProtection: true,
      allowedHosts: ["127.0.0.1", "localhost"],
    });

    const mcp = createMcpServer();
    await mcp.connect(transport);

    transport.onclose = () => {
      if (transport?.sessionId) {
        delete sessions[transport.sessionId];
        console.log(`✗ MCP session closed: ${transport.sessionId}`);
      }
    };
  }

  if (!transport) {
    res.status(400).json({
      jsonrpc: "2.0",
      error: { code: -32000, message: "No valid session/initialize" },
      id: null,
    });
    return;
  }

  await transport.handleRequest(req, res, req.body);
});

app.get("/mcp", async (req, res) => {
  const sessionId = (req.headers["mcp-session-id"] as string) || "";
  const transport = sessions[sessionId];
  if (!transport) return res.status(400).send("Invalid session");
  await transport.handleRequest(req, res);
});

app.delete("/mcp", async (req, res) => {
  const sessionId = (req.headers["mcp-session-id"] as string) || "";
  const transport = sessions[sessionId];
  if (!transport) return res.status(400).send("Invalid session");
  await transport.handleRequest(req, res);
});

app.get("/mcp/session", (_req, res) => {
  const ids = Object.keys(sessions);
  res.json({ session_id: ids[0] ?? null, sessions: ids });
});

// Health & assets
app.get("/health", (_req, res) => {
  res.json({
    status: "ok",
    version: "1.0.0",
    sessions: Object.keys(sessions).length,
  });
});
app.get("/health/tts", (_req, res) => {
  res.json({ provider: ttsProvider(), has_key: !!process.env.OPENAI_API_KEY });
});

app.get("/api/assets/:assetId", (req, res) => {
  try {
    const r = getRender(req.params.assetId);
    const audioPath = r?.audio_path;
    if (!audioPath) return res.status(404).json({ error: "Asset not found" });
    const abs = path.resolve(String(audioPath));
    if (!fs.existsSync(abs)) return res.status(404).json({ error: "File missing" });
    res.setHeader("Content-Type", mime.getType(abs) || "application/octet-stream");
    fs.createReadStream(abs).pipe(res);
  } catch (e: any) {
    res.status(500).json({ error: "Asset serving error", detail: String(e?.message || e) });
  }
});

app.listen(PORT, HOST, () => {
  console.log(`🎭 OffBook Server listening on http://${HOST}:${PORT}`);
});
