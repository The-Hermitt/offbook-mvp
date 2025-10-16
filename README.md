# OffBook MVP

Upload a script PDF, select a role, assign AI voices to partners, and render a “reader” track (AI reads partner lines; you perform yours). Works via REST debug routes and an HTTP MCP endpoint for the ChatGPT Apps SDK.

## Quick Links
- Health: `/health`, `/health/tts`
- Debug flow base: `/debug/*`
- MCP endpoint: `/mcp`
- Mini Player: `/app.html`

## Environment (Render)
Required:
- `NODE_VERSION=20`
- `OPENAI_API_KEY=sk-...` (for real TTS)
Optional:
- `SHARED_SECRET=super-dev-secret` (guards `/mcp` and `/debug/*`)

Build/Start (Render Settings or render.yaml):
- **Build Command:** `npm install`
- **Start Command:** `npm start`

## End-to-End (curl)
> Add `-H "X-Shared-Secret: super-dev-secret"` to each call if you set a shared secret.

```bash
BASE="https://<your-service>.onrender.com"

# 1) Upload
curl -s -X POST "$BASE/debug/upload_script" \
  -H "Content-Type: application/json" \
  -d '{"pdf_url":"https://www.w3.org/WAI/ER/tests/xhtml/testfiles/resources/pdf/dummy.pdf","title":"Test Script"}'

# 2) List scenes
curl -s "$BASE/debug/scenes?script_id=SCRIPT_ID"

# 3) Set voice
curl -s -X POST "$BASE/debug/set_voice" \
  -H "Content-Type: application/json" \
  -d '{"script_id":"SCRIPT_ID","voice_map":{"UNKNOWN":"alloy"}}'

# 4) Render
curl -s -X POST "$BASE/debug/render" \
  -H "Content-Type: application/json" \
  -d '{"script_id":"SCRIPT_ID","scene_id":"SCENE_ID","role":"UNKNOWN","pace":"normal"}'

# 5) Poll
curl -s "$BASE/debug/render_status?render_id=RENDER_ID"
