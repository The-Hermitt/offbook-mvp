# 🤖 OffBook SDK — AGENTS.md
> Context guide for Codex, GPT, and other AI agents collaborating on this project.

---

## 🧩 Project Overview
OffBook SDK is a **script rehearsal toolkit** where actors can:
- Import scripts (text or PDF)
- Assign AI voices to partner roles
- Rehearse scenes with responsive cueing
- Record takes using **camera + mic**
- Review takes in a gallery

The system also exposes **MCP tools** for GPT integration in the SDK Store.

---

## 🧱 Stack Summary
- **Backend:** Node + TypeScript + Express
- **Database:** SQLite (via `better-sqlite3`)
- **Frontend:** `/public/app-tabs.html` (mobile-first web app)
- **AI Services:**
  - **TTS:** OpenAI voices
  - **STT:** Whisper (live-ish cue detection)
- **Host:** Render Free (ephemeral disk)
- **Storage:** Local → planned Cloudflare R2
- **MCP Endpoints:** `upload_script`, `list_scenes`, `set_voice`, `render_reader`, `render_status`

---

## 🧠 Collaboration Workflow (Codex → GPT → User)

| Stage | Role | Responsibility |
|-------|------|----------------|
| **1. Codex** | Drafts long or repetitive code, generates boilerplate, refactors modules. |
| **2. GPT** | Reviews Codex output, ensures correctness, safety, and full-file replacement. |
| **3. User** | Copies finalized code into GitHub Codespaces and pushes to `main`. |

Always deliver **complete file replacements** (no patches).  
Commit format:
```bash
git add -A && git commit -m "feat: <summary>" && git push origin main
