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

## Collaboration Contract

**Who does what**
- **Codex (cloud/IDE/GitHub)**: Works in branches and pull requests. It may push granular commits, refactor multiple files, and open PRs for review. It should NEVER force-push to `main`.
- **OffBook-Builder GPT (chat)**: When the user asks for code in chat, always return **complete file replacements** (no diffs). Include exact file paths and copy–pasteable commit/deploy commands.
- **User**: Merges PRs or pastes full files from chat into Codespaces, then pushes.

**Repo hygiene for Codex**
- Branch naming: `feature/<slug>` or `fix/<slug>`
- Open a PR with:
  - Clear title and summary
  - Checklist asserting:
    - [ ] Does not break **camera+mic** recording in Record tab
    - [ ] Preserves **responsive cueing** (target ≤ 250 ms)
    - [ ] Parser still skips INT./EXT., ALL-CAPS action, parentheticals
    - [ ] No secrets committed; Render env untouched
- If code review is enabled, mention `@codex review` in PR description.

**When to use which format**
- **Codex** → PRs and diffs are preferred (speed + traceability).
- **Chat (this thread)** → return entire files so the user can paste once and push.
