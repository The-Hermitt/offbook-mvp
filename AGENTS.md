# 🤖 OffBook SDK — AGENTS.md
> Operating rules for Codex, Builder GPT, and humans working on **offbook-mvp**.

---

## 0) What we’re building (unchanged)
OffBook is a script rehearsal toolkit where actors can:
- Import scripts (paste text or PDF; image-PDFs auto-OCR on the server)
- Assign AI voices to partner roles
- Rehearse with **responsive cueing**
- **Record (camera + mic mandatory)** with a 3-2-1 countdown
- Review takes in a gallery

---

## 1) Roles
- **Owner (@The-Hermitt)**: final say on UI, merges UI changes, sets priorities.
- **Codex (cloud / IDE / phone)**: main implementer; opens PRs; must obey guardrails.
- **Builder GPT (this chat)**: provides **complete file replacements** and exact commands; can author docs/tests; never pushes.

---

## 2) Non-negotiables (guardrails)
- **Protected UI file:** `/public/app-tabs.html`
  - May **not** be changed by Codex unless the task is explicitly a UI change.
  - Changes require owner approval via CODEOWNERS.
- **Canonical UI contract**
  - Bottom tabs only: **Import, Assign, Rehearse, Record, Gallery, Settings** — one visible at a time.
  - **Import / Upload PDF** pane: **Title (top)** then **PDF (below)** — stacked vertically, no overflow/popping out of the card.
- **Shared-secret gate for debug API**
  - Header: `X-Shared-Secret: 1976`
  - UI is opened with: `/app-tabs.html?secret=1976`
  - Missing/incorrect secret → 404 by design.

---

## 3) Secrets & environment
- **GitHub Actions secrets**
  - `OFFBOOK_BASE_URL = https://offbook-mvp.onrender.com`
  - `OFFBOOK_SHARED_SECRET = 1976`
- **Render env**
  - `SHARED_SECRET = 1976`
  - *(optional)* `BASE_URL = https://offbook-mvp.onrender.com`

---

## 4) Branching, PRs, and auto-merge
- **Branch names (Codex):** `codex/<task-name>` (e.g., `codex/fix-import-404`)
- **Open a PR to `main`** with:
  - Title: `feat|fix|chore: <task>`
  - Label **`ready`** only when smoke passes locally (see §6)
  - If `/public/app-tabs.html` changed: also add **`ui-approval-required`** and @-mention **@The-Hermitt**
- **Ruleset (main):**
  - Requires PRs + 1 approval
  - Status check: **OffBook Smoke (Render)**
  - Blocks force pushes
- **Auto-merge:**
  - If **no protected UI change** + label **`ready`** + CI green → squash-merge automatically.
  - If UI changed → waits for owner approval (auto-merge off).

---

## 5) Server & routes Codex can rely on
- **Entry:** `src/server.ts` imports `initHttpRoutes(app)` from `src/http-routes.ts`.
- **Health:** `GET /health`, `GET /health/tts`
- **Debug API (requires secret):**
  - `POST /debug/upload_script_text` `{ title, text }` → `{ script_id, scene_count }`
  - `POST /debug/upload_script_upload` (multipart: `title`, `pdf`) → OCR fallback if needed
  - `GET /debug/scenes?script_id=...`
  - `POST /debug/set_voice`
  - `POST /debug/render` → returns `{ render_id, status }` (stub creates silent mp3)
  - `GET /debug/render_status?render_id=...`
  - `GET /api/assets/:render_id` → MP3 stream
- **OCR pipeline (server-side only, user never sees it):**
  - `pdf-parse` → if weak text → rasterize via `pdfjs-dist` + `canvas` → `tesseract.js`
  - Important: **create tesseract worker without `logger` option** (avoids Node DataClone error).

---

## 6) Smoke testing
- **CI:** `.github/workflows/smoke.yml` (OffBook Smoke (Render))
  - Hits `/health`, `/health/tts`
  - Exercises `/debug/*` with the secret
  - Asserts tab labels exist in `/public/app-tabs.html`
  - Labels UI-touching PRs and disables auto-merge for them
- **Local quick smoke (Codex/dev):**
  ```bash
  BASE="$OFFBOOK_BASE_URL" SECRET="$OFFBOOK_SHARED_SECRET" scripts/smoke-debug.sh
