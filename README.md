# OffBook MCP Server (Phase A)

An MCP server for screenplay rehearsal tools. Upload scripts, parse scenes, configure character voices, and generate reader audio tracks.

## Features

- **Upload Script**: Parse screenplay PDFs from HTTPS URLs
- **Parse Sides**: Extract scenes and character lists
- **Set Voice**: Configure TTS voice assignments per character
- **Render Reader**: Generate audio of partner lines (excluding your role)

## Quick Start

```bash
# Install dependencies
npm install

# Build the project
npm run build

# Set up environment
cp .env.example .env

# Initialize database (after building)
npm run db:reset

# Start server
npm run dev
```

Server runs at `http://localhost:3000`

## Testing with MCP Inspector

```bash
npx @modelcontextprotocol/inspector http://localhost:3000/mcp
```

### Example Flow

1. **Upload a script**:
   ```json
   {
     "pdf_url": "https://example.com/screenplay.pdf",
     "title": "My Screenplay"
   }
   ```
   Returns: `{ script_id, characters[], scenes_found }`

2. **Parse sides**:
   ```json
   {
     "script_id": "abc123"
   }
   ```
   Returns: `{ script_id, title, scenes[], characters[] }`

3. **Set voices**:
   ```json
   {
     "script_id": "abc123",
     "voice_map": {
       "HAMLET": "alloy",
       "OPHELIA": "nova"
     }
   }
   ```
   Returns: `{ ok: true }`

4. **Render reader**:
   ```json
   {
     "script_id": "abc123",
     "scene_id": "scene456",
     "role": "HAMLET",
     "pace": "normal"
   }
   ```
   Returns: `{ render_id, status: "complete", download_url }`

## API Endpoints

- `POST /mcp` - MCP messages
- `GET /mcp?sessionId=...` - SSE stream
- `DELETE /mcp?sessionId=...` - Close session
- `GET /health` - Health check
- `GET /api/assets/:assetId` - Download audio

## Environment Variables

```bash
PORT=3000
DATABASE_URL=./offbook.db
APP_URL=http://localhost:3000
OPENAI_API_KEY=          # Optional: enables real TTS (Phase B)
```

## PDF Requirements

- **HTTPS only**: URLs must use HTTPS protocol
- **Size limit**: Maximum 30MB
- **Format**: Standard screenplay format with scene headings (INT./EXT.) recommended

## Parse Behavior

The parser uses screenplay heuristics:

- **Scene headings**: Lines starting with INT./EXT./SCENE
- **Character names**: All-caps lines (<30 chars)
- **Dialogue**: Text following a character name
- **Auto-split**: Scenes auto-split after ~80 dialogue lines if no headings found

Parse warnings are returned when low-confidence patterns are detected.

## Voice Configuration

Supported voices: `alloy`, `verse`, `nova`, `aria`

Unknown voices default to `alloy`. Character names are normalized (uppercase, stripped of (O.S.), (V.O.), (CONT'D)).

## Audio Generation

**Phase A**: Generates stub audio (silent MP3) unless `OPENAI_API_KEY` is set.

**Phase B** (future): Real TTS with OpenAI, concatenated dialogue with pauses.

## Database Schema

- **users**: User accounts
- **scripts**: Uploaded scripts
- **scenes**: Parsed scenes with dialogue
- **voice_configs**: Voice assignments per script
- **renders**: Generated audio tracks

## Development

```bash
npm run dev        # Watch mode
npm run build      # Compile TypeScript
npm run start      # Run compiled JS
npm run db:reset   # Reinitialize database
```

## Roadmap

- **Phase B**: Real TTS with OpenAI, voice selection, pace control
- **Phase C**: OAuth, PWA capture handoff, recording sync

## Architecture

```
src/
  server.ts           # Express + SSE transport
  mcp-server.ts       # MCP tool registration
  lib/
    db.ts             # SQLite setup
    pdf.ts            # PDF download & parse
    tts.ts            # Audio generation (stub)
    auth.ts           # Token validation (stub)
    normalize.ts      # Character name normalization
  tools/
    upload-script.ts  # Tool implementations
    parse-sides.ts
    set-voice.ts
    render-reader.ts
```

## License

Private
