#!/usr/bin/env bash
# Safe, non-exiting smoke test for OffBook debug harness.

set +e  # do NOT exit on errors

# --- Config (defaults you can override via env)
BASE="${BASE:-https://offbook-mvp.onrender.com}"
SECRET="${SECRET:-super-dev-secret}"  # default to the secret we use

# --- Cookie jar for session continuity across requests
JAR="$(pwd)/.ob_cookiejar"
cleanup() { rm -f "$JAR"; }
trap cleanup EXIT

echo "== BASE: $BASE"
echo "== using X-Shared-Secret header: $( [ -n "$SECRET" ] && echo yes || echo no )"

HDRS=(-H "Content-Type: application/json")
[ -n "$SECRET" ] && HDRS+=(-H "X-Shared-Secret: $SECRET")

# 1) Health
echo
echo "== GET /health"
curl -s -i -c "$JAR" -b "$JAR" "$BASE/health" | sed -n '1,12p'

echo
echo "== GET /health/tts"
curl -s -i -c "$JAR" -b "$JAR" "$BASE/health/tts" | sed -n '1,12p'

# 2) Upload script text
echo
echo "== POST /debug/upload_script_text"
UPLOAD=$(curl -s -i -c "$JAR" -b "$JAR" -X POST "$BASE/debug/upload_script_text" "${HDRS[@]}" \
  -d '{"title":"Sides","text":"JANE: Hi.\nGABE: Hey.\nJANE: Ready?"}')
echo "$UPLOAD" | sed -n '1,25p'
SID=$(echo "$UPLOAD" | sed -n 's/.*"script_id":"\([^"]*\)".*/\1/p')
if [ -z "$SID" ]; then
  echo "!! Could not extract script_id (likely secret mismatch or route not mounted)."
  exit 0
fi
echo "script_id: $SID"

# 3) Fetch scenes
echo
echo "== GET /debug/scenes?script_id=$SID"
SCENES=$(curl -s -i -c "$JAR" -b "$JAR" "$BASE/debug/scenes?script_id=$SID" "${HDRS[@]}")
echo "$SCENES" | sed -n '1,25p'
SCID=$(echo "$SCENES" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
if [ -z "$SCID" ]; then
  echo "!! Could not extract scene id."
  exit 0
fi
echo "scene_id: $SCID"

# 4) Set a voice
echo
echo "== POST /debug/set_voice"
curl -s -i -c "$JAR" -b "$JAR" -X POST "$BASE/debug/set_voice" "${HDRS[@]}" \
  -d "{\"script_id\":\"$SID\",\"voice_map\":{\"GABE\":\"alloy\"}}" | sed -n '1,20p'

# 5) Render reader track
echo
echo "== POST /debug/render"
RENDER=$(curl -s -i -c "$JAR" -b "$JAR" -X POST "$BASE/debug/render" "${HDRS[@]}" \
  -d "{\"script_id\":\"$SID\",\"scene_id\":\"$SCID\",\"role\":\"JANE\",\"pace\":\"normal\"}")
echo "$RENDER" | sed -n '1,25p'
RID=$(echo "$RENDER" | sed -n 's/.*"render_id":"\([^"]*\)".*/\1/p')
if [ -z "$RID" ]; then
  echo "!! Could not extract render_id."
  exit 0
fi
echo "render_id: $RID"

# 6) Check status + asset URL
echo
echo "== GET /debug/render_status?render_id=$RID"
STATUS=$(curl -s -i -c "$JAR" -b "$JAR" "$BASE/debug/render_status?render_id=$RID" "${HDRS[@]}")
echo "$STATUS" | sed -n '1,40p'

echo
echo "Asset URL:"
echo "$BASE/api/assets/$RID"
echo
echo "Open that URL in a browser to confirm the MP3 streams."
