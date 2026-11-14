#!/usr/bin/env bash
# DEMO HELPER: show that what is stored on the private volume is ciphertext.
#   ./scripts/show_ciphertext.sh               -> list stored files
#   ./scripts/show_ciphertext.sh <file_id>     -> hex dump of the first 256 bytes + stats
#   BYTES=1024 ./scripts/show_ciphertext.sh <file_id>
set -euo pipefail
cd "$(dirname "$0")/.."

DIR=/data/files
BYTES="${BYTES:-256}"

if [[ $# -eq 0 ]]; then
  docker compose exec django-web ls -la "$DIR"
  exit 0
fi

ID="$1"
[[ "$ID" =~ ^[0-9a-fA-F-]{36}$ ]] || { echo "file_id must be a UUID"; exit 1; }

echo "== $DIR/$ID.enc =="
docker compose exec -T django-web sh -c "
  ls -l '$DIR/$ID.enc'
  echo
  echo '--- first $BYTES bytes (od -A x -t x1z) ---'
  od -A x -t x1z -N $BYTES '$DIR/$ID.enc'
  echo
  echo '--- readable strings (>=6 chars) in the whole file ---'
  python - <<'PY'
import re
data = open('$DIR/$ID.enc','rb').read()
hits = re.findall(rb'[ -~]{6,}', data)
print(len(hits), 'printable runs found' if hits else 'none: looks like random data')
print(hits[:5])
PY
"
