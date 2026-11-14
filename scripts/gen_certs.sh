#!/usr/bin/env bash
# Generate a self-signed TLS certificate for Nginx.
#   usage: ./scripts/gen_certs.sh [hostname-or-ip ...]
# Extra args become Subject Alternative Names (e.g. the VM's IP).
set -euo pipefail
cd "$(dirname "$0")/.."

OUT=nginx/certs
mkdir -p "$OUT"

SANS="DNS:localhost,IP:127.0.0.1"
for h in "$@"; do
  if [[ "$h" =~ ^[0-9.]+$ ]]; then SANS+=",IP:$h"; else SANS+=",DNS:$h"; fi
done

openssl req -x509 -nodes -newkey rsa:4096 -sha256 -days 365 \
  -keyout "$OUT/server.key" -out "$OUT/server.crt" \
  -subj "/C=VN/O=SecureVault Course Project/CN=localhost" \
  -addext "subjectAltName=$SANS" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth"

# The nginx container runs its master process as root, which reads the key.
chmod 600 "$OUT/server.key"
chmod 644 "$OUT/server.crt"
echo "Created $OUT/server.crt and $OUT/server.key (SAN: $SANS)"
