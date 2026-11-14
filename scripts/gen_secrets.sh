#!/usr/bin/env bash
# Create (once) the AES-256 master key (Docker secret) and a .env with random secrets.
#   usage: ./scripts/gen_secrets.sh [hostname-or-ip ...]
# Existing files are never overwritten (overwriting the master key would make every
# stored file permanently undecryptable).
set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p secrets
chmod 700 secrets   # host dir is private; the FILE is world-readable so the
                    # non-root container user can read the bind-mounted secret.

if [[ -e secrets/master_key.txt ]]; then
  echo "secrets/master_key.txt already exists - keeping it."
else
  umask 077
  # 32 random bytes, base64 encoded = 256-bit key
  openssl rand -base64 32 > secrets/master_key.txt
  chmod 644 secrets/master_key.txt
  echo "Created secrets/master_key.txt (BACK THIS UP - without it all files are lost)."
fi

if [[ -e .env ]]; then
  echo ".env already exists - keeping it."
else
  HOSTS="localhost,127.0.0.1"
  ORIGINS="https://localhost"
  for h in "$@"; do HOSTS+=",$h"; ORIGINS+=",https://$h"; done
  umask 077
  sed \
    -e "s|^DJANGO_SECRET_KEY=.*|DJANGO_SECRET_KEY=$(openssl rand -base64 48 | tr -d '\n=+/')|" \
    -e "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$(openssl rand -base64 24 | tr -d '\n=+/')|" \
    -e "s|^DJANGO_ALLOWED_HOSTS=.*|DJANGO_ALLOWED_HOSTS=$HOSTS|" \
    -e "s|^DJANGO_CSRF_TRUSTED_ORIGINS=.*|DJANGO_CSRF_TRUSTED_ORIGINS=$ORIGINS|" \
    .env.example > .env
  echo "Created .env with random DJANGO_SECRET_KEY and POSTGRES_PASSWORD."
fi
