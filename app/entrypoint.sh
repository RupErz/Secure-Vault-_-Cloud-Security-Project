#!/bin/sh
set -e

# Fail fast if the master key is missing/invalid (rather than at first upload).
python manage.py shell -c "from vault.crypto import get_master_key; get_master_key(); print('master key OK')"

python manage.py migrate --noinput

# 2 processes x 8 threads (a slow 1 GB transfer occupies one thread for its whole life).
# --timeout is the worker *heartbeat* limit: with gthread the heartbeat comes from the main
# thread, so a long request does NOT trip it; 3600 only guards against a truly hung worker.
# It matches nginx's 3600 s idle limits on /files/upload/ and the download route.
exec gunicorn config.wsgi:application \
  --bind 0.0.0.0:8000 \
  --worker-class gthread --workers 2 --threads 8 \
  --timeout 3600 --graceful-timeout 30 --keep-alive 5 \
  --worker-tmp-dir /tmp \
  --access-logfile - --error-logfile -
