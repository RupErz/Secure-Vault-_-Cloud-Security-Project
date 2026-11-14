# ---- Stage 1: build the static Tailwind stylesheet (replaces the CDN) -------------------
# Node exists only in this throw-away stage; the final image contains just the CSS file.
FROM node:22-alpine AS css
WORKDIR /build/tailwind
COPY tailwind/package.json tailwind/package-lock.json ./
RUN npm ci --ignore-scripts
COPY tailwind/tailwind.config.js tailwind/input.css tailwind/copy-fonts.js ./
# Tailwind scans templates + JS for class names (paths match tailwind.config.js)
COPY vault/templates /build/vault/templates
COPY vault/static/vault /build/vault/static/vault
RUN npm run build

# ---- Stage 2: the application image -------------------------------------------------------
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# Non-root user. /data/files is created and chowned BEFORE the volume is mounted,
# so the named volume inherits this ownership on first use.
RUN useradd --uid 1000 --create-home --shell /usr/sbin/nologin app \
 && mkdir -p /data/files /app/staticfiles \
 && chown -R app:app /data /app

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY --chown=app:app . .
RUN chmod +x entrypoint.sh
COPY --from=css --chown=app:app /build/tailwind/dist/tailwind.css vault/static/vault/tailwind.css
COPY --from=css --chown=app:app /build/tailwind/dist/fonts vault/static/vault/fonts

USER app
# collectstatic needs no DB or real secrets; this key is build-time only.
RUN DJANGO_SECRET_KEY=build-only USE_SQLITE=1 python manage.py collectstatic --noinput

EXPOSE 8000
ENTRYPOINT ["./entrypoint.sh"]
