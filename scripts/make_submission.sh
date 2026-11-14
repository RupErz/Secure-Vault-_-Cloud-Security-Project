#!/usr/bin/env bash
# Build the course-submission ZIP:  ./scripts/make_submission.sh  ->  dist/securevault-submission-<date>.zip
#
# NEVER included: .env (and .env.*, except .env.example), secrets/, nginx/certs/, private keys,
# stored/encrypted file data, databases, __pycache__/.pyc, node_modules, virtualenvs, .git,
# previously built ZIPs. After zipping, the archive is re-scanned: it is deleted and the script
# fails if any excluded path or any real secret VALUE from your local .env / master key is found.
# Only needs python3 (present on Ubuntu); does not need the `zip` command.
set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p dist
OUT="dist/securevault-submission-$(date +%Y%m%d-%H%M%S).zip"
export OUT

python3 - <<'PY'
import fnmatch, os, re, sys, zipfile

OUT = os.environ["OUT"]
ROOT = "securevault"            # top-level folder inside the zip

# Directory names excluded wherever they appear
EXCLUDE_DIRS = {"__pycache__", ".git", ".venv", "venv", "node_modules", ".idea", ".vscode",
                "secrets", "storage", "storage_dev", "staticfiles", "dist", ".pytest_cache"}
# Exact relative directory paths excluded
EXCLUDE_PATHS = {"nginx/certs", "app/tailwind/dist", "app/vault/static/vault/fonts"}
# File name patterns excluded (matched on the base name)
EXCLUDE_FILES = [".env", ".env.*", "*.pyc", "*.pyo", "*.enc", "*.part", "*.key", "*.pem", "*.crt",
                 "*.p12", "master_key*", "db.sqlite3", "*.sqlite3", "*.zip", ".DS_Store", "tailwind.css"]
KEEP_FILES = {".env.example"}   # explicit exception to ".env.*"


def excluded_dir(rel):
    return os.path.basename(rel) in EXCLUDE_DIRS or rel in EXCLUDE_PATHS


def excluded_file(rel):
    name = os.path.basename(rel)
    if name in KEEP_FILES:
        return False
    return any(fnmatch.fnmatch(name, pat) for pat in EXCLUDE_FILES)


def violation(rel):
    """Used for the post-build audit of archive member names."""
    parts = rel.split("/")
    if any(p in EXCLUDE_DIRS for p in parts[:-1]):
        return True
    if any(rel.startswith(p + "/") for p in EXCLUDE_PATHS):
        return True
    return excluded_file(rel)


included = []
for dirpath, dirnames, filenames in os.walk("."):
    rel_dir = os.path.relpath(dirpath, ".").replace(os.sep, "/")
    rel_dir = "" if rel_dir == "." else rel_dir
    dirnames[:] = sorted(d for d in dirnames if not excluded_dir(f"{rel_dir}/{d}".lstrip("/")))
    for f in sorted(filenames):
        rel = f"{rel_dir}/{f}".lstrip("/")
        if not excluded_file(rel) and not os.path.islink(rel):
            included.append(rel)

with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as zf:
    for rel in included:
        zf.write(rel, f"{ROOT}/{rel}")      # keeps file mode (e.g. executable scripts)

# ---------------------------------------------------------------- audit the finished archive
problems = []
with zipfile.ZipFile(OUT) as zf:
    names = [n[len(ROOT) + 1:] for n in zf.namelist()]
    problems += [f"forbidden path in zip: {n}" for n in names if violation(n)]

    # Secret VALUES that exist locally must not appear in any member.
    needles = {}
    if os.path.exists("secrets/master_key.txt"):
        needles["master key"] = open("secrets/master_key.txt").read().strip()
    if os.path.exists(".env"):
        for line in open(".env"):
            m = re.match(r"(DJANGO_SECRET_KEY|POSTGRES_PASSWORD)=(.+)", line.strip())
            if m and m.group(2) not in ("change-me",):
                needles[m.group(1)] = m.group(2)
    for n in zf.namelist():
        data = zf.read(n)
        for label, value in needles.items():
            if len(value) >= 8 and value.encode() in data:
                problems.append(f"{label} value found inside {n}")
    if "README.md" not in names or ".env.example" not in names or "docker-compose.yml" not in names:
        problems.append("expected files missing (README.md / .env.example / docker-compose.yml)")

if problems:
    os.remove(OUT)
    print("SUBMISSION BLOCKED - archive deleted:", *problems, sep="\n  ", file=sys.stderr)
    sys.exit(1)

print(f"Created {OUT}: {len(included)} files, {os.path.getsize(OUT) / 1024:.0f} KiB")
print("Verified: no .env / secrets / certs / storage data / __pycache__ and no secret values inside.")
PY

echo
echo "Contents (top level):"
python3 -c "
import zipfile, sys
z = zipfile.ZipFile('$OUT')
print('\n'.join(sorted(n for n in z.namelist())))
"
