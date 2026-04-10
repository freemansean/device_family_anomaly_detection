#!/usr/bin/env bash
# setup.sh — One-time local setup for Sasquatch Client Anomaly Detection.
# Idempotent: safe to re-run. Run this once before using start.sh.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Sasquatch — Local Setup ==="

# ── Repo layout sanity check ──────────────────────────────────────────────────
# Fail fast with a clear message if the clone is incomplete. Previously this
# script just ran `cd sasquatch/frontend` and blew up with a raw bash error
# on machines where the frontend tree was missing.
REQUIRED_PATHS=(
  "requirements.txt"
  "sasquatch/main.py"
  "sasquatch/client_anomaly"
  "sasquatch/frontend/package.json"
  "sasquatch/frontend/vite.config.js"
  "redis.conf"
  ".env.example"
)
missing=()
for p in "${REQUIRED_PATHS[@]}"; do
  if [ ! -e "$p" ]; then
    missing+=("$p")
  fi
done
if [ ${#missing[@]} -gt 0 ]; then
  echo ""
  echo "ERROR: the following expected files/directories are missing from $SCRIPT_DIR:"
  for p in "${missing[@]}"; do
    echo "  - $p"
  done
  echo ""
  echo "This usually means the clone is incomplete or you are running setup.sh"
  echo "from the wrong directory. Re-clone the repo and run ./setup.sh from"
  echo "the 'unsupervised_anomaly' directory."
  exit 1
fi
echo "✓ Repo layout looks good"

# ── .env bootstrap ────────────────────────────────────────────────────────────
if [ ! -f ".env" ]; then
  cp .env.example .env
  echo "✓ Wrote .env from .env.example (edit it to add your Mist credentials)"
  ENV_WAS_CREATED=1
else
  echo "✓ .env already present — leaving it alone"
  ENV_WAS_CREATED=0
fi

# ── Redis ─────────────────────────────────────────────────────────────────────
if ! command -v redis-server &>/dev/null; then
  echo ""
  echo "ERROR: Redis is not installed. Install it first:"
  echo ""
  echo "  Option A (Homebrew — recommended on macOS):"
  echo "    /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
  echo "    brew install redis"
  echo ""
  echo "  Option B (Docker):"
  echo "    docker run -d --name redis -p 6379:6379 redis:7-alpine"
  echo ""
  exit 1
fi
echo "✓ Redis found: $(redis-server --version | awk '{print $1, $2, $3}')"

# ── Python ────────────────────────────────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
  echo "ERROR: python3 not found. Install Python 3.10 or newer and re-run ./setup.sh."
  exit 1
fi

if [ ! -d ".venv" ]; then
  echo "Creating Python virtual environment (.venv)..."
  python3 -m venv .venv
fi
echo "✓ Python venv ready"

echo "Installing Python dependencies..."
.venv/bin/pip install --quiet --upgrade pip
.venv/bin/pip install --quiet -r requirements.txt
echo "✓ Python dependencies installed"

# ── Node / npm ────────────────────────────────────────────────────────────────
if ! command -v npm &>/dev/null; then
  echo "ERROR: npm not found. Install Node.js 18 or newer and re-run ./setup.sh."
  exit 1
fi

echo "Installing npm dependencies..."
(cd sasquatch/frontend && npm install --silent)
echo "Building frontend..."
(cd sasquatch/frontend && npm run build >/dev/null)
if [ ! -d "sasquatch/frontend/dist" ]; then
  echo "ERROR: frontend build completed but sasquatch/frontend/dist was not created."
  exit 1
fi
echo "✓ Frontend built → sasquatch/frontend/dist/"

# ── SQLite ────────────────────────────────────────────────────────────────────
# The database file auto-creates on first backend boot via db.get_connection().
# Nothing to do here — just note where it lives for the operator.
echo "✓ SQLite DB will auto-create at sasquatch/client_anomaly/data/sasquatch.db on first run"

# ── OUI database ──────────────────────────────────────────────────────────────
# oui_lookup.py resolves MAC → manufacturer from a local copy of the IEEE
# MA-L registry (data/oui.json, ~1.3 MB). The file is gitignored by the
# broader `data/` rule, so a fresh clone has to download it once.
OUI_PATH="sasquatch/client_anomaly/data/oui.json"
if [ -f "$OUI_PATH" ]; then
  echo "✓ OUI database already present at $OUI_PATH"
else
  echo "Downloading IEEE OUI database (one-time, ~1.3 MB)..."
  # `sasquatch/` has no __init__.py, so we cd in and import client_anomaly as
  # the top-level package — same trick `start.sh` uses via uvicorn --app-dir.
  if (cd sasquatch && ../.venv/bin/python -m client_anomaly.oui_lookup); then
    echo "✓ OUI database built → $OUI_PATH"
  else
    echo "WARNING: OUI download failed. The app will still run, but MAC"
    echo "         manufacturer lookups will return 'Unknown' until you rerun"
    echo "         './setup.sh' with internet access."
  fi
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo "Setup complete."
if [ "$ENV_WAS_CREATED" -eq 1 ]; then
  echo ""
  echo "NEXT STEP — edit .env to fill in your Mist credentials:"
  echo "  MIST_API_TOKEN=..."
  echo "  MIST_ORG_ID=..."
  echo "  MIST_CLOUD_HOST=api.mist.com   # or api.gc1/gc2/gc4/eu.mist.com"
  echo ""
  echo "Without those, the dashboard will load but 'Collect Events' will fail —"
  echo "there is no sample-data / demo mode."
fi
echo ""
echo "Run ./start.sh to launch all services."
