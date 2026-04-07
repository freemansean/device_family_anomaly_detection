#!/usr/bin/env bash
# setup.sh — One-time local setup for Sasquatch Client Anomaly Detection
# Run this once before using start.sh
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Sasquatch — Local Setup ==="

# ── Redis ────────────────────────────────────────────────────────────────────
if ! command -v redis-server &>/dev/null; then
  echo ""
  echo "Redis is not installed. Install it first:"
  echo ""
  echo "  Option A (Homebrew — recommended):"
  echo "    /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
  echo "    brew install redis"
  echo ""
  echo "  Option B (Docker):"
  echo "    docker run -d --name redis -p 6379:6379 redis:7-alpine"
  echo ""
  exit 1
fi
echo "✓ Redis found: $(redis-server --version)"

# ── Python venv ───────────────────────────────────────────────────────────────
if [ ! -d ".venv" ]; then
  echo "Creating Python virtual environment..."
  python3 -m venv .venv
fi
echo "✓ Python venv ready"

echo "Installing Python dependencies..."
.venv/bin/pip install --quiet --upgrade pip
.venv/bin/pip install --quiet -r requirements.txt
echo "✓ Python dependencies installed"

# ── Frontend ──────────────────────────────────────────────────────────────────
cd sasquatch/frontend
echo "Installing npm dependencies..."
npm install --silent
echo "Building frontend..."
npm run build
echo "✓ Frontend built → sasquatch/frontend/dist/"
cd "$SCRIPT_DIR"

echo ""
echo "Setup complete. Run ./start.sh to launch all services."
