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

# ── Ollama (local LLM — required for AI Assist) ───────────────────────────────
echo ""
echo "--- Ollama (local LLM for AI Assist) ---"

# Determine which model to pull — read from .env if present, else default
OLLAMA_MODEL_TO_PULL="llama3.2"
if [ -f ".env" ]; then
  _env_model=$(grep -E '^OLLAMA_MODEL=' .env | head -1 | cut -d'=' -f2- | tr -d '"'"'" | xargs)
  if [ -n "$_env_model" ]; then
    OLLAMA_MODEL_TO_PULL="$_env_model"
  fi
fi

if command -v ollama &>/dev/null; then
  echo "✓ Ollama already installed: $(ollama --version 2>/dev/null || echo 'version unknown')"
else
  echo "Installing Ollama..."
  if [[ "$OSTYPE" == "darwin"* ]]; then
    if command -v brew &>/dev/null; then
      brew install --quiet ollama
    else
      echo "  Homebrew not found — using install script..."
      curl -fsSL https://ollama.com/install.sh | sh
    fi
  elif [[ "$OSTYPE" == "linux"* ]]; then
    curl -fsSL https://ollama.com/install.sh | sh
  else
    echo "  Unsupported OS for automatic Ollama install."
    echo "  Download manually from https://ollama.com/download"
    echo "  AI Assist will not be available until Ollama is installed."
    OLLAMA_SKIP=true
  fi
fi

if [ "${OLLAMA_SKIP:-false}" != "true" ] && command -v ollama &>/dev/null; then
  echo "✓ Ollama installed"

  # Start a temporary Ollama server to pull the model, then stop it
  echo "Pulling model '$OLLAMA_MODEL_TO_PULL' (this may take a few minutes on first run)..."
  # Start Ollama in background just long enough to pull
  OLLAMA_HOST=127.0.0.1:11434 ollama serve >/dev/null 2>&1 &
  _tmp_ollama_pid=$!
  # Wait for it to be ready (up to 15s)
  for i in {1..30}; do
    if curl -sf http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then break; fi
    sleep 0.5
  done
  ollama pull "$OLLAMA_MODEL_TO_PULL"
  kill "$_tmp_ollama_pid" 2>/dev/null || true
  echo "✓ Model '$OLLAMA_MODEL_TO_PULL' ready"
fi

echo ""
echo "Setup complete. Run ./start.sh to launch all services."
