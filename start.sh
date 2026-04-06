#!/usr/bin/env bash
# start.sh — Start all Sasquatch services locally
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

BACKEND_PORT=8000
FRONTEND_PORT=3000
LOG_DIR="$SCRIPT_DIR/logs"
REDIS_DATA_DIR="$SCRIPT_DIR/data/redis"
mkdir -p "$LOG_DIR" "$REDIS_DATA_DIR"

echo "=== Sasquatch — Starting Local Services ==="

# ── Redis ─────────────────────────────────────────────────────────────────────
if ! command -v redis-server &>/dev/null; then
  echo "ERROR: redis-server not found. Run ./setup.sh first."
  exit 1
fi

if redis-cli ping &>/dev/null 2>&1; then
  echo "✓ Redis already running"
else
  LC_ALL=en_US.UTF-8 LANG=en_US.UTF-8 redis-server "$SCRIPT_DIR/redis.conf" \
    --daemonize yes \
    --logfile "$LOG_DIR/redis.log" \
    --dir "$REDIS_DATA_DIR"
  # Wait for Redis to be ready
  for i in {1..10}; do
    if redis-cli ping &>/dev/null 2>&1; then break; fi
    sleep 0.5
  done
  echo "✓ Redis started"
fi

# ── Ollama ────────────────────────────────────────────────────────────────────
if command -v ollama &>/dev/null; then
  if curl -sf http://localhost:11434/api/tags >/dev/null 2>&1; then
    echo "✓ Ollama already running"
  else
    echo "Starting Ollama..."
    ollama serve > "$LOG_DIR/ollama.log" 2>&1 &
    echo $! > "$LOG_DIR/ollama.pid"
    # Wait for Ollama to be ready (up to 10s)
    for i in {1..20}; do
      if curl -sf http://localhost:11434/api/tags >/dev/null 2>&1; then break; fi
      sleep 0.5
    done
    echo "✓ Ollama started (PID $(cat $LOG_DIR/ollama.pid)) → logs/ollama.log"
  fi
else
  echo "  Ollama not installed — AI Assist will be unavailable (run ./setup.sh to install)"
fi

# ── Backend ───────────────────────────────────────────────────────────────────
if [ ! -d ".venv" ]; then
  echo "ERROR: Python venv not found. Run ./setup.sh first."
  exit 1
fi

# Kill any existing backend on this port
lsof -ti tcp:$BACKEND_PORT | xargs kill -9 2>/dev/null || true

echo "Starting backend on port $BACKEND_PORT..."
PORT=$BACKEND_PORT .venv/bin/uvicorn main:app \
  --app-dir sasquatch \
  --host 0.0.0.0 \
  --port $BACKEND_PORT \
  --log-level info \
  > "$LOG_DIR/backend.log" 2>&1 &
echo $! > "$LOG_DIR/backend.pid"
echo "✓ Backend started (PID $(cat $LOG_DIR/backend.pid)) → logs/backend.log"

# Wait for backend to be ready
for i in {1..20}; do
  if curl -s "http://localhost:$BACKEND_PORT/docs" &>/dev/null; then break; fi
  sleep 0.5
done

# ── Frontend ──────────────────────────────────────────────────────────────────
FRONTEND_DIR="$SCRIPT_DIR/sasquatch/frontend"
if [ ! -d "$FRONTEND_DIR/dist" ]; then
  echo "ERROR: Frontend not built. Run ./setup.sh first."
  exit 1
fi

# Kill any existing frontend on this port
lsof -ti tcp:$FRONTEND_PORT | xargs kill -9 2>/dev/null || true

echo "Starting frontend on port $FRONTEND_PORT..."
cd "$FRONTEND_DIR"
npx serve dist --listen $FRONTEND_PORT \
  > "$LOG_DIR/frontend.log" 2>&1 &
echo $! > "$LOG_DIR/frontend.pid"
cd "$SCRIPT_DIR"
echo "✓ Frontend started (PID $(cat $LOG_DIR/frontend.pid)) → logs/frontend.log"

echo ""
echo "┌─────────────────────────────────────────────┐"
echo "│  Frontend    http://localhost:$FRONTEND_PORT           │"
echo "│  Backend API http://localhost:$BACKEND_PORT           │"
echo "│  API docs    http://localhost:$BACKEND_PORT/docs      │"
echo "│  Ollama LLM  http://localhost:11434          │"
echo "└─────────────────────────────────────────────┘"
echo ""
echo "Run ./stop.sh to shut everything down."
