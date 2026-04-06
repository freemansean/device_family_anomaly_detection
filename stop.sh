#!/usr/bin/env bash
# stop.sh — Stop all Sasquatch local services
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$SCRIPT_DIR/logs"

echo "=== Sasquatch — Stopping Local Services ==="

stop_pid() {
  local name=$1
  local pidfile="$LOG_DIR/$2.pid"
  if [ -f "$pidfile" ]; then
    local pid
    pid=$(cat "$pidfile")
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid"
      echo "✓ $name stopped (PID $pid)"
    else
      echo "  $name was not running"
    fi
    rm -f "$pidfile"
  fi
}

stop_pid "Frontend" "frontend"
stop_pid "Backend" "backend"
stop_pid "Ollama" "ollama"

# Leave Redis running — it's a shared service.
# To stop Redis: brew services stop redis  OR  redis-cli shutdown
echo "  Redis left running (stop manually: brew services stop redis)"
echo "Done."
