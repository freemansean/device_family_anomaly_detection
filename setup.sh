#!/usr/bin/env bash
# setup.sh — One-time local setup for Sasquatch Client Anomaly Detection.
# Idempotent: safe to re-run. Run this once before using start.sh.
#
# On Ubuntu, missing dependencies (Python 3.10+, Node.js 18+, Redis 7+) are
# installed automatically via apt. On other systems, clear instructions are
# printed and the script exits.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Sasquatch — Local Setup ==="

# ── OS detection ──────────────────────────────────────────────────────────────
# Detect whether we're on Ubuntu so we can decide whether to auto-install
# missing dependencies or just print instructions and exit.
IS_UBUNTU=0
if [ -f /etc/os-release ]; then
  # Source the OS info file — gives us $ID (e.g. "ubuntu") and $VERSION_ID
  # shellcheck source=/dev/null
  . /etc/os-release
  if [ "${ID:-}" = "ubuntu" ]; then
    IS_UBUNTU=1
  fi
fi

# ── Helper: require sudo for apt operations ───────────────────────────────────
# Checks that sudo is available before attempting any apt-get calls.
# Prints a clear error and exits if sudo isn't usable, rather than failing
# mid-install with a cryptic permission-denied message.
ensure_sudo() {
  if ! command -v sudo &>/dev/null; then
    echo "ERROR: sudo is required to install packages but was not found."
    echo "       Run this script as root, or install sudo first."
    exit 1
  fi
  # Validate current sudo credentials (no-op if already valid).
  # This surfaces a password prompt once up front rather than mid-install.
  sudo -v || { echo "ERROR: Could not obtain sudo privileges."; exit 1; }
}

# ── Helper: compare version strings ──────────────────────────────────────────
# Usage: version_ge <installed_version> <minimum_version>
# Returns 0 (true) if installed >= minimum, 1 (false) otherwise.
# Works by sorting both strings with sort -V and checking which comes first.
version_ge() {
  # printf both versions, one per line, then pick the "lowest" with sort -V.
  # If the lowest equals $2 (our minimum), then $1 >= $2.
  local lowest
  lowest=$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)
  [ "$lowest" = "$2" ]
}

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

# ══════════════════════════════════════════════════════════════════════════════
# DEPENDENCY: Redis 7+
# ══════════════════════════════════════════════════════════════════════════════
# We need Redis ≥ 7.0. The check below reads the version from redis-server
# itself rather than relying on the package manager, so it works regardless of
# how Redis was installed (apt, Homebrew, manual build, Docker sidecar, etc.).
install_redis_ubuntu() {
  echo "  → Installing Redis via apt..."
  ensure_sudo

  # The default Ubuntu 22.04 repos ship Redis 6.x. To get Redis 7+ we add the
  # official Redis apt repository which tracks the latest stable release.
  echo "  → Adding official Redis apt repository..."
  sudo apt-get update -qq
  sudo apt-get install -y -qq curl gnupg lsb-release

  # Import the Redis signing key so apt trusts packages from their repo.
  curl -fsSL https://packages.redis.io/gpg \
    | sudo gpg --dearmor -o /usr/share/keyrings/redis-archive-keyring.gpg

  # Add the Redis apt source for the current Ubuntu release codename.
  echo "deb [signed-by=/usr/share/keyrings/redis-archive-keyring.gpg] \
https://packages.redis.io/deb $(lsb_release -cs) main" \
    | sudo tee /etc/apt/sources.list.d/redis.list >/dev/null

  sudo apt-get update -qq
  sudo apt-get install -y -qq redis
  echo "  ✓ Redis installed"
}

if ! command -v redis-server &>/dev/null; then
  # Redis binary is completely absent — install from scratch.
  echo "Redis not found."
  if [ "$IS_UBUNTU" -eq 1 ]; then
    install_redis_ubuntu
  else
    echo ""
    echo "ERROR: Redis is not installed. Install it first:"
    echo ""
    echo "  Option A (Homebrew — recommended on macOS):"
    echo "    brew install redis"
    echo ""
    echo "  Option B (Docker):"
    echo "    docker run -d --name redis -p 6379:6379 redis:7-alpine"
    echo ""
    exit 1
  fi
else
  # Redis binary exists — verify the version meets our ≥ 7.0 requirement.
  # `redis-server --version` prints e.g. "Redis server v=7.2.4 sha=..."
  REDIS_VERSION=$(redis-server --version | grep -oP 'v=\K[0-9]+\.[0-9]+\.[0-9]+')
  if version_ge "$REDIS_VERSION" "7.0.0"; then
    echo "✓ Redis found: $(redis-server --version | awk '{print $1, $2, $3}')"
  else
    echo "Redis $REDIS_VERSION is installed but version 7.0+ is required."
    if [ "$IS_UBUNTU" -eq 1 ]; then
      echo "  → Upgrading Redis..."
      install_redis_ubuntu
    else
      echo ""
      echo "ERROR: Please upgrade Redis to 7.0 or newer."
      echo "  Homebrew: brew upgrade redis"
      echo "  Docker:   docker pull redis:7-alpine"
      echo ""
      exit 1
    fi
  fi
fi

# ══════════════════════════════════════════════════════════════════════════════
# DEPENDENCY: Python 3.10+
# ══════════════════════════════════════════════════════════════════════════════
# We accept any python3 binary that reports version ≥ 3.10. If the system
# Python is older we install python3.12 from the deadsnakes PPA (Ubuntu) or
# print instructions for other platforms.
install_python_ubuntu() {
  echo "  → Installing Python 3.12 via deadsnakes PPA..."
  ensure_sudo
  sudo apt-get update -qq
  sudo apt-get install -y -qq software-properties-common
  sudo add-apt-repository -y ppa:deadsnakes/ppa
  sudo apt-get update -qq
  # python3.12-venv is a separate package on Ubuntu and is needed for `python3 -m venv`
  sudo apt-get install -y -qq python3.12 python3.12-venv python3.12-distutils
  echo "  ✓ Python 3.12 installed"
}

PYTHON_BIN=""   # will hold the path to the acceptable python3 binary

if command -v python3 &>/dev/null; then
  # A python3 exists — check whether its version is new enough.
  PY_VERSION=$(python3 -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])')
  if version_ge "$PY_VERSION" "3.10.0"; then
    echo "✓ Python found: $(python3 --version)"
    PYTHON_BIN="python3"
  else
    echo "Python $PY_VERSION is installed but 3.10+ is required."
    if [ "$IS_UBUNTU" -eq 1 ]; then
      install_python_ubuntu
      PYTHON_BIN="python3.12"
    else
      echo ""
      echo "ERROR: Please install Python 3.10 or newer."
      echo "  Download: https://www.python.org/downloads/"
      echo ""
      exit 1
    fi
  fi
else
  # No python3 at all.
  echo "Python 3 not found."
  if [ "$IS_UBUNTU" -eq 1 ]; then
    install_python_ubuntu
    PYTHON_BIN="python3.12"
  else
    echo "ERROR: python3 not found. Install Python 3.10 or newer and re-run ./setup.sh."
    exit 1
  fi
fi

# ── Python venv ───────────────────────────────────────────────────────────────
# Use the verified/installed python binary to create the virtualenv so we are
# guaranteed to get the right version inside .venv even on machines that have
# multiple python versions alongside each other.
#
# On Ubuntu, the `python3-venv` package is a *separate* apt package from the
# interpreter itself and is not installed by default. We must ensure it exists
# before calling `python3 -m venv`, otherwise Python exits with the misleading
# "ensurepip is not available" error even though Python itself is fine.
# We derive the package name from the binary (e.g. python3   → python3-venv,
#                                                  python3.12 → python3.12-venv)
if [ "$IS_UBUNTU" -eq 1 ]; then
  # Derive the apt package names for the venv and pip modules directly from the
  # binary name by appending the appropriate suffix. Examples:
  #   python3    → python3-venv,  python3-pip
  #   python3.10 → python3.10-venv, python3.10-distutils (pip lives in python3-pip for 3.10)
  #   python3.12 → python3.12-venv, python3.12-pip (or python3-pip as fallback)
  # On Ubuntu, the -venv package provides `ensurepip` and the -pip package
  # ensures pip is available inside newly created venvs. Both are needed.
  PY_BASENAME=$(basename "$PYTHON_BIN")   # e.g. "python3" or "python3.10"
  VENV_PKG="${PY_BASENAME}-venv"          # e.g. "python3-venv" or "python3.10-venv"
  PIP_PKG="${PY_BASENAME}-pip"            # e.g. "python3-pip" or "python3.10-pip"

  ensure_sudo
  sudo apt-get update -qq

  # Install -venv if missing (needed for `python -m venv` / ensurepip)
  if ! dpkg -s "$VENV_PKG" &>/dev/null; then
    echo "  → Installing $VENV_PKG (required for 'python -m venv')..."
    sudo apt-get install -y -qq "$VENV_PKG"
    echo "  ✓ $VENV_PKG installed"
  fi

  # Install -pip if the versioned package exists in apt, otherwise fall back to
  # the generic python3-pip which covers all system Python versions on Ubuntu.
  if ! dpkg -s "$PIP_PKG" &>/dev/null; then
    echo "  → Installing pip for $PY_BASENAME..."
    # Try the versioned package first; if apt can't find it use python3-pip.
    if apt-cache show "$PIP_PKG" &>/dev/null; then
      sudo apt-get install -y -qq "$PIP_PKG"
      echo "  ✓ $PIP_PKG installed"
    else
      sudo apt-get install -y -qq python3-pip
      echo "  ✓ python3-pip installed (covers $PY_BASENAME)"
    fi
  fi
fi

# Delete a pre-existing .venv that may have been created without pip
# (i.e. from a previous failed run before the pip package was present).
# We detect this by checking for the pip binary inside the venv.
if [ -d ".venv" ] && [ ! -f ".venv/bin/pip" ]; then
  echo "  → Existing .venv has no pip — removing and recreating..."
  rm -rf .venv
fi

if [ ! -d ".venv" ]; then
  echo "Creating Python virtual environment (.venv) with $PYTHON_BIN..."
  "$PYTHON_BIN" -m venv .venv
fi

# Last-resort pip bootstrap: if the venv still has no pip after creation
# (can happen when ensurepip is broken even after installing the apt packages),
# download and run the official get-pip.py installer directly.
if [ ! -f ".venv/bin/pip" ]; then
  echo "  → pip not found in venv — bootstrapping via get-pip.py..."
  curl -fsSL https://bootstrap.pypa.io/get-pip.py -o /tmp/get-pip.py
  .venv/bin/python /tmp/get-pip.py --quiet
  rm -f /tmp/get-pip.py
  echo "  ✓ pip bootstrapped"
fi

echo "✓ Python venv ready"

echo "Installing Python dependencies..."
.venv/bin/pip install --quiet --upgrade pip
.venv/bin/pip install --quiet -r requirements.txt
echo "✓ Python dependencies installed"

# ══════════════════════════════════════════════════════════════════════════════
# DEPENDENCY: Node.js 18+
# ══════════════════════════════════════════════════════════════════════════════
# The Ubuntu system repos typically ship Node.js 12 or 16, which is too old.
# We use NodeSource's setup script to pin the LTS 18.x channel, then apt-get
# install as usual. On other platforms we print install instructions.
install_node_ubuntu() {
  echo "  → Installing Node.js 18 LTS via NodeSource..."
  ensure_sudo
  sudo apt-get update -qq
  sudo apt-get install -y -qq curl

  # NodeSource provides a convenience script that adds their apt repo and
  # imports the signing key in one step. We pin to the Node 18 LTS channel.
  curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
  sudo apt-get install -y -qq nodejs
  echo "  ✓ Node.js $(node --version) installed"
}

if ! command -v npm &>/dev/null; then
  # npm (and therefore node) is completely absent.
  echo "Node.js / npm not found."
  if [ "$IS_UBUNTU" -eq 1 ]; then
    install_node_ubuntu
  else
    echo "ERROR: npm not found. Install Node.js 18 or newer and re-run ./setup.sh."
    exit 1
  fi
else
  # npm exists — verify Node version meets our ≥ 18.0.0 requirement.
  NODE_VERSION=$(node --version | sed 's/^v//')   # strip leading 'v'
  if version_ge "$NODE_VERSION" "18.0.0"; then
    echo "✓ Node.js found: $(node --version) / npm $(npm --version)"
  else
    echo "Node.js $NODE_VERSION is installed but 18.0+ is required."
    if [ "$IS_UBUNTU" -eq 1 ]; then
      install_node_ubuntu
    else
      echo ""
      echo "ERROR: Please upgrade Node.js to 18 or newer."
      echo "  nvm:      nvm install 18 && nvm use 18"
      echo "  Download: https://nodejs.org/"
      echo ""
      exit 1
    fi
  fi
fi

# ── Frontend build ────────────────────────────────────────────────────────────
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
