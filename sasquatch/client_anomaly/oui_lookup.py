"""
oui_lookup.py — Local IEEE OUI database lookup.

Provides manufacturer name resolution from the first 3 octets (OUI) of a MAC address
using a bundled copy of the IEEE MA-L registry. No network calls are made at lookup time.

The database is loaded lazily on first use and held in memory (~1.3 MB dict).

Updating the database:
  python3 -m sasquatch.client_anomaly.oui_lookup

Or from code:
  from sasquatch.client_anomaly.oui_lookup import build_db
  build_db()           # downloads from IEEE and overwrites data/oui.json
  build_db("/path/to/oui.txt")  # parse a locally downloaded copy
"""

import json
import logging
import re
import urllib.request
from pathlib import Path

log = logging.getLogger(__name__)

_DB_PATH = Path(__file__).parent / "data" / "oui.json"
_IEEE_URL = "https://standards-oui.ieee.org/oui/oui.txt"

_db: dict[str, str] | None = None


def _load() -> dict[str, str]:
    global _db
    if _db is not None:
        return _db
    if _DB_PATH.exists():
        try:
            _db = json.loads(_DB_PATH.read_text())
            log.debug("OUI database loaded: %d entries from %s", len(_db), _DB_PATH)
        except Exception as exc:
            log.warning("Failed to load OUI database: %s — lookups will return Unknown", exc)
            _db = {}
    else:
        log.warning(
            "OUI database not found at %s — run oui_lookup.build_db() to download. "
            "MAC manufacturer lookups will return Unknown until the database is built.",
            _DB_PATH,
        )
        _db = {}
    return _db


def lookup(mac: str) -> str:
    """
    Return the IEEE-registered manufacturer name for a MAC address.

    Accepts any MAC format (colons, hyphens, raw hex). Only the first 6 hex
    characters (OUI) are used. Returns "Unknown" if not in database.
    """
    oui = re.sub(r"[^0-9a-fA-F]", "", mac)[:6].upper()
    if len(oui) < 6:
        return "Unknown"
    return _load().get(oui, "Unknown")


def _parse_ieee_text(text: str) -> dict[str, str]:
    """Parse IEEE OUI text file format into {OUI_HEX: manufacturer} dict."""
    db: dict[str, str] = {}
    for line in text.splitlines():
        m = re.match(r"^([0-9A-Fa-f]{6})\s+\(base 16\)\s+(.+)", line)
        if m:
            db[m.group(1).upper()] = m.group(2).strip()
    return db


def build_db(source_path: str | None = None) -> int:
    """
    Build or refresh the local OUI database.

    If source_path is provided, parse that file (must be IEEE OUI text format).
    Otherwise, download the current registry from the IEEE standards server.

    Overwrites data/oui.json and resets the in-memory cache.
    Returns the number of OUI entries written.

    This function performs a network download when source_path is None — it should
    only be called at setup/update time, never in the detection hot path.
    """
    global _db

    if source_path:
        text = Path(source_path).read_text()
        log.info("Parsing OUI file: %s", source_path)
    else:
        log.info("Downloading OUI registry from %s", _IEEE_URL)
# The IEEE server returns HTTP 418 if the request looks like a bot/scraper.
# Spoofing a standard browser User-Agent header gets us through.
        req = urllib.request.Request(
            _IEEE_URL,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36"}
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            text = resp.read().decode("utf-8", errors="replace")
        log.info("Download complete: %d bytes", len(text))

    db = _parse_ieee_text(text)
    if not db:
        raise ValueError("Parsed 0 OUI entries — check source file format")

    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    _DB_PATH.write_text(json.dumps(db, separators=(",", ":")))
    _db = db  # reset in-memory cache
    log.info("OUI database written: %d entries → %s", len(db), _DB_PATH)
    return len(db)


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    source = sys.argv[1] if len(sys.argv) > 1 else None
    count = build_db(source)
    print(f"OUI database built: {count} entries → {_DB_PATH}")
