"""
db.py -- SQLite event store and client cache.

Replaces Redis sorted sets for events and Redis JSON blobs for client cache.
SQLite handles millions of rows with near-zero memory overhead, persists to disk,
and supports SQL queries for aggregation and filtering.

Connection management: a single module-level connection is lazily initialised on
first use and reused across all callers.  WAL mode is enabled for concurrent
reads during writes.

Tables:
  events  -- enriched client events, deduplicated by (mac, event_type, timestamp, bssid)
  clients -- MAC -> device metadata lookup, one row per MAC, scoped to the org.
             MACs are unique across the org, so client records are stored once
             per MAC and shared by every site that sees that MAC in events.
"""

import json
import logging
import os
import pathlib
import re
import time
from typing import Optional

import aiosqlite

log = logging.getLogger(__name__)

# Default DB path: data/sasquatch.db next to this file.  Overridable via env var.
_DEFAULT_DB_DIR = pathlib.Path(__file__).parent / "data"
DB_PATH = os.getenv(
    "SASQUATCH_SQLITE_PATH",
    str(_DEFAULT_DB_DIR / "sasquatch.db"),
)

# Retention: events older than this are pruned on each write cycle.
# This is the storage window — drilldowns, search, post-incident forensics
# all read against this 7-day pool.
EVENTS_RETENTION_SECONDS = 7 * 24 * 3600  # 7 days

# Detection window: anomaly detection (feature_engineer.build_features and
# anomaly_detector.score / score_org_wide) only considers events newer than
# this. Decoupled from EVENTS_RETENTION_SECONDS so the storage horizon can
# stay long for forensics while detection focuses on "current behavior".
# Bounding the detection window also bounds Phase 3/4 working-set memory:
# more days of data → more rare MACs → larger composite_features dict.
DETECTION_WINDOW_SECONDS = 24 * 3600  # 24 hours


def get_detection_cutoff() -> float:
    """Unix timestamp marking the lower bound of the anomaly detection
    window. Single source of truth for every detection-side `get_events`
    call so the window can be tuned in one place."""
    return time.time() - DETECTION_WINDOW_SECONDS

# Module-level connection -- lazily initialised.
_conn: Optional[aiosqlite.Connection] = None


async def get_connection() -> aiosqlite.Connection:
    """Return the shared async SQLite connection, creating it on first call."""
    global _conn
    if _conn is None:
        # Ensure the directory exists
        db_dir = pathlib.Path(DB_PATH).parent
        db_dir.mkdir(parents=True, exist_ok=True)

        _conn = await aiosqlite.connect(DB_PATH)
        _conn.row_factory = aiosqlite.Row
        await _conn.execute("PRAGMA journal_mode=WAL")
        await _conn.execute("PRAGMA synchronous=NORMAL")
        await _conn.execute("PRAGMA busy_timeout=5000")
        await _init_schema(_conn)
        log.info(f"SQLite connection opened: {DB_PATH}")
    return _conn


async def close():
    """Close the shared connection.  Safe to call multiple times."""
    global _conn
    if _conn is not None:
        await _conn.close()
        _conn = None
        log.info("SQLite connection closed")


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id TEXT NOT NULL DEFAULT '',
    site_id TEXT NOT NULL,
    mac TEXT NOT NULL,
    event_type TEXT NOT NULL,
    timestamp REAL NOT NULL,
    bssid TEXT NOT NULL DEFAULT '',
    device_family TEXT,
    device_model TEXT,
    device_manufacturer TEXT,
    wlan TEXT,
    event_category TEXT,
    raw_json TEXT NOT NULL,
    UNIQUE(mac, event_type, timestamp, bssid)
);

CREATE INDEX IF NOT EXISTS idx_events_site_ts ON events(site_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_events_mac ON events(mac, timestamp);
CREATE INDEX IF NOT EXISTS idx_events_org_ts ON events(org_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_events_wlan ON events(site_id, wlan);

CREATE TABLE IF NOT EXISTS clients (
    mac TEXT PRIMARY KEY,
    org_id TEXT NOT NULL DEFAULT '',
    family TEXT NOT NULL,
    model TEXT,
    os TEXT,
    manufacturer TEXT,
    random_mac BOOLEAN DEFAULT FALSE,
    last_ssid TEXT,
    last_ap TEXT,
    last_site_id TEXT,
    last_username TEXT,
    last_username_norm TEXT,
    updated_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_clients_org ON clients(org_id);
CREATE INDEX IF NOT EXISTS idx_clients_family ON clients(family);
CREATE INDEX IF NOT EXISTS idx_clients_last_site ON clients(last_site_id);
-- idx_clients_username_norm is created in _migrate_clients_add_last_username
-- after the ALTER TABLE adds the column, to keep init safe on legacy DBs.

CREATE TABLE IF NOT EXISTS client_refresh_log (
    org_id TEXT PRIMARY KEY,
    refreshed_at REAL NOT NULL,
    client_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS client_summary (
    mac TEXT NOT NULL,
    site_id TEXT NOT NULL,
    wlan TEXT NOT NULL,
    org_id TEXT NOT NULL DEFAULT '',

    device_family TEXT,
    device_model TEXT,
    device_manufacturer TEXT,
    device_os TEXT,
    last_username TEXT,
    service_account_family TEXT,
    random_mac BOOLEAN DEFAULT FALSE,

    health_score REAL,
    if_score REAL,
    centroid_dist_score REAL,
    dbscan_label INTEGER,
    is_if_outlier BOOLEAN DEFAULT FALSE,
    is_dbscan_outlier BOOLEAN DEFAULT FALSE,
    is_family_outlier BOOLEAN DEFAULT FALSE,
    is_markov_outlier BOOLEAN DEFAULT FALSE,
    markov_reason TEXT,
    service_alarm BOOLEAN DEFAULT FALSE,

    total_events INTEGER DEFAULT 0,
    dhcp_success INTEGER DEFAULT 0,
    dhcp_failure INTEGER DEFAULT 0,
    dns_success INTEGER DEFAULT 0,
    dns_failure INTEGER DEFAULT 0,
    auth_success INTEGER DEFAULT 0,
    auth_failure INTEGER DEFAULT 0,
    roam_success INTEGER DEFAULT 0,
    roam_failure INTEGER DEFAULT 0,
    disassoc_ap INTEGER DEFAULT 0,
    disassoc_client INTEGER DEFAULT 0,
    arp_success INTEGER DEFAULT 0,
    arp_failure INTEGER DEFAULT 0,
    captive_portal INTEGER DEFAULT 0,
    security INTEGER DEFAULT 0,
    collaboration INTEGER DEFAULT 0,
    other INTEGER DEFAULT 0,

    first_seen REAL,
    last_seen REAL,
    built_at REAL NOT NULL,

    PRIMARY KEY (mac, site_id, wlan)
);

CREATE INDEX IF NOT EXISTS idx_summary_family ON client_summary(device_family);
CREATE INDEX IF NOT EXISTS idx_summary_family_wlan ON client_summary(device_family, wlan);
CREATE INDEX IF NOT EXISTS idx_summary_site_wlan ON client_summary(site_id, wlan);
CREATE INDEX IF NOT EXISTS idx_summary_health ON client_summary(health_score);
CREATE INDEX IF NOT EXISTS idx_summary_username ON client_summary(last_username);
CREATE INDEX IF NOT EXISTS idx_summary_sa_family ON client_summary(service_account_family);
CREATE INDEX IF NOT EXISTS idx_summary_mac ON client_summary(mac);
"""


async def _migrate_clients_to_org_scope(conn: aiosqlite.Connection) -> None:
    """
    Detect the legacy per-site clients schema and rebuild it as a per-org table.

    Legacy schema had a composite PRIMARY KEY (mac, site_id) and a `site_id`
    column. The new schema is keyed on `mac` alone. Since the clients cache is
    refreshed daily from the Mist API, dropping and recreating the table is
    safe -- the next refresh repopulates it. Same for client_refresh_log, which
    used to be keyed by site_id and is now keyed by org_id.
    """
    # Inspect current clients schema
    cursor = await conn.execute("PRAGMA table_info(clients)")
    cols = await cursor.fetchall()
    col_names = {row[1] for row in cols}
    if cols and ("site_id" in col_names and "last_site_id" not in col_names):
        log.info("Migrating clients table from per-site to per-org schema (drop+recreate)")
        await conn.execute("DROP TABLE IF EXISTS clients")
        await conn.execute("DROP TABLE IF EXISTS client_refresh_log")
        await conn.commit()


async def _migrate_clients_add_last_username(conn: aiosqlite.Connection) -> None:
    """
    Add `last_username` and `last_username_norm` columns to an existing clients
    table if they are missing. The daily client refresh re-populates both from
    the Mist API, so no backfill is needed — a NULL column is acceptable until
    the next refresh runs.
    """
    cursor = await conn.execute("PRAGMA table_info(clients)")
    cols = await cursor.fetchall()
    if not cols:
        return  # table will be created fresh by the main schema script
    col_names = {row[1] for row in cols}
    if "last_username" not in col_names:
        log.info("Adding last_username column to clients table")
        await conn.execute("ALTER TABLE clients ADD COLUMN last_username TEXT")
    if "last_username_norm" not in col_names:
        log.info("Adding last_username_norm column to clients table")
        await conn.execute("ALTER TABLE clients ADD COLUMN last_username_norm TEXT")
    await conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_clients_username_norm "
        "ON clients(org_id, last_username_norm)"
    )
    await conn.commit()


async def _migrate_client_summary_split_disassoc(conn: aiosqlite.Connection) -> None:
    """
    Replace the legacy single `disassoc` column on `client_summary` with
    `disassoc_ap` and `disassoc_client`. Additive + in-place: adds the new
    columns if missing, then drops the old one if present. The next detection
    cycle rebuilds the scope from events, so the new columns re-populate
    correctly without any backfill — AP vs Client is derivable only from the
    raw event_type, which the summary row no longer has.
    """
    cursor = await conn.execute("PRAGMA table_info(client_summary)")
    cols = await cursor.fetchall()
    if not cols:
        return
    col_names = {row[1] for row in cols}
    if "disassoc_ap" not in col_names:
        log.info("Adding disassoc_ap column to client_summary")
        await conn.execute("ALTER TABLE client_summary ADD COLUMN disassoc_ap INTEGER DEFAULT 0")
    if "disassoc_client" not in col_names:
        log.info("Adding disassoc_client column to client_summary")
        await conn.execute("ALTER TABLE client_summary ADD COLUMN disassoc_client INTEGER DEFAULT 0")
    if "disassoc" in col_names:
        log.info("Dropping legacy disassoc column from client_summary")
        await conn.execute("ALTER TABLE client_summary DROP COLUMN disassoc")
    await conn.commit()


async def _migrate_client_summary_add_device_os(conn: aiosqlite.Connection) -> None:
    """
    Add `device_os` to `client_summary`. The next detection cycle rebuilds
    the scope from the client cache, so the column populates without a
    backfill.
    """
    cursor = await conn.execute("PRAGMA table_info(client_summary)")
    cols = await cursor.fetchall()
    if not cols:
        return
    col_names = {row[1] for row in cols}
    if "device_os" not in col_names:
        log.info("Adding device_os column to client_summary")
        await conn.execute("ALTER TABLE client_summary ADD COLUMN device_os TEXT")
    await conn.commit()


async def _init_schema(conn: aiosqlite.Connection):
    """Create tables and indexes if they don't exist."""
    await _migrate_clients_to_org_scope(conn)
    await conn.executescript(_SCHEMA_SQL)
    await _migrate_clients_add_last_username(conn)
    await _migrate_client_summary_split_disassoc(conn)
    await _migrate_client_summary_add_device_os(conn)
    await conn.commit()


# ---------------------------------------------------------------------------
# Events CRUD
# ---------------------------------------------------------------------------

async def insert_events(events: list[dict], site_id: str) -> int:
    """
    Insert enriched events into SQLite.  Duplicates (same mac, event_type,
    timestamp, bssid) are silently ignored via INSERT OR IGNORE.

    Returns the number of rows actually inserted (excluding duplicates).
    """
    if not events:
        return 0

    conn = await get_connection()
    rows = []
    for event in events:
        mac = (event.get("mac") or "").replace(":", "").lower()
        rows.append((
            event.get("org_id", ""),
            site_id,
            mac,
            event.get("type", ""),
            float(event.get("timestamp") or 0),
            event.get("bssid", ""),
            event.get("device_family"),
            event.get("device_model"),
            event.get("device_manufacturer"),
            event.get("wlan"),
            event.get("event_category"),
            json.dumps(event, sort_keys=True),
        ))

    cursor = await conn.executemany(
        """INSERT OR IGNORE INTO events
           (org_id, site_id, mac, event_type, timestamp, bssid,
            device_family, device_model, device_manufacturer, wlan,
            event_category, raw_json)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        rows,
    )
    await conn.commit()
    return cursor.rowcount


async def get_events(
    site_id: Optional[str] = None,
    wlan: Optional[str] = None,
    since: Optional[float] = None,
    mac: Optional[str] = None,
) -> list[dict]:
    """
    Load events from SQLite, optionally filtered by site and/or WLAN and/or
    MAC.

    By default returns events from the last EVENTS_RETENTION_SECONDS (7 days).
    Pass `since` to override the cutoff timestamp. Pass `mac` (normalized
    form: no colons, lowercase — same as how event_collector stores it) to
    pull only that MAC's events; this is the path the per-MAC drilldown
    takes and uses idx_events_mac to avoid a full per-site scan.
    """
    conn = await get_connection()
    cutoff = since if since is not None else (time.time() - EVENTS_RETENTION_SECONDS)

    conditions = ["timestamp >= ?"]
    params: list = [cutoff]

    if site_id:
        conditions.append("site_id = ?")
        params.append(site_id)
    if wlan:
        conditions.append("wlan = ?")
        params.append(wlan)
    if mac:
        conditions.append("mac = ?")
        params.append(mac)

    where = " AND ".join(conditions)
    query = f"SELECT raw_json FROM events WHERE {where} ORDER BY timestamp"

    rows = await conn.execute_fetchall(query, params)
    # Decode per-row so a single corrupt raw_json blob doesn't take out the
    # entire read (which would cascade through feature_engineer, summary builder,
    # drilldown routes, etc.). Bad rows are logged and skipped.
    events: list[dict] = []
    _bad = 0
    for row in rows:
        try:
            events.append(json.loads(row[0]))
        except (json.JSONDecodeError, TypeError):
            _bad += 1
    if _bad:
        log.warning(
            "get_events: skipped %d row(s) with malformed raw_json (site_id=%s wlan=%s)",
            _bad, site_id, wlan,
        )
    return events


async def get_event_count(
    site_id: Optional[str] = None,
    wlan: Optional[str] = None,
) -> int:
    """Return event count without loading full JSON blobs."""
    conn = await get_connection()
    cutoff = time.time() - EVENTS_RETENTION_SECONDS

    conditions = ["timestamp >= ?"]
    params: list = [cutoff]
    if site_id:
        conditions.append("site_id = ?")
        params.append(site_id)
    if wlan:
        conditions.append("wlan = ?")
        params.append(wlan)

    where = " AND ".join(conditions)
    query = f"SELECT COUNT(*) FROM events WHERE {where}"
    rows = await conn.execute_fetchall(query, params)
    return rows[0][0] if rows else 0


async def get_event_counts_by_site_wlan() -> dict[tuple[str, str], int]:
    """
    SQL-side per-(site_id, wlan) event count across the **detection window**
    (DETECTION_WINDOW_SECONDS, currently 24h), not the storage retention
    window. Used by Phase 2 to filter out scopes with no in-window events
    before doing per-scope feature builds — must match the window the
    detection-side `get_events` calls use, or Phase 2 would emit work for
    scopes whose events are all stale.

    Replaces the previous pattern of `get_events()` (full org corpus, every
    raw_json blob decoded) followed by `Counter(e["site_id"] for e in ...)`.
    On a multi-million-event org that pattern peaked at ~30 GB of decoded
    Python dicts; this returns a dict of ~hundreds of (site, wlan) tuples
    using kilobytes.
    """
    conn = await get_connection()
    cutoff = get_detection_cutoff()
    query = (
        "SELECT site_id, COALESCE(wlan, '') AS w, COUNT(*) AS cnt "
        "FROM events WHERE timestamp >= ? "
        "GROUP BY site_id, w"
    )
    rows = await conn.execute_fetchall(query, [cutoff])
    return {(sid, wlan): int(cnt) for sid, wlan, cnt in rows}


async def get_events_category_rollup(
    site_id: str,
    wlan: str,
    macs_filter: Optional[set[str]] = None,
) -> tuple[dict[str, dict[str, int]], dict[str, set[str]]]:
    """
    SQL-side rollup of (device_family, event_category, mac) for one (site, wlan).

    Returns (cat_counts, family_macs):
      cat_counts:  {device_family: {event_category: count}}
      family_macs: {device_family: set(mac)}

    Used by build_site_events_summary instead of pulling and json.loads-ing
    every event row. On a million-event site this drops peak memory from
    multi-GB to a few hundred KB.

    `macs_filter`, if provided, restricts the rollup to events whose mac is
    in the set — used by the service-account synthetic-row pass.
    """
    conn = await get_connection()
    cutoff = time.time() - EVENTS_RETENTION_SECONDS

    query = (
        "SELECT COALESCE(device_family, 'Unknown') AS fam, "
        "       COALESCE(event_category, 'OTHER') AS cat, "
        "       mac, "
        "       COUNT(*) AS cnt "
        "FROM events "
        "WHERE timestamp >= ? AND site_id = ? AND wlan = ? "
        "GROUP BY fam, cat, mac"
    )
    rows = await conn.execute_fetchall(query, [cutoff, site_id, wlan])

    # MACs are stored normalized (no colons, lowercase) by event_collector,
    # so no per-row normalization is required.
    cat_counts: dict[str, dict[str, int]] = {}
    family_macs: dict[str, set[str]] = {}
    for fam, cat, mac, cnt in rows:
        if macs_filter is not None and mac not in macs_filter:
            continue
        if fam not in cat_counts:
            cat_counts[fam] = {}
            family_macs[fam] = set()
        cat_counts[fam][cat] = cat_counts[fam].get(cat, 0) + int(cnt)
        if mac:
            family_macs[fam].add(mac)
    return cat_counts, family_macs


async def get_per_mac_category_counts_for_family(
    site_id: str,
    wlan: str,
    family: Optional[str] = None,
    macs_filter: Optional[set[str]] = None,
) -> tuple[dict[str, dict[str, int]], dict[str, int]]:
    """
    SQL-side per-MAC category breakdown within a (site, wlan), filtered by
    either device_family or an explicit MAC set (used by service-account
    families which select members by sa membership rather than by event
    device_family).

    Returns (mac_counts, mac_total):
      mac_counts: {mac: {event_category: count}}
      mac_total:  {mac: total_events}

    Replaces the per-row Python pattern in /sites/{id}/families/{family}/event-counts
    that pulled and JSON-decoded every event in the (site, wlan) — the full
    7-day blob — just to filter to one family on the server.
    """
    conn = await get_connection()
    cutoff = time.time() - EVENTS_RETENTION_SECONDS
    conditions = ["timestamp >= ?", "site_id = ?", "wlan = ?"]
    params: list = [cutoff, site_id, wlan]
    if family:
        conditions.append("device_family = ?")
        params.append(family)
    if macs_filter:
        placeholders = ",".join("?" * len(macs_filter))
        conditions.append(f"mac IN ({placeholders})")
        params.extend(sorted(macs_filter))
    where = " AND ".join(conditions)
    query = (
        f"SELECT mac, COALESCE(event_category, 'OTHER') AS cat, COUNT(*) AS cnt "
        f"FROM events WHERE {where} "
        f"GROUP BY mac, cat"
    )
    rows = await conn.execute_fetchall(query, params)
    mac_counts: dict[str, dict[str, int]] = {}
    mac_total: dict[str, int] = {}
    for mac, cat, cnt in rows:
        if not mac:
            continue
        cnt_i = int(cnt)
        if mac not in mac_counts:
            mac_counts[mac] = {}
            mac_total[mac] = 0
        mac_counts[mac][cat] = cnt_i
        mac_total[mac] += cnt_i
    return mac_counts, mac_total


async def get_mac_category_counts(
    site_id: str,
    wlan: str,
    macs: set[str],
) -> dict[str, int]:
    """
    SQL-side per-category event counts for a specific set of MACs at one
    (site, wlan). Used by the service-account synthetic-row builder to avoid
    a second full-event scan in build_site_events_summary.

    Returns {event_category: total_count} summed across the supplied macs.
    """
    if not macs:
        return {}
    conn = await get_connection()
    cutoff = time.time() - EVENTS_RETENTION_SECONDS
    # MACs are stored normalized (no colons, lowercase) by event_collector,
    # so we can match against the column directly without LOWER/REPLACE.
    placeholders = ",".join("?" * len(macs))
    query = (
        f"SELECT COALESCE(event_category, 'OTHER') AS cat, COUNT(*) AS cnt "
        f"FROM events "
        f"WHERE timestamp >= ? AND site_id = ? AND wlan = ? "
        f"AND mac IN ({placeholders}) "
        f"GROUP BY cat"
    )
    params = [cutoff, site_id, wlan, *sorted(macs)]
    rows = await conn.execute_fetchall(query, params)
    return {cat: int(cnt) for cat, cnt in rows}


async def get_wlans(site_id: Optional[str] = None) -> list[str]:
    """Return sorted list of unique WLAN (SSID) names."""
    conn = await get_connection()
    cutoff = time.time() - EVENTS_RETENTION_SECONDS

    if site_id:
        rows = await conn.execute_fetchall(
            "SELECT DISTINCT wlan FROM events WHERE site_id = ? AND timestamp >= ? AND wlan IS NOT NULL AND wlan != ''",
            (site_id, cutoff),
        )
    else:
        rows = await conn.execute_fetchall(
            "SELECT DISTINCT wlan FROM events WHERE timestamp >= ? AND wlan IS NOT NULL AND wlan != ''",
            (cutoff,),
        )
    return sorted(row[0] for row in rows)


async def get_site_ids_with_events() -> list[str]:
    """Return list of site_ids that have events in the retention window."""
    conn = await get_connection()
    cutoff = time.time() - EVENTS_RETENTION_SECONDS
    rows = await conn.execute_fetchall(
        "SELECT DISTINCT site_id FROM events WHERE timestamp >= ?",
        (cutoff,),
    )
    return [row[0] for row in rows]


async def reenrich_events(
    site_id: str,
    enricher: callable,
    client_cache: dict[str, dict],
) -> int:
    """
    Re-enrich stored events whose device_family starts with 'Unknown'.

    enricher: a function(event_dict, client_cache) -> enriched_event_dict
    Returns count of events updated.
    """
    conn = await get_connection()
    cutoff = time.time() - EVENTS_RETENTION_SECONDS

    rows = await conn.execute_fetchall(
        """SELECT id, raw_json FROM events
           WHERE site_id = ? AND timestamp >= ?
           AND (device_family LIKE 'Unknown%' OR device_family IS NULL)""",
        (site_id, cutoff),
    )

    updates = []
    for row in rows:
        event = json.loads(row[1])
        new_event = enricher(event, client_cache)
        new_json = json.dumps(new_event, sort_keys=True)
        if new_json == row[1]:
            continue
        updates.append((
            new_event.get("device_family"),
            new_event.get("device_model"),
            new_event.get("device_manufacturer"),
            new_event.get("event_category"),
            new_json,
            row[0],  # id
        ))

    if not updates:
        return 0

    await conn.executemany(
        """UPDATE events SET device_family=?, device_model=?, device_manufacturer=?,
           event_category=?, raw_json=? WHERE id=?""",
        updates,
    )
    await conn.commit()
    log.info(f"Re-enriched {len(updates)} stale events for site {site_id}")
    return len(updates)


async def delete_events_for_site(site_id: str) -> int:
    """Delete all events for a given site.  Returns row count deleted."""
    conn = await get_connection()
    cursor = await conn.execute("DELETE FROM events WHERE site_id = ?", (site_id,))
    await conn.commit()
    return cursor.rowcount


async def purge_old_events() -> int:
    """Delete events older than the retention window.  Returns row count deleted."""
    conn = await get_connection()
    cutoff = time.time() - EVENTS_RETENTION_SECONDS
    cursor = await conn.execute("DELETE FROM events WHERE timestamp < ?", (cutoff,))
    await conn.commit()
    deleted = cursor.rowcount
    if deleted:
        log.info(f"Purged {deleted} expired events (older than 7 days)")
    return deleted


# ---------------------------------------------------------------------------
# Clients CRUD (org-scoped — MACs are unique across the org)
# ---------------------------------------------------------------------------

def normalize_username(raw: str | None) -> str:
    """
    Canonical normalization used when grouping usernames into service-account
    families. Case-insensitive, whitespace-stripped. Returns an empty string
    for missing/blank values so call sites can test falsy.
    """
    if not raw:
        return ""
    return raw.strip().lower()


async def upsert_clients_org(org_id: str, client_map: dict[str, dict]) -> int:
    """
    Upsert client records for the org. ``client_map`` is MAC -> metadata dict
    (shape: {family, model, os, manufacturer, random_mac, last_ssid, last_ap,
    last_site_id, last_username}).

    The clients table is fully replaced for this org on every refresh — MACs
    seen at any site in the org live in the same row, since MACs are unique
    org-wide. Returns count of rows upserted.
    """
    conn = await get_connection()
    now = time.time()

    # Wipe the org's existing rows then bulk insert -- fastest for full refresh.
    await conn.execute("DELETE FROM clients WHERE org_id = ?", (org_id,))

    if client_map:
        rows = []
        for mac, meta in client_map.items():
            username = meta.get("last_username", "") or ""
            rows.append((
                mac,
                org_id,
                meta.get("family", "Unknown"),
                meta.get("model", ""),
                meta.get("os", ""),
                meta.get("manufacturer", ""),
                meta.get("random_mac", False),
                meta.get("last_ssid", ""),
                meta.get("last_ap", ""),
                meta.get("last_site_id", ""),
                username,
                normalize_username(username),
                now,
            ))
        await conn.executemany(
            """INSERT OR REPLACE INTO clients
               (mac, org_id, family, model, os, manufacturer,
                random_mac, last_ssid, last_ap, last_site_id,
                last_username, last_username_norm, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            rows,
        )

    # Record that this org has been refreshed (even if zero clients).
    await conn.execute(
        """INSERT OR REPLACE INTO client_refresh_log (org_id, refreshed_at, client_count)
           VALUES (?, ?, ?)""",
        (org_id, now, len(client_map)),
    )
    await conn.commit()
    return len(client_map)


async def get_org_client_cache(org_id: str) -> dict[str, dict] | None:
    """
    Load the org-wide client cache from SQLite.

    Returns:
      None  -- no rows for this org (refresh has never run).
      {}    -- org exists in DB but has no clients.
      {...} -- normal populated cache: MAC -> {family, model, os, manufacturer,
               random_mac, last_ssid, last_ap, last_site_id}.

    To distinguish 'never refreshed' from 'refreshed but empty', we check the
    refresh log: ``upsert_clients_org`` always writes a refresh-log row even
    when client_map is empty.
    """
    conn = await get_connection()

    rows = await conn.execute_fetchall(
        """SELECT mac, family, model, os, manufacturer, random_mac,
                  last_ssid, last_ap, last_site_id, last_username,
                  last_username_norm
           FROM clients WHERE org_id = ?""",
        (org_id,),
    )

    if not rows:
        refresh_row = await conn.execute_fetchall(
            "SELECT 1 FROM client_refresh_log WHERE org_id = ? LIMIT 1",
            (org_id,),
        )
        if refresh_row:
            return {}
        return None

    result = {}
    for row in rows:
        result[row[0]] = {
            "family": row[1],
            "model": row[2] or "",
            "os": row[3] or "",
            "manufacturer": row[4] or "",
            "random_mac": bool(row[5]),
            "last_ssid": row[6] or "",
            "last_ap": row[7] or "",
            "last_site_id": row[8] or "",
            "last_username": row[9] or "",
            "last_username_norm": row[10] or "",
        }
    return result


async def iter_org_client_rows(org_id: str):
    """
    Yield client rows for an org one tuple at a time so CSV export can stream
    without holding the full cache in memory. Each tuple matches the column
    order of ``CLIENT_EXPORT_COLUMNS``.
    """
    conn = await get_connection()
    cursor = await conn.execute(
        """SELECT mac, family, manufacturer, model, os, random_mac,
                  last_username, last_ssid, last_ap, last_site_id, updated_at
           FROM clients WHERE org_id = ? ORDER BY mac""",
        (org_id,),
    )
    try:
        async for row in cursor:
            yield row
    finally:
        await cursor.close()


CLIENT_EXPORT_COLUMNS: tuple[str, ...] = (
    "mac", "family", "manufacturer", "model", "os", "random_mac",
    "last_username", "last_ssid", "last_ap", "last_site_id", "updated_at",
)


async def get_service_account_usernames(
    org_id: str, min_count: int
) -> dict[str, dict]:
    """
    Return normalized usernames that qualify as service accounts based on the
    clients table (MACs are unique org-wide so grouping by normalized username
    is an org-wide count).

    A username qualifies when ``min_count`` or more distinct client rows in the
    org share the same case-insensitive / whitespace-stripped value.

    Return shape: {normalized_username: {"label": display_label, "mac_count": N}}
    The display_label is the most common original-case variant seen among the
    rows — used when building the family name ``{label}.service_account``.
    """
    if not org_id or min_count <= 0:
        return {}
    conn = await get_connection()
    rows = await conn.execute_fetchall(
        """SELECT last_username_norm, last_username, COUNT(*) AS cnt
           FROM clients
           WHERE org_id = ?
             AND last_username_norm IS NOT NULL
             AND last_username_norm != ''
           GROUP BY last_username_norm, last_username""",
        (org_id,),
    )
    # Collapse variants per normalized key and pick the most common original.
    grouped: dict[str, dict[str, int]] = {}
    for norm, original, cnt in rows:
        key = norm or ""
        if not key:
            continue
        bucket = grouped.setdefault(key, {})
        bucket[original or key] = bucket.get(original or key, 0) + int(cnt)

    result: dict[str, dict] = {}
    for norm, variants in grouped.items():
        total = sum(variants.values())
        if total < min_count:
            continue
        label = max(variants.items(), key=lambda kv: kv[1])[0]
        result[norm] = {"label": label, "mac_count": total}
    return result


async def search_clients_by_mac_prefix(
    mac_prefix: str,
    org_id: Optional[str] = None,
    limit: int = 50,
) -> list[dict]:
    """
    Prefix-match against the clients table by MAC address, then enrich each hit
    with the most-recent event site_id / wlan / timestamp from the events table.

    The search is deliberately prefix-only (``LIKE 'prefix%'``) because:

    - ``clients.mac`` is the PRIMARY KEY, so a leading-anchored LIKE uses the PK
      index for a range scan -- O(log n + results) instead of a full table scan.
    - ``events.idx_events_mac`` covers the per-result recency lookup in O(log n).

    The caller is responsible for normalising the input (stripping colons /
    hyphens / whitespace and lowercasing); this helper normalises defensively
    but expects canonical hex already.

    Args:
      mac_prefix: normalised MAC fragment (hex-only, lowercase). Must be
        non-empty -- an empty prefix would scan every row and is rejected.
      org_id: when set, restrict results to a specific org. When omitted, all
        orgs in the table are searched (single-org deployments are the common
        case, so this is usually unnecessary).
      limit: maximum number of rows returned from the clients table. The
        per-result events lookup runs once per row returned, so the effective
        cost is O((log n) * limit).

    Returns:
      List of dicts sorted by most-recent event first (rows with no events in
      the retention window sort to the end). Each dict carries::

        {
          "mac": "aabbccddee01",
          "family": "MacBook",
          "manufacturer": "Apple",
          "last_username": "srv_Apple_EP",
          "last_site_id": "abc-123",        # from clients (daily refresh)
          "last_event_site_id": "abc-123",  # from events (retention window)
          "last_event_wlan": "Corp-WiFi",
          "last_event_ts": 1775014952.642,
          "event_count": 142,
        }
    """
    # Defensive normalisation — canonical hex only, max 12 chars (full MAC).
    norm = re.sub(r"[^0-9a-f]", "", (mac_prefix or "").lower())
    if not norm:
        return []
    norm = norm[:12]

    conn = await get_connection()

    # Primary lookup — leading-anchored LIKE uses the clients.mac PRIMARY KEY.
    like_pattern = f"{norm}%"
    if org_id:
        rows = await conn.execute_fetchall(
            """SELECT mac, family, manufacturer, last_username, last_site_id
               FROM clients
               WHERE org_id = ? AND mac LIKE ?
               ORDER BY mac
               LIMIT ?""",
            (org_id, like_pattern, int(limit)),
        )
    else:
        rows = await conn.execute_fetchall(
            """SELECT mac, family, manufacturer, last_username, last_site_id
               FROM clients
               WHERE mac LIKE ?
               ORDER BY mac
               LIMIT ?""",
            (like_pattern, int(limit)),
        )

    if not rows:
        return []

    # Per-row enrichment — most-recent event site/wlan/ts and count in window.
    cutoff = time.time() - EVENTS_RETENTION_SECONDS
    results: list[dict] = []
    for row in rows:
        mac = row[0]
        recent = await conn.execute_fetchall(
            """SELECT site_id, wlan, timestamp
               FROM events
               WHERE mac = ? AND timestamp >= ?
               ORDER BY timestamp DESC
               LIMIT 1""",
            (mac, cutoff),
        )
        count_row = await conn.execute_fetchall(
            "SELECT COUNT(*) FROM events WHERE mac = ? AND timestamp >= ?",
            (mac, cutoff),
        )
        event_count = int(count_row[0][0]) if count_row else 0

        if recent:
            last_event_site_id = recent[0][0] or ""
            last_event_wlan = recent[0][1] or ""
            last_event_ts = float(recent[0][2]) if recent[0][2] is not None else None
        else:
            last_event_site_id = ""
            last_event_wlan = ""
            last_event_ts = None

        results.append({
            "mac": mac,
            "family": row[1] or "",
            "manufacturer": row[2] or "",
            "last_username": row[3] or "",
            "last_site_id": row[4] or "",
            "last_event_site_id": last_event_site_id,
            "last_event_wlan": last_event_wlan,
            "last_event_ts": last_event_ts,
            "event_count": event_count,
        })

    # Sort: most-recent event first; rows with no events in the window go last.
    results.sort(
        key=lambda r: (r["last_event_ts"] is None, -(r["last_event_ts"] or 0.0))
    )
    return results


async def search_families_by_prefix(
    prefix: str,
    org_id: Optional[str] = None,
    limit: int = 50,
) -> list[dict]:
    """
    Substring-match device family names in the events table (within the
    retention window) and return each matching family with its distinct MAC
    count.

    Counting from events rather than the clients table ensures the number
    shown in the autocomplete dropdown matches what the all-WLANs drilldown
    will actually display — only MACs with recent events, not the full
    client cache (which includes MACs that haven't been seen in weeks).

    Matching is case-insensitive and unanchored (``LIKE '%prefix%'``) so the
    operator can type any distinctive chunk of a composite family name such
    as ``"MacBook"`` to find ``"Apple | MacBook Pro | macOS 14"``.

    Returns a list of ``{"family": str, "mac_count": int}`` dicts sorted by
    ``mac_count`` descending so the most populous matches land at the top of
    the autocomplete.
    """
    norm = (prefix or "").strip().lower()
    if len(norm) < 2:
        return []

    conn = await get_connection()
    cutoff = time.time() - EVENTS_RETENTION_SECONDS
    like_pattern = f"%{norm}%"

    if org_id:
        rows = await conn.execute_fetchall(
            """SELECT device_family, COUNT(DISTINCT mac) AS mac_count
               FROM events
               WHERE org_id = ? AND timestamp >= ?
                 AND device_family IS NOT NULL AND device_family != ''
                 AND LOWER(device_family) LIKE ?
               GROUP BY device_family
               ORDER BY mac_count DESC, device_family ASC
               LIMIT ?""",
            (org_id, cutoff, like_pattern, int(limit)),
        )
    else:
        rows = await conn.execute_fetchall(
            """SELECT device_family, COUNT(DISTINCT mac) AS mac_count
               FROM events
               WHERE timestamp >= ?
                 AND device_family IS NOT NULL AND device_family != ''
                 AND LOWER(device_family) LIKE ?
               GROUP BY device_family
               ORDER BY mac_count DESC, device_family ASC
               LIMIT ?""",
            (cutoff, like_pattern, int(limit)),
        )

    return [{"family": row[0], "mac_count": int(row[1])} for row in rows]


async def delete_clients_for_org(org_id: str) -> int:
    """Delete all client records for an org. Returns row count deleted."""
    conn = await get_connection()
    cursor = await conn.execute("DELETE FROM clients WHERE org_id = ?", (org_id,))
    await conn.execute("DELETE FROM client_refresh_log WHERE org_id = ?", (org_id,))
    await conn.commit()
    return cursor.rowcount


# ---------------------------------------------------------------------------
# Client summary (per-device materialised rollup for drilldowns)
# ---------------------------------------------------------------------------

# Column order used by both the INSERT and the row-dict adapter below.
_CLIENT_SUMMARY_COLS: tuple[str, ...] = (
    "mac", "site_id", "wlan", "org_id",
    "device_family", "device_model", "device_manufacturer", "device_os",
    "last_username", "service_account_family", "random_mac",
    "health_score", "if_score", "centroid_dist_score", "dbscan_label",
    "is_if_outlier", "is_dbscan_outlier", "is_family_outlier",
    "is_markov_outlier", "markov_reason", "service_alarm",
    "total_events",
    "dhcp_success", "dhcp_failure",
    "dns_success", "dns_failure",
    "auth_success", "auth_failure",
    "roam_success", "roam_failure",
    "disassoc_ap", "disassoc_client",
    "arp_success", "arp_failure",
    "captive_portal", "security", "collaboration", "other",
    "first_seen", "last_seen", "built_at",
)


async def upsert_client_summaries(rows: list[dict]) -> int:
    """
    Bulk-upsert per-(mac, site_id, wlan) summary rows.

    Each row dict must carry the keys in ``_CLIENT_SUMMARY_COLS``; missing
    keys default to ``None``. Uses ``INSERT OR REPLACE`` so the primary key
    upsert is idempotent — callers following the truncate-and-rebuild pattern
    (see ``delete_client_summaries_for_scope``) will typically have emptied
    the scope first.

    Returns number of rows written.
    """
    if not rows:
        return 0
    conn = await get_connection()
    placeholders = ", ".join("?" * len(_CLIENT_SUMMARY_COLS))
    col_list = ", ".join(_CLIENT_SUMMARY_COLS)
    tuples = [tuple(r.get(c) for c in _CLIENT_SUMMARY_COLS) for r in rows]
    await conn.executemany(
        f"INSERT OR REPLACE INTO client_summary ({col_list}) VALUES ({placeholders})",
        tuples,
    )
    await conn.commit()
    return len(tuples)


async def delete_client_summaries_for_scope(site_id: str, wlan: str) -> int:
    """Delete every summary row for a single (site_id, wlan) scope."""
    conn = await get_connection()
    cursor = await conn.execute(
        "DELETE FROM client_summary WHERE site_id = ? AND wlan = ?",
        (site_id, wlan),
    )
    await conn.commit()
    return cursor.rowcount


async def delete_client_summaries_not_in(scopes: list[tuple[str, str]]) -> int:
    """
    Delete any summary row whose (site_id, wlan) is not in ``scopes``.

    Called at the tail of a detection cycle to drop rows for scopes that no
    longer have events (e.g. a WLAN was removed, or a site aged out of the
    retention window). Without this sweep, stale rows would persist and pollute
    drilldown results.
    """
    conn = await get_connection()
    if not scopes:
        cursor = await conn.execute("DELETE FROM client_summary")
        await conn.commit()
        return cursor.rowcount
    # Fetch every (site, wlan) currently present, delete the diff against `scopes`.
    # Scope count is O(sites * wlans) — low hundreds in practice — so a per-row
    # DELETE is fine and avoids the SQLite 999-variable cap on VALUES-based anti-joins.
    deleted = 0
    existing = await conn.execute_fetchall(
        "SELECT DISTINCT site_id, wlan FROM client_summary"
    )
    keep = {(s, w) for s, w in scopes}
    to_delete = [(s, w) for (s, w) in existing if (s, w) not in keep]
    for sid, w in to_delete:
        cursor = await conn.execute(
            "DELETE FROM client_summary WHERE site_id = ? AND wlan = ?",
            (sid, w),
        )
        deleted += cursor.rowcount
    await conn.commit()
    return deleted


def _row_to_summary_dict(row) -> dict:
    """Adapt an aiosqlite.Row from a SELECT * into a plain dict."""
    return {c: row[i] for i, c in enumerate(_CLIENT_SUMMARY_COLS)}


# Per-service SQL fragments that mirror computeMacServiceAlarms() in
# OrgFamilyDrilldown.jsx: a MAC has a service alarm when that service has any
# outcome-bearing events (success + failure > 0), at least one failure, and
# success/total < 0.5. Kept here so alarm-keyword filter tags ("auth", "dhcp"…)
# produce the same set of MACs the UI would have rendered under a client-side
# filter.
_SERVICE_ALARM_SQL: dict[str, str] = {
    "auth": (
        "(auth_success + auth_failure) > 0 AND auth_failure > 0 "
        "AND CAST(auth_success AS REAL) / (auth_success + auth_failure) < 0.5"
    ),
    "roam": (
        "(roam_success + roam_failure) > 0 AND roam_failure > 0 "
        "AND CAST(roam_success AS REAL) / (roam_success + roam_failure) < 0.5"
    ),
    "dhcp": (
        "(dhcp_success + dhcp_failure) > 0 AND dhcp_failure > 0 "
        "AND CAST(dhcp_success AS REAL) / (dhcp_success + dhcp_failure) < 0.5"
    ),
    "dns": (
        "(dns_success + dns_failure) > 0 AND dns_failure > 0 "
        "AND CAST(dns_success AS REAL) / (dns_success + dns_failure) < 0.5"
    ),
    "arp": (
        "(arp_success + arp_failure) > 0 AND arp_failure > 0 "
        "AND CAST(arp_success AS REAL) / (arp_success + arp_failure) < 0.5"
    ),
}


def _filter_tag_clause(tag: dict) -> tuple[str, list]:
    """
    Turn one resolved filter tag into a WHERE sub-clause.

    ``tag`` shape::

        {"text": "<lowercase user input>", "site_ids": [<optional>]}

    Routes are responsible for pre-resolving site-name matches into ``site_ids``
    via the Mist sites map; db.py stays pure-SQL and never touches Redis.

    Semantics match the frontend haystack in OrgFamilyDrilldown.jsx: each tag
    is OR-matched across mac / device_family / last_username / wlan / site_id,
    plus the service-alarm keyword shortcuts (``auth``, ``roam``, ``dhcp``,
    ``dns``, ``arp``) and the bare literal ``alarm`` (any service alarm). All
    tags are AND-combined by the caller.
    """
    text = tag["text"]
    like = f"%{text}%"
    ors: list[str] = [
        "LOWER(mac) LIKE ?",
        "LOWER(COALESCE(device_family, '')) LIKE ?",
        "LOWER(COALESCE(last_username, '')) LIKE ?",
        "LOWER(COALESCE(wlan, '')) LIKE ?",
    ]
    params: list = [like, like, like, like]

    site_ids = tag.get("site_ids") or []
    if site_ids:
        placeholders = ",".join("?" * len(site_ids))
        ors.append(f"site_id IN ({placeholders})")
        params.extend(site_ids)

    if text == "alarm":
        ors.append("service_alarm = 1")
    svc_sql = _SERVICE_ALARM_SQL.get(text)
    if svc_sql:
        ors.append(f"({svc_sql})")

    return "(" + " OR ".join(ors) + ")", params


def _summary_where(
    *,
    family_exact: Optional[str] = None,
    family_substring: Optional[str] = None,
    wlan: Optional[str] = None,
    site_id: Optional[str] = None,
    service_account_family: Optional[str] = None,
    manufacturer_exact: Optional[str] = None,
    last_username: Optional[str] = None,
    mac_prefix: Optional[str] = None,
    filter_tags: Optional[list[dict]] = None,
) -> tuple[str, list]:
    """Build a WHERE clause + param list for client_summary queries.

    ``filter_tags`` is an optional list of resolved tag dicts (see
    ``_filter_tag_clause``); each tag's internal OR-block is AND-joined with
    every other filter. Keeping the structural filters (``family_exact``,
    ``wlan``, etc.) separate from the free-text tag filters means scope-defining
    params still use indexed equality predicates while tags layer on top.
    """
    conditions: list[str] = []
    params: list = []
    if family_exact is not None:
        conditions.append("device_family = ?")
        params.append(family_exact)
    if family_substring is not None:
        conditions.append("LOWER(device_family) LIKE ?")
        params.append(f"%{family_substring.lower()}%")
    if wlan is not None:
        conditions.append("wlan = ?")
        params.append(wlan)
    if site_id is not None:
        conditions.append("site_id = ?")
        params.append(site_id)
    if service_account_family is not None:
        conditions.append("service_account_family = ?")
        params.append(service_account_family)
    if manufacturer_exact is not None:
        conditions.append("device_manufacturer = ?")
        params.append(manufacturer_exact)
    if last_username is not None:
        conditions.append("last_username = ?")
        params.append(last_username)
    if mac_prefix is not None:
        # Leading-anchored LIKE hits idx_summary_mac as a range scan.
        conditions.append("mac LIKE ?")
        params.append(f"{mac_prefix.lower()}%")
    for tag in filter_tags or []:
        clause, tag_params = _filter_tag_clause(tag)
        conditions.append(clause)
        params.extend(tag_params)
    where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
    return where, params


async def query_client_summary(
    *,
    family_exact: Optional[str] = None,
    family_substring: Optional[str] = None,
    wlan: Optional[str] = None,
    site_id: Optional[str] = None,
    service_account_family: Optional[str] = None,
    manufacturer_exact: Optional[str] = None,
    last_username: Optional[str] = None,
    mac_prefix: Optional[str] = None,
    filter_tags: Optional[list[dict]] = None,
    limit: Optional[int] = None,
    offset: Optional[int] = None,
    order_by: Optional[str] = None,
) -> list[dict]:
    """
    Query the client_summary table with optional filters.

    - ``family_exact``: exact match on device_family (used by the WLAN-scoped
      drilldown when the UI passes a single family).
    - ``family_substring``: case-insensitive substring match on device_family
      (used by the search-drilldown substring endpoint).
    - ``wlan`` / ``site_id``: scope filters.
    - ``service_account_family`` / ``last_username``: back the service-account
      drilldown and future per-username filters.
    - ``filter_tags``: list of resolved free-text tag dicts from the drilldown
      UI filter box — see ``_filter_tag_clause`` for the per-tag match semantics.
    - ``limit``: optional row cap.
    - ``offset``: skip this many rows (used with ``limit`` for pagination).
    - ``order_by``: raw SQL ORDER BY clause (e.g. ``"if_score ASC"``).

    Returns a list of dicts, one per row, keyed by ``_CLIENT_SUMMARY_COLS``.
    """
    where, params = _summary_where(
        family_exact=family_exact, family_substring=family_substring,
        wlan=wlan, site_id=site_id, service_account_family=service_account_family,
        manufacturer_exact=manufacturer_exact,
        last_username=last_username, mac_prefix=mac_prefix,
        filter_tags=filter_tags,
    )

    order_sql = f" ORDER BY {order_by}" if order_by else ""
    limit_sql = f" LIMIT {int(limit)}" if limit is not None else ""
    offset_sql = f" OFFSET {int(offset)}" if offset is not None else ""
    # Explicit column list (not SELECT *) so positional hydration in
    # _row_to_summary_dict stays correct even after ALTER TABLE has appended
    # columns to the physical table in a different order.
    col_list = ", ".join(_CLIENT_SUMMARY_COLS)
    sql = f"SELECT {col_list} FROM client_summary{where}{order_sql}{limit_sql}{offset_sql}"

    conn = await get_connection()
    rows = await conn.execute_fetchall(sql, params)
    return [_row_to_summary_dict(r) for r in rows]


async def count_client_summary(
    *,
    family_exact: Optional[str] = None,
    family_substring: Optional[str] = None,
    wlan: Optional[str] = None,
    site_id: Optional[str] = None,
    service_account_family: Optional[str] = None,
    manufacturer_exact: Optional[str] = None,
    last_username: Optional[str] = None,
    mac_prefix: Optional[str] = None,
    filter_tags: Optional[list[dict]] = None,
) -> dict:
    """
    Return aggregate counts for a client_summary query without fetching rows.

    Returns ``{total, if_outlier, dbscan_outlier, markov_outlier, families}``
    where ``families`` is a sorted list of distinct device_family values.
    """
    where, params = _summary_where(
        family_exact=family_exact, family_substring=family_substring,
        wlan=wlan, site_id=site_id, service_account_family=service_account_family,
        manufacturer_exact=manufacturer_exact,
        last_username=last_username, mac_prefix=mac_prefix,
        filter_tags=filter_tags,
    )

    conn = await get_connection()
    row = (await conn.execute_fetchall(
        f"SELECT COUNT(*), "
        f"SUM(CASE WHEN is_if_outlier THEN 1 ELSE 0 END), "
        f"SUM(CASE WHEN is_dbscan_outlier THEN 1 ELSE 0 END), "
        f"SUM(CASE WHEN is_markov_outlier THEN 1 ELSE 0 END) "
        f"FROM client_summary{where}",
        params,
    ))[0]

    family_rows = await conn.execute_fetchall(
        f"SELECT DISTINCT device_family FROM client_summary{where} "
        f"ORDER BY device_family",
        params,
    )

    return {
        "total": row[0] or 0,
        "if_outlier": row[1] or 0,
        "dbscan_outlier": row[2] or 0,
        "markov_outlier": row[3] or 0,
        "families": [r[0] for r in family_rows if r[0]],
    }


# ---------------------------------------------------------------------------
# Misc org helpers
# ---------------------------------------------------------------------------


async def has_org_client_cache(org_id: str) -> bool:
    """Check if a client cache has been written for an org (even if empty)."""
    conn = await get_connection()
    rows = await conn.execute_fetchall(
        "SELECT 1 FROM client_refresh_log WHERE org_id = ? LIMIT 1",
        (org_id,),
    )
    return len(rows) > 0
