# Project Sasquatch — Client Anomaly Detection Module
## CLAUDE.md — Implementation Guide

This file provides full context for implementing the Client Anomaly Detection sub-module
of Project Sasquatch. Read this entirely before writing any code.

---

## What This Module Does

Detects anomalous client behavior across every site in a Juniper Mist org by:
1. Building an org-wide client device database (MAC → device metadata), refreshed daily.
   The cache is org-scoped: MAC addresses uniquely identify clients across the entire
   organization, so a single lookup table serves every site. Persisted in the SQLite
   `clients` table.
2. Pulling client events from the org events endpoint over a rolling window — manual
   full collects fetch the last 12 hours, hourly polls top up the trailing 1 hour.
   Events are streamed to SQLite in batches and enriched with device metadata at
   write time.
3. Engineering per-MAC behavioral feature vectors. Each MAC carries TWO vectors:
   an `event_vector` (~59-dim normalized per-event-type frequency distribution,
   fed to IF and Centroid distance) and a `category_vector` (~15-dim semantic
   buckets + 2 concentration features, fed to DBSCAN, the health scorer, and
   the human-readable explainer). See `feature_engineer.py` for the full design.
4. Running a four-stage ML detection pipeline (see `anomaly_detector.py`):
   - **Stage 1 — DBSCAN** (population-wide): flags MACs that don't cluster with any
     peer group. `min_samples` and `eps` are auto-tuned per run from the population
     size — `min_samples = max(3, n_clients * pct)` and `eps` is the k-distance
     elbow. Only one operator knob (`anomaly_dbscan_min_samples_pct`).
   - **Stage 2 — Family Centroid Distance**: flags entire device families whose
     L2-normalized centroid sits far (cosine distance) from a healthy-family
     reference centroid built from families with mean health ≥
     `ANOMALY_CENTROID_HEALTHY_REF_THRESHOLD`.
   - **Stage 3 — Isolation Forest** (per device family): flags individual MACs
     anomalous within their family. Families below `MIN_PEERS` borrow MACs from
     other org sites for the same family.
   - **Stage 4 — Markov Chain** (see `markov_analyzer.py`): scores event-transition
     sequences within episodes against a 24hr site baseline and runs a
     baseline-independent stuck-loop detector that anchors each episode to its
     opening AP. Per-MAC `markov_reason` collapses to `anomaly` (anomalous chain
     transitions) or `repeated` (stuck failure loop). Families are flagged when
     ≥ `MARKOV_FAMILY_OUTLIER_RATIO` of *total family MACs* carry either reason.
5. Computing a separate per-family **Health Score** (see `health_scorer.py`): mean of
   per-MAC failure rates across AUTH, ROAM, DHCP, DNS, and ARP — independent of the
   anomaly pipeline.
6. Rolling up MAC-level anomalies to device-family findings, both per-site and
   org-wide (cross-site scoring runs once per WLAN over the combined org population).
7. Exposing findings via a React + FastAPI dashboard. Dashboard read endpoints serve
   pre-computed aggregates from a Redis summary cache rebuilt at the tail of every
   detection cycle (see `summary_cache.py`).
8. Firing a webhook when a device family qualifies via **either** the inter-family
   centroid detector (`is_family_outlier`, independently sufficient) **or** the
   DBSCAN-or-Markov rollup gate (the per-MAC union of `is_dbscan_outlier` and
   `is_markov_outlier` reaches `ALARM_DBSCAN_MARKOV_RATIO` of total family clients)
   **and** is unhealthy (health score below threshold or service-alarm device
   percentage met) **and** is at least `ALARM_MIN_FAMILY_SIZE` MACs.

**This module has NO LLM in the detection path.** Pure ML + rule-based only.
Client event data must not egress to third-party providers. Do not add any LLM calls
or external service calls (SendGrid, Anthropic, OpenAI, etc.) to any code path that
touches client events. The only external services this module talks to are the Mist
API (events + client cache + Marvis TSHOOT enrichment) and the configured webhook
target.

---

## Why This Exists (Problem Statement)

Mist SLEs are aggregate metrics — they smooth over edge cases. This module is designed
to catch things SLEs miss, such as:

- A client OS discarding DHCP offers → client loops on DHCP_SUCCESS with no connectivity
- A client holding a stale PMKID → repeated 11r-FBT roam failures
- A device type (e.g., all HP printers at a site) silently failing DNS
- A specific client model with a firmware bug causing repeated SAE auth failures

The detection strategy: we need to detect anomalies between device groups and flag if a small-yet-critical subset of the client population is unhappy. We don't want to alert for a full failure - the dashboard already handles that - but we need to flag device anomalies using health scores and unsupervised learning techniques.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | FastAPI (Python) |
| Frontend | React (Vite) |
| Persistent storage | SQLite via `aiosqlite` (events, clients, alert sessions) |
| Derived state cache | Redis (features, anomalies, findings, health, summary cache, locks) |
| Scheduling | APScheduler (in-process) |
| ML | scikit-learn (IsolationForest, DBSCAN, PCA, NearestNeighbors) |
| Feature Engineering | pandas, numpy |
| Mist API Client | httpx (async) |
| Alerting | httpx webhook POST (configurable target) |
| Configuration | env vars + per-key GUI overrides in `config_overrides.json` |

**Storage split** — SQLite is the system of record for everything that must
survive a Redis flush or restart: client events (7-day retention), the
org-wide client cache, alert session history. Redis holds derived state with
TTLs (feature vectors, anomaly scores, findings, health scores, the
dashboard summary cache), plus operational primitives (the global pipeline
mutex and progress keys). When in doubt: if losing it would be a real data
loss, it lives in SQLite; if losing it would just trigger a recompute, it
lives in Redis.

**No LLM, no third-party data egress.** Client event data must not be sent
to any external provider. This module deliberately does NOT use SendGrid,
the Anthropic SDK, or any other external service beyond the Mist API and
the configured webhook target. See "What NOT to Build" at the bottom of
this file.

Match existing patterns in the codebase where they exist.

---

## Known Issues & Backlog

See [TODO.md](TODO.md) for tracked issues, improvement notes, and technical debt.
Update it when you identify new problems or resolve existing ones.

---

## Project Structure

```
sasquatch/
├── client_anomaly/
│   ├── __init__.py
│   ├── db.py                    # SQLite schema, migrations, async access layer (events + clients tables)
│   ├── config.py                # env + config_overrides.json resolution; single source of truth for tunables
│   ├── client_cache.py          # Daily org-wide client list refresh → SQLite
│   ├── event_collector.py       # Streaming event pull (12hr full / 1hr poll) + MAC enrichment → SQLite (batched flushes)
│   ├── feature_engineer.py      # Per-MAC feature vector construction
│   ├── anomaly_detector.py      # Four-stage ML pipeline (DBSCAN/IF/Markov) + finding rollup
│   ├── markov_analyzer.py       # Markov Chain episode analysis (Stage 4)
│   ├── health_scorer.py         # Per-family health score (separate from anomaly pipeline)
│   ├── webhook_dispatcher.py    # Dual-gate alert dispatch (anomaly + health)
│   ├── alert_tracker.py         # Persistent alert session history (7-day, per-site)
│   ├── client_summary_builder.py # Materialised per-(mac, site, wlan) summary table builder (Phase 5b)
│   ├── summary_cache.py         # Pre-computed dashboard aggregates (org/site overview, alerts, findings)
│   ├── scheduler.py             # APScheduler job definitions
│   └── api/
│       ├── __init__.py
│       └── routes.py            # FastAPI route definitions
├── frontend/
│   └── src/
│       ├── components/
│       │   ├── SiteOverview.jsx         # Heatmap: event categories × device types + health column
│       │   ├── OrgOverview.jsx          # Org four-tab shell: Org Alerts (default), Org Overview, Org Family Insights, Findings
│       │   ├── OrgAlerts.jsx            # Default org view: org-wide + per-site dual-gate alerts with family drilldown
│       │   ├── OrgFamilyInsights.jsx    # Org-wide family heatmap + health column
│       │   ├── FindingsFeed.jsx         # Site findings: IF CENTROID → DBSCAN % → MARKOV % → HEALTH sections
│       │   ├── OrgFindingsFeed.jsx      # Org findings: same detector-section layout, family name drills down to OrgFamilyDrilldown
│       │   └── MacDrilldown.jsx         # Per-MAC 24hr timeline + feature breakdown
│       └── App.jsx
├── .env                         # See env vars section below
└── CLAUDE.md                    # This file
```

---

## SQLite Schema

SQLite is the system of record for client events and the org-wide client
cache. Lives at `sasquatch/client_anomaly/sasquatch.db` (configurable via
`SASQUATCH_DB_PATH`). All access goes through `db.py`, which holds a
single shared `aiosqlite` connection and runs lightweight forward-only
migrations on startup.

**`events` table** — every Mist client event collected for any site, with
the enriched device metadata attached at write time:

```sql
CREATE TABLE events (
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
CREATE INDEX idx_events_site_ts ON events(site_id, timestamp);
CREATE INDEX idx_events_mac ON events(mac, timestamp);
CREATE INDEX idx_events_org_ts ON events(org_id, timestamp);
CREATE INDEX idx_events_wlan ON events(site_id, wlan);
```

The `UNIQUE(mac, event_type, timestamp, bssid)` constraint makes inserts
idempotent: re-collecting an overlapping window is a safe no-op. Retention
is 7 days, enforced by `db.purge_old_events()` running daily at 03:00.

**`clients` table** — org-scoped client cache, one row per MAC across the
entire org. Refreshed daily by `client_cache.refresh_client_cache_org()`:

```sql
CREATE TABLE clients (
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
CREATE INDEX idx_clients_org ON clients(org_id);
CREATE INDEX idx_clients_family ON clients(family);
CREATE INDEX idx_clients_last_site ON clients(last_site_id);
CREATE INDEX idx_clients_username_norm ON clients(last_username_norm);
```

`mac` is the natural primary key — MACs are unique across the org, so a
single row serves every site. `last_site_id` is the most recent site Mist
saw the client at and is what `/sites/{site_id}/clients` filters on.
`last_username` / `last_username_norm` back the service-account virtual
families (see "Service-Account Virtual Families" below).

**`client_refresh_log` table** — a one-row-per-org bookkeeping table:

```sql
CREATE TABLE client_refresh_log (
    org_id TEXT PRIMARY KEY,
    refreshed_at REAL NOT NULL,
    client_count INTEGER NOT NULL DEFAULT 0
);
```

Used by the daily `client_refresh_job` to expose "last refreshed" in the
admin UI and by the event collector startup check (the cache must have
been written at least once before any collect runs).

**`client_summary` table** — per-(mac, site_id, wlan) materialised rollup
rebuilt each detection cycle by `client_summary_builder.py`. Backs the
Device Family Drilldown and Device Family Search endpoints, replacing the
previous O(n) full-event-table scan with an indexed SQLite SELECT.

```sql
CREATE TABLE client_summary (
    mac TEXT NOT NULL,
    site_id TEXT NOT NULL,
    wlan TEXT NOT NULL,
    org_id TEXT NOT NULL DEFAULT '',

    device_family TEXT,
    device_model TEXT,
    device_manufacturer TEXT,
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
    disassoc INTEGER DEFAULT 0,
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

CREATE INDEX idx_summary_family ON client_summary(device_family);
CREATE INDEX idx_summary_family_wlan ON client_summary(device_family, wlan);
CREATE INDEX idx_summary_site_wlan ON client_summary(site_id, wlan);
CREATE INDEX idx_summary_health ON client_summary(health_score);
CREATE INDEX idx_summary_username ON client_summary(last_username);
CREATE INDEX idx_summary_sa_family ON client_summary(service_account_family);
CREATE INDEX idx_summary_mac ON client_summary(mac);
```

Rebuild strategy: truncate-and-rebuild per `(site_id, wlan)` each detection
cycle in Phase 5b. After rebuilding all active scopes, stale rows for scopes
no longer in the events table are swept. The table is never read during
detection — only by the drilldown API routes.

**Migrations** — `db._init_schema()` runs all `CREATE TABLE IF NOT EXISTS`
DDL on startup, then runs forward-only migration helpers
(`_migrate_clients_to_org_scope`, `_migrate_clients_add_last_username`)
that detect missing columns/indexes via `PRAGMA table_info` and apply
in-place `ALTER TABLE`. There is no migration framework — keep
migrations idempotent and additive.

**Public API in `db.py`** (all async unless noted):
- Events: `insert_events`, `get_events`, `get_event_count`, `get_wlans`,
  `get_site_ids_with_events`, `reenrich_events`, `delete_events_for_site`,
  `purge_old_events`
- Clients: `upsert_clients_org`, `get_org_client_cache`,
  `has_org_client_cache`, `search_clients_by_mac_prefix`,
  `delete_clients_for_org`, `get_service_account_usernames`,
  `normalize_username` (sync)
- Client summary: `upsert_client_summaries`, `delete_client_summaries_for_scope`,
  `delete_client_summaries_not_in`, `query_client_summary`

---

## Redis Key Schema

| Key | TTL | Contents |
|---|---|---|
| _(client cache lives in SQLite — see SQLite Schema above)_ | — | Stored in the `clients` table, org-scoped, MAC PRIMARY KEY |
| _(events live in SQLite — see SQLite Schema above)_ | — | Stored in the `events` table, 7-day retention purged by `db.purge_old_events` |
| _(wlans derived from SQLite events table on demand)_ | — | `db.get_wlans(site_id)` issues `SELECT DISTINCT wlan` against the events table |
| `sasquatch:event_type_index` | 7 days | JSON array: ordered list of known Mist client event type strings |
| `sasquatch:features:{site_id}:{wlan_key}` | 24hr | JSON dict: MAC → feature vector dict |
| `sasquatch:anomalies:{site_id}:{wlan_key}` | 24hr | JSON dict: MAC → {if_score, dbscan_label, is_outlier, is_family_outlier, is_markov_outlier, markov_episode_anomaly_ratio, …} |
| `sasquatch:markov_baseline:{site_id}:{wlan_key}` | 48hr | JSON dict: {transition_counts, event_type_index, computed_at} |
| `sasquatch:health:{site_id}:{wlan_key}` | 24hr | JSON dict: family → {health_score, components, total_events, mac_count} |
| `sasquatch:findings:{site_id}:{wlan_key}` | 24hr | JSON array: rolled-up findings for GUI + webhook |
| `sasquatch:org_anomalies:{site_id}:{wlan_key}` | 24hr | JSON dict: per-MAC org-wide scores (written by `score_org_wide`) |
| `sasquatch:org_findings:{wlan_key}` | 24hr | JSON array: org-wide findings (one entry per device family across all sites) |
| `sasquatch:alert_active:{site_id}:{wlan_key}` | none (managed explicitly) | Hash: family → `{first_seen, last_seen}` for currently-active alert sessions |
| `sasquatch:alert_sessions` | none (pruned on write) | Sorted set: session keys scored by `first_seen` unix timestamp; entries older than 8 days are pruned each cycle |
| `sasquatch:alert_session:{session_key}` | 8 days | JSON: `{site_id, family, wlan, first_seen, last_seen, resolved_at, status}` for one alert session |
| `sasquatch:summary:org_summary:{wlan_key}` | 2hr | Pre-computed `/org/summary` response (see `summary_cache.py`) |
| `sasquatch:summary:org_findings:{wlan_key}` | 2hr | Pre-computed `/org/findings` response |
| `sasquatch:summary:org_alerts:{wlan_key}` | 2hr | Pre-computed `/org/alerts` response |
| `sasquatch:summary:org_alerts_full` | 2hr | Pre-computed `/org/alerts-full` response (cross-WLAN, no wlan dimension) |
| `sasquatch:summary:org_family_insights:{wlan_key}` | 2hr | Pre-computed `/org/family-insights` response |
| `sasquatch:summary:site_findings:{site_id}:{wlan_key}` | 2hr | Pre-computed `/sites/{id}/findings` response |
| `sasquatch:summary:site_health:{site_id}:{wlan_key}` | 2hr | Pre-computed `/sites/{id}/health` response |
| `sasquatch:summary:site_events_summary:{site_id}:{wlan_key}` | 2hr | Pre-computed `/sites/{id}/events/summary` response |

**TTL note:** Events are 7 days in SQLite (purged by `db.purge_old_events`). The
client cache has no TTL — it lives in SQLite under the `clients` table and is
overwritten in place by each daily refresh. Detection/scoring output keys
(features, anomalies, health, findings) remain 24hr in Redis.

**Client cache (SQLite, org-scoped):** Stored in the `clients` table keyed by
`mac TEXT PRIMARY KEY` with `org_id`, `family`, `model`, `os`, `manufacturer`,
`random_mac`, `last_ssid`, `last_ap`, `last_site_id`, and `updated_at` columns.
A single row per MAC across the entire org — the same MAC seen tomorrow at a
different site overwrites `last_site_id` on the next refresh. Use
`db.get_org_client_cache(org_id)` (one row per MAC) for the full org map, or
filter by `last_site_id` for a per-site view. The `client_refresh_log` table
records refresh timestamps keyed by `org_id`.

**Startup behavior:** If the org client cache is missing at startup, the event
collector must fail fast with a clear error — `_collect_org_streaming()` checks
`get_client_cache() is None` and raises. Do NOT silently make a redundant client
list API call from the event collector — the "Build Cache" path
(`_org_collect_background_task` Phase 1) and the daily `client_refresh_job` own
that responsibility.

---

## Module Specifications

### `config.py`

**Purpose:** Single source of truth for every tunable knob in the
detection pipeline. Every consumer reads through `config.get(section, key)`
or `config.get_section(section)` — no module reads `os.getenv` directly
for an anomaly setting.

**Resolution order (first match wins):**
1. `config_overrides.json` (per-key GUI overrides, persisted across restarts)
2. Environment variable (e.g. `ANOMALY_IF_CONTAMINATION`)
3. Hardcoded default in the `DEFAULTS` dict

The override file lives at
`sasquatch/client_anomaly/config_overrides.json` and is read on every
`get()` call (no in-process caching), so admin changes from the GUI take
effect immediately on the next pipeline run without a service restart.
Config changes do **not** invalidate the dashboard summary cache —
threshold changes only take effect on the next detection cycle, when the
cache is rebuilt.

**Sections:** `general`, `anomaly`, `markov`, `health`, `webhook`. Each
section in `DEFAULTS` declares a `{key: {default, env, cast}}` map that
the resolver uses to coerce types and validate.

**Public API:**
- `get(section, key) -> int | float | str` — single-key resolved value
- `get_section(section) -> dict` — full resolved section, used by the
  GET `/api/v1/anomaly-config` endpoint
- `get_section_defaults(section) -> dict` — hardcoded defaults only,
  used by validation bounds in the POST `/api/v1/anomaly-config` handler

When adding a new tunable: add it to `DEFAULTS`, expose it in the GUI
config panel, add validation bounds in `routes.set_anomaly_config`, and
update the smoke test in `scripts/smoke_test_config.py`.

---

### `db.py`

**Purpose:** Async SQLite access layer. Owns the schema (see "SQLite
Schema" above), runs forward-only migrations on startup, and exposes
typed read/write helpers for the `events`, `clients`, and
`client_refresh_log` tables.

**Connection model:** A single `aiosqlite` connection is shared across
the entire process via `db.get_connection()`. SQLite serializes writes,
so a single connection is the simplest correct model — no pool, no
per-request open/close. The connection is closed cleanly on app
shutdown via `db.close()`.

**Schema initialization:** `_init_schema()` runs all `CREATE TABLE IF
NOT EXISTS` and `CREATE INDEX IF NOT EXISTS` statements, then runs
forward-only migration helpers that detect missing columns/indexes via
`PRAGMA table_info` and apply in-place `ALTER TABLE`. There is no
migration framework — keep migrations idempotent and additive. Never
write a migration that drops or renames a column.

**Public API:** see "SQLite Schema" section above for the full list.
The most commonly used helpers from outside `db.py`:
- `get_events(site_id, wlan, since)` — flat list of enriched event
  dicts, used by feature engineering and the heatmap endpoints
- `get_org_client_cache(org_id)` — full org client map, used everywhere
  events are enriched and by all per-site client filtering
- `purge_old_events()` — daily retention job target, called by the
  `sqlite_retention_job` APScheduler entry

---

### `client_cache.py`

**Purpose:** Once-daily refresh of the org-wide client device lookup table. The
cache is org-scoped — MACs uniquely identify clients across the entire
organization, so a single API call populates the entire lookup table that every
site reads from.

**Mist API call:**
```
GET https://{MIST_CLOUD_HOST}/api/v1/orgs/{org_id}/clients/search?limit=1000
```

**Pagination — CRITICAL:** This endpoint uses cursor-based pagination, NOT page/offset.
After each response, check for a `next` field at the top level of the JSON. If present,
it contains a full relative URL. Prepend `https://{MIST_CLOUD_HOST}` and call it verbatim
— do NOT attempt to reconstruct or modify the URL. Loop until `next` is absent.

```python
async def fetch_all_clients_org(org_id: str, on_page=None) -> list[dict]:
    url = f"https://{MIST_CLOUD_HOST}/api/v1/orgs/{org_id}/clients/search?limit=1000"
    all_clients = []
    while url:
        resp = await httpx_client.get(url, headers=auth_headers)
        data = resp.json()
        all_clients.extend(data.get("results", []))
        next_path = data.get("next")
        url = f"https://{MIST_CLOUD_HOST}{next_path}" if next_path else None
    return all_clients
```

**Public API:**
- `refresh_client_cache_org(org_id, on_page=None) -> int` — fetches every client
  org-wide, classifies, and writes the entire org cache to SQLite. Returns the
  total client count. Always writes (even when the API returns zero clients) so
  callers can distinguish "cache populated but empty" from "cache never written".
- `get_client_cache() -> dict[str, dict] | None` — loads the entire org cache
  (one entry per MAC). Returns `None` if `refresh_client_cache_org()` has never
  run, `{}` if it ran but the org has zero clients, or the populated map.
  Reads `MIST_ORG_ID` from the environment — no per-site variant exists.

**Device family classification:** Families are built from a unique combination of
Manufacturer → Model → OS (major-version) when Mist provides the fingerprint, joined
with ` | `. Field count is preserved so 2-field composites stay distinct from 3-field
ones (e.g. `"Apple | MacBook Pro | macOS 14"` is a different family from
`"Apple | MacBook Pro"`). There are NO hardcoded patterns (`iPhone`, `MacBook`, etc.)
— those collapsed devices with different model revisions into a single family and
masked the per-revision signal the detector exists to find.

```python
def classify_family(client: dict) -> str:
    mfg    = _clean_token(client.get("mfg") or "")           # strips Inc/Ltd/Corp/...
    model  = _clean_token(client.get("last_model") or "")
    os_str = _os_major(client.get("last_os") or "")          # iOS 17.2.1 -> iOS 17
    if not model:
        model = _clean_token(client.get("last_device") or "")  # coarse type fallback

    parts = [p for p in (mfg, model, os_str) if p]
    return " | ".join(parts) if parts else "Unknown"
```

`_clean_token()` strips corporate suffixes (`Inc`, `Ltd`, `Corp`, `GmbH`, `LLC`,
`Technologies`, `Electronics`, `Company`, `Holdings`, `Systems`, etc.) so
`"Apple, Inc."`, `"Apple Inc"`, and `"Apple"` all collapse to `"Apple"`. It also
discards Mist placeholder tokens (`unknown`, `private`, `iot`, `embedded`, `other`,
`n/a`) so they never contaminate the family key.

`_os_major()` collapses OS strings to major-version granularity:
`"iOS 17.2.1"` → `"iOS 17"`, `"Windows 11.0.22631"` → `"Windows 11"`,
`"macOS 14.4"` → `"macOS 14"`. OS strings without a numeric version (`"iPadOS"`)
pass through unchanged.

**OUI fallback:** When Mist returns no manufacturer (or only a placeholder),
`_build_client_record()` runs an OUI lookup on the MAC's first 3 octets and injects
the result back into the client dict as `mfg` before `classify_family()` runs. So
OUI-derived devices land as single-token families (e.g. `"Awair"`) and Mist-fingerprinted
devices land as 2- or 3-field composites — both flow through the same code path.

**Output:** SQLite `clients` table, one row per MAC across the org. The shape
returned by `get_client_cache()` is:
```json
{
  "d67e8486da0b": {
    "family": "Apple",
    "model": "",
    "os": "Apple OS",
    "manufacturer": "Apple",
    "random_mac": true,
    "last_ssid": "Public",
    "last_ap": "a8f7d9818ea2",
    "last_site_id": "04edb3ac-542a-4d1d-ad90-b1e2fd682a67"
  }
}
```
`last_site_id` is the most recent site Mist saw the client at — used by
`/api/v1/sites/{site_id}/clients` to filter the org cache to a per-site view.

**Note on `model` field:** The `model` array is frequently empty even for known devices
(confirmed in real payload — Apple client with `model: []`). Do not depend on model
for family classification. `device` + `mfg` is more reliable.

**Schedule:** Daily at 00:00 via APScheduler.

---

### `event_collector.py`

**Purpose:** Pull client events from Mist over a rolling time window, enrich with
device metadata, store in SQLite (not Redis — events moved off Redis for capacity/
persistence).

**Mist API call:**
```
GET https://{MIST_CLOUD_HOST}/api/v1/orgs/{org_id}/clients/events?limit=1000
```

The org-level endpoint returns events across every site in one paginated stream;
each event carries its own `site_id`. Per-site collection has been retired —
all event ingest goes through this single org endpoint.

**Time window — explicit Unix timestamps:** Org collects pass `start` and `end` Unix
timestamps in the query string instead of a relative `duration=...`. The window is
anchored at the moment the collect was triggered, so retries and pagination latency
do not shift it. The relative `duration` parameter is still supported by `iter_events_org`
as a fallback when both timestamps are absent.

- `collect_org_full()` (manual "Collect Events" button → POST `/api/v1/org/collect-full`):
  fetches the **last 12 hours** (`end = now`, `start = now - 12*3600`).
- `collect_org()` (hourly poll job): fetches the **last 1 hour** (`end = now`,
  `start = now - 3600`).

**Pagination — GUARANTEED REQUIRED:** These endpoints will always require multiple pages
for any active org. Use cursor pagination: each response carries a `next` field with a
relative URL that must be used verbatim — the `search_after` parameter is a composite
cursor that cannot be reconstructed manually.

The `next` cursor format confirmed from real API response:
```
/api/v1/orgs/{org_id}/clients/events?end=...&limit=1000&search_after=[timestamp,+record_id,+seq]&start=...
```

**Streaming org paginator — `iter_events_org()`:** Implemented as an async generator
that yields raw event batches once the buffer reaches `batch_size` events. The caller
enriches and writes each batch to SQLite before the next batch is fetched. This bounds
memory usage regardless of total event count (9M+ seen in real deployments) and
preserves partial progress if the fetch fails mid-stream.

Two flush thresholds are defined and selected by the caller:
- `_ORG_FLUSH_BATCH_SIZE = 100_000` — used by `collect_org_full()` (12hr collect, multi-million-event runs)
- `_ORG_HOURLY_FLUSH_BATCH_SIZE = 25_000` — used by `collect_org()` (hourly poll); a typical hourly run is well under 100k events, so the default threshold would only flush once at the very end. The lower hourly threshold ensures even modest hourly volumes flush mid-stream and retain the partial-progress / memory-bounding benefits.

```python
async def iter_events_org(
    org_id: str,
    duration: str = "1h",
    batch_size: int = _ORG_FLUSH_BATCH_SIZE,
    on_page=None,
    start: int | None = None,
    end: int | None = None,
):
    if start is not None and end is not None:
        window_qs = f"start={int(start)}&end={int(end)}"
    else:
        window_qs = f"duration={duration}"
    url = f"https://{MIST_CLOUD_HOST}/api/v1/orgs/{org_id}/clients/events?limit=1000&{window_qs}"
    buffer: list[dict] = []
    async with httpx.AsyncClient(timeout=30.0) as client:
        while url:
            resp = await client.get(url, headers=auth_headers)
            resp.raise_for_status()
            data = resp.json()
            buffer.extend(data.get("results", []))
            await _check_rate_limit(resp, page, "org")
            next_path = data.get("next")
            url = f"https://{MIST_CLOUD_HOST}{next_path}" if next_path else None
            if len(buffer) >= batch_size:
                yield buffer
                buffer = []
    if buffer:
        yield buffer
```

`collect_org_full()` and `collect_org()` both delegate to `_collect_org_streaming()`,
which wraps the generator in a try/except: on failure it logs the row count already
persisted to SQLite, flushes unknown event types to Redis, and re-raises. The caller
always receives a `{site_id: rows_written}` dict reflecting actual DB state, never
a full in-memory buffer. `_collect_org_streaming()` accepts a `batch_size` parameter
that the hourly path overrides to `_ORG_HOURLY_FLUSH_BATCH_SIZE`.

`fetch_all_events_org()` is retained as a non-streaming wrapper around the generator
for any code path that genuinely needs the full list — avoid using it for org-wide
multi-hour collects.

**Hourly polling is opt-in (disabled by default).** The hourly `org_event_poll_job`
in `scheduler.py` gates on `sasquatch:event_polling_enabled`; a missing key counts
as disabled. The operator enables it explicitly via `POST /api/v1/org/polling`
once they are comfortable with the resource cost. Earlier revisions auto-enabled
the key after the first successful full collect, which led to the hourly poll
firing while a long-running manual collect/detect was still in flight under
constrained Docker memory limits — the auto-enable has been removed.

**Rate limit handling — `_check_rate_limit()`:** After every paginated response, the
helper checks `X-RateLimit-Remaining` / `X-RateLimit-Reset` headers and sleeps until
the reset window if remaining calls drop below `_RATE_LIMIT_RESERVE` (default 200).

**CRITICAL:** Mist does not reliably return rate limit headers on every endpoint. When
headers are absent, `_check_rate_limit()` falls back to a per-request throttle of 0.8s
(≈ 4500 req/hr, comfortably under the documented 5000/hr limit). On page 1 of every
paginated run the helper logs whichever `*ratelimit*`/`*retry*` headers the API is
sending, so any future header-name drift is immediately visible in the log.

The 0.8s fallback is intentional — a previous deployment hit a 429 after 8.2M events
fetched in ~90 minutes because headers were missing and no throttle was applied. Do
not remove the fallback without confirming Mist reliably returns `X-RateLimit-*` on
the org events endpoint.

**Enrichment:** For each event, look up `mac` in the org-wide client cache. Add fields:
- `device_family`
- `device_model`
- `device_manufacturer`

The cache is loaded **once** at the start of every collect via
`get_client_cache()` and threaded through every batch — `_collect_org_streaming`
loads it before pagination begins and passes the same map down through
`_flush_org_batch` → `_enrich_and_write_org_batch`. There is no per-site cache
fetch in the enrichment path. If `get_client_cache()` returns `None` the
collector raises immediately rather than silently triggering a refresh
mid-collect (a previous bug caused stuck-loops where every collect ran a
multi-thousand-page client search and then refetched events).

If MAC is not in client cache, attempt OUI lookup from the first 3 octets of the MAC
to get manufacturer. Set `device_family = "Unknown"`, `device_model = "Unknown"`.
Do not drop events for unknown MACs — they still contribute to site-wide DBSCAN.

**RSSI filter (all event types):** During enrichment, `_enrich_batch` drops any
event whose `rssi` is below `ANOMALY_RSSI_MIN_THRESHOLD` (default `-87`),
regardless of event type. At the RF fringe every outcome is unreliable —
successes may be racing retransmits, DHCP/DNS latencies inflate, and transient
failures cannot be distinguished from coverage artifacts. Events with
`rssi is None` (synthetic / boundary markers like `MARVIS_EVENT_STA_LEAVING`)
always pass through since they have no signal-strength to evaluate. The filter
is threaded through a `filter_stats` dict and a single INFO summary at end of
collect reports `weak_signal_skipped` counts. Set `ANOMALY_RSSI_MIN_THRESHOLD=-120`
(below the noise floor) to effectively disable the filter.

**Transmission-failure filter on auth events:** `_enrich_batch` also drops auth-family
events whose `status_code` is the radio-layer no-ack signal — the AP never received
the client's frame, so there is no actual auth decision against the device. The filter
covers two event types and the sign convention differs between them:

- `MARVIS_EVENT_CLIENT_AUTH_FAILURE` reports the code as **`-79`**
- `MARVIS_EVENT_CLIENT_MAC_AUTH_FAILURE` reports the same condition as **`+79`**

Both indicate poor RF coverage, not device-level auth behavior, and counting them as
auth failures inflates failure ratios and depresses health scores for devices in
marginal coverage. The mapping lives in `_TRANSMISSION_FAILURE_IGNORED` and is rendered
into the same end-of-collect summary line as the RSSI filter (`transmission_failure_skipped`).

**Event type reference:** The complete known Mist client event taxonomy (sourced from
`GET /api/v1/const/client_events`) contains 59 event types. Store this list at service
startup — it defines the dimensions of the frequency vector used for ML input.

```python
MIST_CLIENT_EVENT_TYPES = [
    # DHCP
    "CLIENT_IP_ASSIGNED",               # DHCP success
    "CLIENT_IPV6_ASSIGNED",             # DHCPv6 success
    "MARVIS_EVENT_CLIENT_DHCP_NAK",     # DHCP denied (server NAK)
    "MARVIS_EVENT_CLIENT_DHCPV6_NAK",   # DHCPv6 denied
    "MARVIS_EVENT_CLIENT_DHCP_FAILURE", # DHCP timed out
    "MARVIS_EVENT_CLIENT_DHCPV6_FAILURE",
    "MARVIS_EVENT_CLIENT_DHCP_STUCK",   # DHCP aborted
    "MARVIS_EVENT_CLIENT_DHCPV6_STUCK",
    "MARVIS_EVENT_CLIENT_FAILED_DHCP_INFORM",

    # DNS
    "CLIENT_DNS_OK",
    "MARVIS_DNS_FAILURE",

    # Initial auth / association
    "CLIENT_AUTHENTICATED",
    "CLIENT_AUTH_ASSOCIATION",
    "CLIENT_AUTH_ASSOCIATION_11R",
    "CLIENT_AUTH_ASSOCIATION_OKC",
    "MARVIS_EVENT_CLIENT_AUTH_FAILURE",
    "MARVIS_EVENT_CLIENT_AUTH_DENIED",
    "MARVIS_EVENT_CLIENT_MAC_AUTH_FAILURE",
    "CLIENT_ASSOCIATION",
    "CLIENT_ASSOCIATION_FAILURE",

    # Roam / reassociation (success)
    "CLIENT_AUTH_REASSOCIATION",        # Standard fast roam
    "CLIENT_AUTH_REASSOCIATION_11R",    # 11r reassociation
    "CLIENT_AUTH_REASSOCIATION_OKC",    # OKC reassociation
    "CLIENT_REASSOCIATION",             # Reassociation without new auth
    "CLIENT_REASSOCIATION_PMKC",        # PMKC reassociation

    # Roam / reassociation (failure)
    "MARVIS_EVENT_CLIENT_FBT_FAILURE",          # 11r FBT failure
    "MARVIS_EVENT_CLIENT_AUTH_FAILURE_OKC",     # OKC auth failure
    "MARVIS_EVENT_CLIENT_AUTH_FAILURE_11R",     # 11r auth failure
    "MARVIS_EVENT_WLC_FT_KEY_NOT_FOUND",        # 11r key lookup failure

    # Disassociation / deauth
    "CLIENT_DEASSOCIATION",
    "CLIENT_DEAUTHENTICATION",          # AP-initiated
    "CLIENT_DEAUTHENTICATED",           # Client-initiated
    "MARVIS_EVENT_STA_LEAVING",         # Clean roam departure (reason_code 8 = normal)

    # ARP / gateway
    "CLIENT_GW_ARP_OK",
    "CLIENT_GW_ARP_FAILURE",
    "CLIENT_ARP_FAILURE",
    "CLIENT_EXCESSIVE_ARPING_GW",       # Itself a flag — excessive ARP retries

    # Captive portal
    "MARVIS_EVENT_WXLAN_CAPTIVE_PORT_FLOW_REDIRECT",
    "HTTP_REDIR_PROCESSED",
    "MARVIS_EVENT_CAPTIVE_PORTAL_AUTHORIZED",
    "MARVIS_EVENT_CLIENT_WXLAN_POLICY_LOOKUP_FAILURE",

    # Security
    "DEFAULT_GATEWAY_SPOOFING_DETECTED",
    "MARVIS_EVENT_CLIENT_STATIC_IP_BLOCKED",

    # Collaboration (Zoom/Teams)
    "CLIENT_JOINED_CALL",
    "CLIENT_LEFT_CALL",
    "CLIENT_DISCONNECTED_FROM_CALL",
    "HIGH_CPU_OBSERVED",

    # Other
    "RADIUS_DAS_NOTIFY",
]
```

**Fetching at runtime:** This list can also be fetched live from
`GET /api/v1/const/client_events` (no auth required) and cached in Redis as
`sasquatch:event_type_index` with a 7-day TTL. This ensures new event types added
by Mist are picked up automatically and expand the feature vector.

**Event category buckets** (used only for the post-hoc explainer, NOT for ML input):

| Category | Event types |
|---|---|
| `DHCP_SUCCESS` | `CLIENT_IP_ASSIGNED`, `CLIENT_IPV6_ASSIGNED` |
| `DHCP_FAILURE` | `MARVIS_EVENT_CLIENT_DHCP_NAK`, `MARVIS_EVENT_CLIENT_DHCPV6_NAK`, `MARVIS_EVENT_CLIENT_DHCP_FAILURE`, `MARVIS_EVENT_CLIENT_DHCPV6_FAILURE`, `MARVIS_EVENT_CLIENT_DHCP_STUCK`, `MARVIS_EVENT_CLIENT_DHCPV6_STUCK`, `MARVIS_EVENT_CLIENT_FAILED_DHCP_INFORM` |
| `DNS_SUCCESS` | `CLIENT_DNS_OK` |
| `DNS_FAILURE` | `MARVIS_DNS_FAILURE` |
| `AUTH_SUCCESS` | `CLIENT_AUTHENTICATED`, `CLIENT_AUTH_ASSOCIATION`, `CLIENT_AUTH_ASSOCIATION_11R`, `CLIENT_AUTH_ASSOCIATION_OKC` |
| `AUTH_FAILURE` | `MARVIS_EVENT_CLIENT_AUTH_FAILURE`, `MARVIS_EVENT_CLIENT_AUTH_DENIED`, `MARVIS_EVENT_CLIENT_MAC_AUTH_FAILURE` |
| `ROAM_SUCCESS` | `CLIENT_AUTH_REASSOCIATION`, `CLIENT_AUTH_REASSOCIATION_11R`, `CLIENT_AUTH_REASSOCIATION_OKC`, `CLIENT_REASSOCIATION`, `CLIENT_REASSOCIATION_PMKC` |
| `ROAM_FAILURE` | `MARVIS_EVENT_CLIENT_FBT_FAILURE`, `MARVIS_EVENT_CLIENT_AUTH_FAILURE_OKC`, `MARVIS_EVENT_CLIENT_AUTH_FAILURE_11R`, `MARVIS_EVENT_WLC_FT_KEY_NOT_FOUND` |
| `DISASSOC` | `CLIENT_DEASSOCIATION`, `CLIENT_DEAUTHENTICATION`, `CLIENT_DEAUTHENTICATED`, `MARVIS_EVENT_STA_LEAVING` |
| `ARP` | `CLIENT_GW_ARP_OK`, `CLIENT_GW_ARP_FAILURE`, `CLIENT_ARP_FAILURE`, `CLIENT_EXCESSIVE_ARPING_GW` |
| `CAPTIVE_PORTAL` | `MARVIS_EVENT_WXLAN_CAPTIVE_PORT_FLOW_REDIRECT`, `HTTP_REDIR_PROCESSED`, `MARVIS_EVENT_CAPTIVE_PORTAL_AUTHORIZED`, `MARVIS_EVENT_CLIENT_WXLAN_POLICY_LOOKUP_FAILURE` |
| `SECURITY` | `DEFAULT_GATEWAY_SPOOFING_DETECTED`, `MARVIS_EVENT_CLIENT_STATIC_IP_BLOCKED` |
| `COLLABORATION` | `CLIENT_JOINED_CALL`, `CLIENT_LEFT_CALL`, `CLIENT_DISCONNECTED_FROM_CALL`, `HIGH_CPU_OBSERVED` |
| `OTHER` | `RADIUS_DAS_NOTIFY`, any unrecognized types |

Log any event types not in the known list to Redis set
`sasquatch:unknown_event_types:org` for review and future vector expansion.

---

### `feature_engineer.py`

**Purpose:** Build per-MAC feature vectors from the event stream.

**Input:** SQLite events table (read via `db.get_events(site_id, wlan)`)
**Output:** Redis `sasquatch:features:{site_id}:{wlan_key}`

---

#### Critical Design Principle: Volume Is Not Anomaly

A client that has roamed 50 times and completed 50 healthy connectivity chains is NOT
anomalous — it is an active, healthy client. A client with 200 events that are all
`CLIENT_IP_ASSIGNED` and nothing else IS anomalous.

**Do NOT use raw event counts or event rates as anomaly features.** The signal is in
the PATTERN and RATIO of events, not the total volume. All features must be ratios,
ratios-of-ratios, entropy measures, or inter-event timing metrics.

The single exception: `burst_score` (see below), which measures time density of a
single event type — not total count.

---

#### Healthy Connectivity Chain (Reference Template)

There are TWO distinct healthy chain types. The feature engineering must distinguish them.

**Type A — Fresh association (first join or IP renewal):**
```
CLIENT_AUTHENTICATED → CLIENT_AUTH_REASSOCIATION → CLIENT_IP_ASSIGNED → CLIENT_GW_ARP_OK → CLIENT_DNS_OK
```
DHCP is expected here. A chain started by `CLIENT_AUTHENTICATED` with no `CLIENT_IP_ASSIGNED`
within 60 seconds is a candidate anomaly (possible DHCP discard pattern).

**Type B — Fast-roam reassociation (PMKSA/OKC/FBT):**
```
CLIENT_AUTHENTICATED → CLIENT_AUTH_REASSOCIATION → CLIENT_GW_ARP_OK → CLIENT_DNS_OK
```
DHCP is NOT expected here — the client retains its IP across roams. This is confirmed
by real payload data: a client roaming across 10+ APs had only 2 unique `dhcp_xid`
values across its entire 24hr event window.

**Chain boundary markers (confirmed from real payload):**
- Chain START: `CLIENT_AUTHENTICATED` (time_since_assoc = 0)
- Chain END: `MARVIS_EVENT_STA_LEAVING` (reason_code 8 = clean voluntary departure)
- Distinguish Type A vs Type B: if `CLIENT_IP_ASSIGNED` appears within 60s of chain
  start → Type A. If not → Type B.

**What is NOT normal:**
- Type A chain started but no `CLIENT_IP_ASSIGNED` within 60s → possible DHCP discard
- `CLIENT_REASSOCIATION_FAILURE` appearing before `CLIENT_AUTH_REASSOCIATION` succeeds → PMKID/roam failure
- Chain started but no `CLIENT_GW_ARP_OK` within 120s → connectivity failure
- Chain completed DHCP but no `CLIENT_DNS_OK` within 60s → DNS failure post-DHCP

---

#### ML Input: Two Vectors, Routed by Stage

**Design principle:** The ML models receive raw, assumption-free features —
no pre-computed ratios, no chain-completion logic, no domain knowledge about
what sequences "should" look like. The model discovers what normal looks
like from the population itself.

But "raw" is granularity-dependent: per-event-type frequencies and per-category
frequencies surface different signal. So `feature_engineer.build_features`
emits BOTH per MAC, and each detection stage consumes the one that matches
its job.

**`event_vector` — normalized event-type frequency distribution (~59 dim):**

One dimension per known Mist client event type. Value = `count(event_type) /
total_events`. Always sums to 1.0; zero-filled for types this MAC never
produced. Dimension ordering comes from Redis `sasquatch:event_type_index`
(refreshed from `GET /api/v1/const/client_events`, 7-day TTL, falls back to
`MIST_CLIENT_EVENT_TYPES` in `event_collector.py`).

```python
# For each MAC, build a vector like:
{
    "CLIENT_IP_ASSIGNED": 0.04,        # 4% of this client's events were DHCP success
    "CLIENT_AUTH_REASSOCIATION": 0.31, # 31% were successful roam reassociations
    "CLIENT_GW_ARP_OK": 0.18,
    "MARVIS_EVENT_STA_LEAVING": 0.21,
    "CLIENT_DNS_OK": 0.18,
    "CLIENT_AUTHENTICATED": 0.08,
    "MARVIS_EVENT_CLIENT_AUTH_FAILURE": 0.0,
    # ... ~59 dimensions, zero-filled for absent types
}
```

Consumers: **Isolation Forest** (per-family, intra-family outliers) and
**Family Centroid cosine distance** (inter-family outliers). Both passes
need per-event-type granularity — collapsing all roam failures into one
ROAM_FAILURE bucket would mask the difference between an iPhone failing
fast-roam (`MARVIS_EVENT_CLIENT_FBT_FAILURE`) and an iPhone failing OKC
(`MARVIS_EVENT_CLIENT_AUTH_FAILURE_OKC`), exactly the per-revision
fingerprint this detector exists to find.

**`category_vector` — semantic-bucket frequency + concentration (~15 dim):**

| Block | Dimensions | Description |
|---|---|---|
| Per-category frequencies | ~13 | `count(events in category) / total events`, one per `EVENT_CATEGORIES` bucket except COLLABORATION (excluded — application-layer noise that contaminates cross-device signal). |
| `top_category_fraction` | 1 | Largest single category share. Amplifies the signal for clients stuck in a single-category loop. |
| `top_failure_category_fraction` | 1 | Largest share among failure categories only. Same amplification, failure-only flavor. |

Consumers: **DBSCAN** (after StandardScaler + PCA reduction — semantic
bucket distance is the right level for population-wide clustering), the
**Health Scorer** (success/failure ratios are inherently category-level),
the post-hoc **top-contributing-features explainer** (chip labels in the
UI need readable names like "ROAM_FAILURE" not raw event-type strings),
and the **MacDrilldown bar chart** (~15 readable bars beat 59 sparse
ones for a human inspector).

**Normalization:** Apply StandardScaler across the full MAC population
before passing to Isolation Forest or DBSCAN. Fit on the full population
per run. Do not persist the scaler — refit each cycle. Centroid distance
deliberately skips StandardScaler (it would zero-mean the small set of
family rows and pull the median reference toward zero, producing
spurious near-unit distances) and instead L2-normalizes each row.

**Storage:** Both vectors land in Redis at `sasquatch:features:{site}:{wlan}`
on the same MAC record under keys `event_vector` and `category_vector`.
A legacy `vector` alias points at `category_vector` for backwards
compatibility with any reader that hasn't migrated yet.

---

#### Post-hoc Explainer Features (NOT fed to ML)

These are computed only AFTER a MAC is flagged as anomalous by the ML. They run on
the raw events of flagged MACs only, and exist purely to generate the `probable_pattern`
label for the webhook and GUI. They encode domain knowledge deliberately excluded from
the detection path.

| Feature | Description |
|---|---|
| `pmkid_failure_count` | `CLIENT_REASSOCIATION_FAILURE` events with status_code 53 |
| `gas_timeout_count` | `MARVIS_EVENT_CLIENT_AUTH_FAILURE` events with status_code 62 |
| `dhcp_unique_xid_count` | Count of unique `dhcp_xid` values — true DHCP transactions |
| `dns_to_dhcp_xid_ratio` | `CLIENT_DNS_OK` count / unique DHCP XIDs — collapses toward 0 in DHCP discard pattern |
| `roam_failure_types` | Set of distinct roam failure event types seen (FBT, OKC, 11r key) |
| `top_event_type` | The single most frequent event type for this MAC |
| `top_event_fraction` | Fraction of total events that are the top event type |


---

#### Normalization

Apply StandardScaler across the full MAC population before passing to Isolation Forest
or DBSCAN. Fit on the full population per run. Do not persist the scaler to Redis —
refit each cycle. This is already documented in the ML Input section above; this is
a reminder that it applies to both timing features and the frequency vector.

---

### `anomaly_detector.py`

**Purpose:** Score each MAC through a four-stage ML detection pipeline. Produce per-MAC
anomaly scores and roll up to device type findings. Does NOT compute health scores —
that is handled separately by `health_scorer.py`.

**Stage 1 — DBSCAN (site-wide) + Family Centroid Distance:**

DBSCAN runs per-MAC across all MACs in the WLAN scope. Both `min_samples` and
`eps` are auto-tuned per run from population size:

```python
from sklearn.cluster import DBSCAN

# min_samples = max(3, int(n_clients * pct))    # pct admin-tunable, 0.01–0.10
# eps         = k-distance elbow on PCA-reduced vectors
db = DBSCAN(eps=eps, min_samples=min_samples)
labels = db.fit_predict(full_feature_matrix)  # -1 = noise/outlier
```

DBSCAN label -1 means the MAC doesn't fit any cluster — a site-wide behavioral
outlier regardless of device type. The min_samples percentage is the only
admin-tunable input (`anomaly_dbscan_min_samples_pct`, integer 1–10 mapped to
0.01–0.10, default 3 → 3%); eps is selected each run by the k-distance elbow
("knee") method and is not exposed in the GUI. There is no min_family_size
pre-filter — every real MAC participates in DBSCAN, and small-family
suppression is the job of `ALARM_MIN_FAMILY_SIZE` downstream. DBSCAN sets
`dbscan_label`, `is_dbscan_outlier`, and `dbscan_family_noise_ratio` on each
MAC record. These values are stored on anomaly records and used by the
frontend, but DBSCAN noise ratio no longer determines which families are
flagged at the family level.

**`is_family_outlier` is set by the inter-family cosine-distance detection step (separate from Stage 2):**

After DBSCAN, a centroid detection pass runs across family-level centroids. For each device
family with ≥ 2 MACs, a dual-representation row is built: element-wise median of all per-MAC
feature vectors concatenated with the component-wise maximum. Each family row is then
L2-normalized to a unit vector before computing distances. (Cosine distance is scale-invariant
but requires non-zero-magnitude vectors — StandardScaler is NOT used here because it makes
rows zero-mean and causes the median reference to approach the zero vector, producing
spuriously high distances everywhere.)

A reference centroid is built as the element-wise median of the L2-normalized rows (re-normalized
to a unit vector), and each family's cosine distance from that reference is computed. Families
exceeding `ANOMALY_CENTROID_DIST_THRESHOLD` (default 0.35) are flagged as `is_family_outlier`.

Requires at least 2 qualifying families (≥ 2 MACs each). Below that, the step is skipped
entirely and no families are flagged at the family level. Isolation Forest is **no longer
used at the inter-family (centroid) level** — the centroid-IF path was removed because IF
is statistically unreliable at small N (5–8 family rows): contamination-derived thresholds
carry little statistical meaning and scores are noisy between cycles. Cosine distance is
simpler, more stable, and produces interpretable scores. IF remains in use for **intra-family**
MAC outlier detection (Stage 2).

**Healthy-only reference centroid:** Before centroid detection runs, `score()` /
`score_org_wide()` compute per-family mean health via the shared
`_family_mean_health(groups, feature_map, log_prefix, wlan)` helper (one source of
truth for both site and org paths — edit the helper rather than duplicating the
prelude inline). Families with mean health >=
`ANOMALY_CENTROID_HEALTHY_REF_THRESHOLD` (default 0.75) form the
"healthy reference pool": the reference centroid (element-wise median) is built from
healthy families only. All families — including unhealthy ones — are measured against
this healthy reference. This prevents a group of failing families from hiding behind
each other: even if Awair, Raspberry Pi, and Texas Instruments all share the same
auth-failure behavioral signature (and thus look "normal" relative to each other), their
centroids point far from the healthy reference and get flagged.

If fewer than `ANOMALY_CENTROID_HEALTHY_REF_MIN` (default 2) families are healthy, the
detector falls back to the standard all-family reference. The log line reports which
mode ran each cycle.

Anomaly records and findings carry `centroid_dist_score` (higher = more anomalous) so
the distance value is always observable. There is no `centroid_detection_method` field
anymore — the method is always cosine distance.

**Hidden catch-all families:** `Unknown` and `IoT (Unknown)` are heterogeneous
buckets for devices where Mist returned no fingerprint and the OUI lookup also
failed. Mixing unrelated devices into one "family" produces noisy centroid /
IF / Markov signal that is not actionable, so the set defined in
`anomaly_detector.HIDDEN_FAMILIES` is suppressed at three rollup points:

- Site finding rollup (`anomaly_detector.score`)
- Org-wide finding rollup (`anomaly_detector.score_org_wide`)
- Per-family health scoring (`health_scorer.compute_family_health` —
  duplicates the set as `_HIDDEN_FAMILIES` to avoid a circular import back
  into `anomaly_detector`)

The frontend cluster viz components apply the same set client-side, and
individual MACs in these families are still visible in MAC drilldowns and
the raw anomaly records — only the family-level rollup is suppressed.

**Stage 2 — Isolation Forest (per device family):**

```python
from sklearn.ensemble import IsolationForest

# Run separately for each device_family group with >= MIN_PEERS MACs
MIN_PEERS = 2  # Don't run IF on a family with fewer than 2 MACs — not enough signal

clf = IsolationForest(
    contamination=float(os.getenv("ANOMALY_IF_CONTAMINATION", "0.1")),
    random_state=42,
    n_estimators=100
)
scores = clf.fit_predict(feature_matrix)  # -1 = outlier, 1 = normal
raw_scores = clf.decision_function(feature_matrix)  # continuous score
```

For families below MIN_PEERS at a single site, the scorer attempts to supplement with
feature records from the same family at other org sites (org-level pooling). If the
combined count still falls below MIN_PEERS, set `if_score = None`, `is_if_outlier = False`.

**No failure weighting in the ML feature vector.** The `_extract_vector_array()` function
passes raw normalized frequencies to StandardScaler without any column weighting. Failure
signals are captured by the separate Health Score — mixing them into the anomaly feature
space conflates "behaves differently" with "is failing", which are distinct signals.

**Stage 4 — Markov Chain (two signals, single reason):**

`markov_analyzer.py` runs two complementary checks against each MAC's event stream:

1. **Event-level transition scoring (baseline-relative):** scores each normal-length
   episode's consecutive event transitions against the 24hr site transition matrix
   (Laplace-smoothed). An episode is anomalous when its mean log-prob falls below
   threshold; a MAC is flagged when ≥ `MARKOV_OUTLIER_EPISODE_RATIO` of its scoreable
   episodes are anomalous. This catches clients whose connection chains drift from the
   site norm.
2. **Stuck-loop detector (baseline-independent, `detect_stuck_loop()`):** counts all
   consecutive `(A→B)` event-type transition pairs across a MAC's full event stream.
   If the single most common pair accounts for ≥ `MARKOV_STUCK_LOOP_THRESHOLD`
   (default 0.4) of all transitions AND at least one of the two event types is a
   failure/disassoc type, the MAC is flagged `is_stuck_loop=True`. This is critical
   for catching devices that contaminate their own baseline (e.g. a device cycling
   `AUTH_FAILURE → DISASSOC` at 149k events would dominate the site transition matrix
   and look "normal" to the baseline-relative scorer) — the stuck-loop detector
   ignores the baseline entirely.

Both signals roll up into a single `is_markov_outlier` boolean plus a single
`markov_reason` field that collapses to one of two states:

- `"anomaly"` — event-level transition scoring flagged the MAC
- `"repeated"` — stuck-loop detector flagged the MAC (wins ties with `"anomaly"`)

Per-MAC anomaly records still carry the detail fields needed to explain the flag:
`markov_scoreable_episodes`, `markov_anomalous_episodes`, `markov_episode_anomaly_ratio`,
`is_stuck_loop`, `stuck_loop_pair` (e.g. `"MARVIS_EVENT_CLIENT_AUTH_FAILURE→CLIENT_DEAUTHENTICATION"`),
and `stuck_loop_fraction`. Findings carry `markov_family_reason` — the dominant
per-MAC reason across flagged clients in the family. Repeated-short-episode (Layer 2)
and episode-sequence scoring paths were removed; the baseline persists only
`transition_counts` + `event_type_index`.

**Finding rollup logic:**

After all stages, roll up to device family findings:
- For each device family: count `is_outlier` MACs / total MACs in family
- `is_outlier = is_if_outlier OR is_dbscan_outlier OR is_family_outlier OR is_markov_outlier`
- A finding is generated whenever the family has any outlier MAC, a Markov family
  flag, or a centroid (`is_family_outlier`) flag. There is **no detector-side outlier-
  ratio gate** — every family with signal surfaces in the Findings UI so operators
  can browse low-ratio findings. Alarm escalation (webhook + OrgAlerts feed) is
  governed separately by the General Config alarm gates: `ALARM_DBSCAN_MARKOV_RATIO`
  (per-MAC union of DBSCAN and Markov), centroid bypass (`is_family_outlier`),
  health score, service-alarm device percentage, and `ALARM_MIN_FAMILY_SIZE`.
- Each finding carries `dbscan_or_markov_outlier_count` / `dbscan_or_markov_outlier_ratio`
  so the alarm gate can apply the rollup ratio without re-reading per-MAC anomaly records.
- Minimum family size to generate a finding:
  - Families that used org-level IF pooling: **MIN_PEERS** (`ANOMALY_MIN_PEERS`, default 3) — higher bar because cross-site data was borrowed; avoids hallucinated site findings driven by org noise
  - All others (site-local IF or IF skipped): **`ANOMALY_FINDING_MIN_SIZE`** (default 2) — even 2 devices flagged by centroid detection is real site signal worth reporting
- Top contributing features: mean comparison of outlier MACs vs non-outlier MACs in
  the same family. For family-wide outliers (all MACs flagged), compares against all
  other families at the site.
- **`predominant_wlan`**: detection always runs scoped to a specific SSID, so
  `finding.wlan` is the exact SSID and `predominant_wlan` is set to `null`. The
  field is retained for backwards compatibility with downstream consumers.

**Finding severity:**
- `minimal`: outlier_ratio 0–0.3
- `moderate`: outlier_ratio 0.3–0.6
- `significant`: outlier_ratio > 0.6

Findings at any severity are stored in Redis and visible in the UI. Webhook dispatch
is governed by the dual gate in `webhook_dispatcher.py` — severity alone is not sufficient.

---

### `health_scorer.py`

**Purpose:** Compute a per-family health score that is completely independent of the anomaly
detection pipeline. The health score answers "is this device family experiencing elevated
failures?" — separate from "is this device family behaving unusually?"

**Input:** Redis `sasquatch:features:{site_id}:{wlan_key}` (already computed by `feature_engineer`)
**Output:** Redis `sasquatch:health:{site_id}:{wlan_key}`

**Per-device average, not volume-weighted pool.** Each MAC's normalized feature vector
already encodes per-MAC failure rates (e.g. `AUTH_FAILURE / (AUTH_SUCCESS + AUTH_FAILURE)`).
The family health score is the **simple mean of per-MAC scores** — every device gets one
equal vote regardless of how many events it generated. This prevents a single high-volume
misbehaving device from dragging down the family score.

**Score formula per MAC:**
```python
# Aggregate all success and failure events across all categories.
# Neutral events (DISASSOC, OTHER, CAPTIVE_PORTAL, etc.) are excluded from
# the denominator so they don't dilute the failure signal.
SUCCESS_CATS = (AUTH_SUCCESS, ROAM_SUCCESS, DHCP_SUCCESS, DNS_SUCCESS, ARP_SUCCESS)
FAILURE_CATS = (AUTH_FAILURE, ROAM_FAILURE, DHCP_FAILURE, DNS_FAILURE, ARP_FAILURE)

total_success = sum(vec[cat] for cat in SUCCESS_CATS)
total_failure = sum(vec[cat] for cat in FAILURE_CATS)
total = total_success + total_failure

mac_health = 1.0 - (total_failure / total)  if total > 0 else 1.0
family_health_score = mean(mac_health for mac in family)
```

**Why aggregate instead of per-category weighted average:** A device with 100% DHCP
failure and perfect auth/roam would previously score 0.80 health (DHCP weight = 0.20).
Under the aggregate model it scores 0.0 — all outcome-bearing events are failures. Any
category failing completely drags health to its floor. The per-category breakdown is
still computed and stored in `components` for tooltip display, but does not affect the
health score itself.

**Score ranges:** 1.0 = no failures observed. 0.0 = all outcome-bearing events are failures.
Default alert threshold: `ANOMALY_HEALTH_SCORE_THRESHOLD = 0.30`.

**Per-service rollup and device-alarm ratio:** Alongside the aggregate health
score, `compute_family_health` also computes per-service health and
maintains two parallel device-alarm tallies used by the alarm gates:

- **Per-service** — for each of auth/roam/dhcp/dns/arp the family record
  carries `service_health[svc]` (mean of per-MAC service success ratio across
  active MACs only), `service_alarm_counts[svc] = {active, unhealthy}`, and
  `service_alarms` — the list of services where `unhealthy / active >
  FAMILY_SERVICE_ALARM_THRESHOLD` (50%). A MAC is "active" in a service when
  it has any events in that service bucket; a MAC is "unhealthy" in that
  service when its individual `success / (success + failure)` falls below
  `SERVICE_HEALTH_THRESHOLD` (50%).
- **Device-level** — `mac_alarm_count` is the count of MACs in the family
  that tripped at least one per-MAC service alarm (any service below
  `SERVICE_HEALTH_THRESHOLD`); `mac_alarm_ratio = mac_alarm_count / mac_count`.
  This is what the new `ALARM_SERVICE_DEVICE_PCT` General Config knob gates
  on. The org-level rollup in `score_org_wide` sums the per-site
  `mac_alarm_count` over the per-site `mac_count`, so the org alarm
  threshold applies to the full org-wide family population, not a single
  site.

**Key functions:**
- `compute_family_health(features)` — pure computation, no I/O, testable in isolation
- `score_health(site_id, wlan)` — reads features from Redis, calls above, writes results
- `get_health(site_id, wlan)` — Redis read helper used by routes and webhook dispatcher

**Run order:** `score_health` must be called after `build_features` and before
`webhook_dispatcher.evaluate_and_dispatch`. It runs in the scheduler, background detection
task, and org-wide detection job.

**Critical:** Every code path that calls `build_features` must also call `score_health`
immediately after, or health data will be stale/expired (24hr TTL) while anomaly findings
remain fresh. The `POST /org/detect` route must call `score_health(sid, wlan)` inside
its Phase 1 feature-build loop — omitting it leaves health null for families that only
appear at a small number of sites.

---

### Service-Account Virtual Families

**Why this exists:** A device labelled `MacBook` can also be authenticating under a
shared service-account username such as `srv_Apple_EP`. Looking at MacBooks alone
would miss "all devices logging in as `srv_Apple_EP` are failing auth" — the username
is the more meaningful grouping for that signal. Service-account families let the
detector see the same MAC twice: once under its hardware family (`MacBook`) and once
under its username family (`srv_Apple_EP.service_account`). Anomalies can surface from
either view and the operator sees both.

**Source field:** `last_username` from the Mist org clients endpoint. Captured by
`client_cache.py`, persisted on the `clients` SQLite row (column added via migration),
and threaded through event enrichment in `event_collector.py` so every event row
inherits `last_username` alongside `device_family` / `device_model` / `device_manufacturer`.

**Family naming convention:** Service-account family names use the suffix
`.service_account`. A username `srv_Apple_EP` produces the family
`srv_Apple_EP.service_account`. The suffix is the only flag downstream code uses to
distinguish service-account families from hardware families — do not use it for any
other purpose.

**≥50 MAC threshold:** A username only becomes a virtual family once at least 50
distinct MACs in the org cache share it. Below that, the username is treated as
identifying / decorative metadata only and does not generate a family. Threshold lives
in `feature_engineer.py`; rebuilding the threshold list happens at feature-build time
so it tracks current cache state (not stale snapshots).

**Dual-family model — composite keys:** Feature records for service-account families
use composite keys `{mac}#sa` so a single MAC can carry two parallel feature rows:

| Key | family_field | is_service_account_record |
|---|---|---|
| `aabbccddee01` | `MacBook` | False |
| `aabbccddee01#sa` | `srv_Apple_EP.service_account` | True |

Both rows are emitted by `feature_engineer.py` and both flow through every stage of
`anomaly_detector.py` — DBSCAN, per-family Isolation Forest, Markov stuck-loop, and
inter-family centroid detection. The composite key ensures dict-based state never
collides between the two perspectives.

**Roll-up behavior:** Service-account families are scored as first-class families.
They generate findings, contribute to `org_findings`, and pass through the dual
alert gate exactly like hardware families. The `service_account` summary block on
each primary anomaly record (set in `score()`) carries `family`, `last_username`,
`is_family_outlier`, `is_if_outlier`, `if_score`, and `centroid_dist_score` so
the per-MAC drilldown can show "this device is also part of
`srv_Apple_EP.service_account`, which scored X".

**Webhook gating:** Same dual gate as hardware families. A service-account family
fires the webhook when `is_family_outlier == True` AND `health_score < threshold`.

**Frontend surfacing:** Service-account families are visible in:
- **SiteOverview / OrgFamilyInsights heatmap rows** — rendered with the SA color
  scheme (`SA_COLOR = "#d4a06a"`, `SA_BG = "#2a1f15"`), labelled with the username
  (suffix stripped), and tagged with a `SVC ACCT` badge that lists the underlying
  device families on hover.
- **OrgAlerts / FindingsFeed cards** — `family_kind === "service_account"` triggers
  the SVC ACCT badge and replaces `device_family` with `service_account_label`.
- **FamilyDrilldown / OrgFamilyDrilldown** — header shows the SA badge, a banner
  block lists the underlying device families the username spans, and an extra
  "Primary Family" column appears showing each member MAC's hardware family.
- **MacDrilldown** — when `scores.service_account` is present, an SA info card
  appears between the metadata grid and the Domain Health Axes, showing the SA
  family label, username, and the SA-specific anomaly + centroid scores.

**API metadata:** `get_events_summary` (powering the heatmap) returns a
`family_metadata` map keyed by family name with `family_kind`,
`service_account_label`, and `service_account_member_families` so the frontend can
render each row correctly without re-deriving the suffix logic.

---

### `webhook_dispatcher.py`

**Purpose:** Apply the alert gates and POST qualifying findings to the webhook URL.

**Alert gates — all conditions must be true to fire the webhook:**
1. **Anomaly gate** — the family qualifies via **either**:
   - `finding["is_family_outlier"] == True` — the inter-family centroid detector
     flagged the whole family as behaviorally different from the healthy
     reference. **Independently sufficient** — bypasses the rollup ratio.
   - **OR** the DBSCAN-or-Markov rollup ratio: the per-MAC union of
     `is_dbscan_outlier` and `is_markov_outlier` reaches `ALARM_DBSCAN_MARKOV_RATIO`
     (default 0.20) of `total_mac_count`. A single client flagged by both
     detectors counts once. Each finding carries `dbscan_or_markov_outlier_count`
     so the gate applies without re-reading per-MAC anomaly records.

   The shared helper `webhook_dispatcher.family_passes_dbscan_markov_gate(finding,
   ratio)` implements both branches and is imported by `routes.py` so
   `get_org_alerts`, `get_org_summary`, and `get_org_alerts_full` use the exact
   same gate as the webhook dispatcher.
2. **Health gate** — `family health_score < ANOMALY_HEALTH_SCORE_THRESHOLD` **OR**
   the service-alarm device-percentage gate fires (`alarm_service_device_pct` of
   the family's MACs have individually tripped a service alarm). Confirms the
   behavioral signal is accompanied by measurable failure degradation.
3. **Family-size gate** — `finding["total_mac_count"] >= ALARM_MIN_FAMILY_SIZE`.
   Default `1` (i.e. no suppression); operators raise this via the General Config
   tab to mute small-population families. Findings below the floor still appear
   in the UI; only the webhook + org/site alert feeds suppress them.

All four General Config alarm knobs (`alarm_dbscan_markov_ratio`,
`anomaly_health_score_threshold`, `alarm_service_device_pct`,
`alarm_min_family_size`) live under the `general` section because they gate
alarm generation, not the detection pipeline itself. Detection-side knobs
remain under the `anomaly` section in `config.py`.

Finding severity (`minimal` / `moderate` / `significant`) is computed and stored on
findings for the UI, but is **not** emitted in the webhook payload — downstream
consumers tune their own alert thresholds via the dual gate above rather than relying
on the Sasquatch severity classification.

**Marvis TSHOOT enrichment:** After findings pass the dual gate but before the payload is
POSTed, the dispatcher calls the Mist Marvis TSHOOT API for each of the top three worst-health
MACs in every qualifying finding. Calls are issued concurrently across all findings using
`asyncio.gather`. Each call hits:

```
GET https://{MIST_CLOUD_HOST}/api/v1/orgs/{MIST_ORG_ID}/troubleshoot?mac={mac}
```

Results are attached to each finding as `marvis_tshoot` — a list of `{mac, tshoot_results}`
objects. `tshoot_results` is the raw `results` array from the Marvis API response (list of
`{category, reason, text, recommendation, site_id}` dicts). TSHOOT failures for individual
MACs return an empty `tshoot_results` list rather than blocking the webhook. If `MIST_ORG_ID`
or `MIST_API_TOKEN` are not configured, the enrichment step is skipped and `marvis_tshoot`
is omitted from the payload.

**Webhook payload:** The outbound payload is intentionally slim — only fields a downstream
alerting consumer actually needs to route and triage. Internal detector metrics
(centroid distances, DBSCAN counts, outlier ratios, IF scores, Markov ratios/counts,
severity, legacy example_macs, top_features) are **not** emitted. The slim projection
is performed by `_slim_finding_for_webhook()` in `webhook_dispatcher.py` — edit that
helper if the shape needs to change.

**Site-scope payload:**
```json
{
  "source": "sasquatch_client_anomaly",
  "scope": "site",
  "site_id": "04edb3ac-542a-4d1d-ad90-b1e2fd682a67",
  "wlan": "Corp-WiFi",
  "timestamp": "2026-04-10T14:32:00Z",
  "findings": [
    {
      "device_family": "iPhone",
      "family_kind": "device_family",
      "affected_mac_count": 18,
      "total_mac_count": 25,
      "is_family_outlier": true,
      "is_family_dbscan_outlier": false,
      "is_family_markov_outlier": true,
      "markov_family_reason": "repeated",
      "probable_pattern": "auth_failure_terminal",
      "health_score": 0.61,
      "service_alarms": ["auth"],
      "service_health": {"auth": 0.55, "roam": 0.92, "dhcp": 0.98, "dns": 0.99, "arp": 1.0},
      "worst_health_macs": [
        {"mac": "aabbccddee01", "health_score": 0.21},
        {"mac": "aabbccddee02", "health_score": 0.34},
        {"mac": "aabbccddee03", "health_score": 0.41}
      ],
      "marvis_tshoot": [
        {
          "mac": "aabbccddee01",
          "tshoot_results": [
            {
              "category": "Client",
              "reason": "Failed Fast Roam",
              "text": "The client failed fast roam. Client experienced poor roaming 25% of the time.",
              "site_id": "12f333fe-4a11-44a2-8dc4-0ea5e725016f"
            },
            {
              "category": "Connectivity",
              "reason": "Poor Coverage",
              "text": "Due to the device connecting at a low signal strength.",
              "recommendation": "1. Ensure there are sufficient access points. 2. Check if the device is sticky.",
              "site_id": "12f333fe-4a11-44a2-8dc4-0ea5e725016f"
            }
          ]
        },
        {"mac": "aabbccddee02", "tshoot_results": []},
        {"mac": "aabbccddee03", "tshoot_results": []}
      ]
    }
  ]
}
```

**Org-scope payload** differs in three ways:
- `"scope": "org"`, `"site_id": null`
- Each finding adds `"site_count"` and `"sites_affected": [...]`
- `worst_health_macs` and `marvis_tshoot` are included, and each entry carries its
  own `site_id` so the consumer can correlate a troubled MAC with the specific site
  it lives at (TSHOOT is dispatched per-MAC against that site). `score_org_wide` picks
  the top 3 worst-health MACs across the family's org-wide population.

**Service-account family findings** add two conditional fields when
`family_kind == "service_account"`:
- `"service_account_label"`: the bare username (suffix stripped), e.g. `"srv_Apple_EP"`
- `"service_account_member_families"`: sorted list of underlying hardware families the
  username spans, e.g. `["MacBook", "Windows"]`

**`probable_pattern` field:** Derive from top contributing features using rule-based
lookup — NO LLM (rule-based only, no network calls). Evaluated in priority order (first match wins):

| Pattern label | Trigger condition |
|---|---|
| `"dhcp_discard_loop"` | `repetition_score` high + `dhcp_to_dns_ratio` near 0 + `category_vector_dhcp` dominant |
| `"pmkid_stale"` | `pmkid_failure_ratio` > 0.1 (status_code 53 on reassociation) |
| `"gas_anqp_timeout"` | `gas_timeout_ratio` > 0.1 (status_code 62, Passpoint probe failure) |
| `"roam_failure"` | `failure_ratio_roam` dominant, not pmkid-specific |
| `"auth_failure_terminal"` | `failure_ratio_auth` high + `auth_fail_recovery_ratio` low |
| `"auth_failure_recovering"` | `failure_ratio_auth` high + `auth_fail_recovery_ratio` high |
| `"dns_failure"` | `failure_ratio_dns` dominant |
| `"dhcp_failure"` | `failure_ratio_dhcp` dominant |
| `"behavioral_outlier"` | no dominant feature matches above patterns |

**Status codes to track for pattern classification (confirmed from real payload):**
- `status_code 53` on `CLIENT_REASSOCIATION_FAILURE` = Invalid PMKID (`"pmkid_stale"`)
- `status_code 62` on `MARVIS_EVENT_CLIENT_AUTH_FAILURE` = GAS Query timeout (`"gas_anqp_timeout"`)
- `status_code 79` on `MARVIS_EVENT_CLIENT_AUTH_FAILURE` = Transmission failure (often precedes 62)
- `reason_code 8` on `MARVIS_EVENT_STA_LEAVING` = Normal voluntary departure (NOT anomalous)

**Retry logic:** 3 attempts with exponential backoff (1s, 2s, 4s). Log failures.
Do not raise exceptions that would kill the scheduler job on webhook failure.

**Alert history tracking:** After computing `qualifying`, `evaluate_and_dispatch` calls
`alert_tracker.record_cycle(site_id, wlan, active_findings)` regardless of whether
`ANOMALY_WEBHOOK_URL` is configured, so history is always recorded. An empty `active_findings`
set resolves any previously-active sessions for that WLAN. Skipped for `org_scope=True`
since org findings are composite cross-site records, not single-site events.

---

### `alert_tracker.py`

**Purpose:** Track contiguous alert sessions — periods where a device family at a site
continuously passes the dual gate (is_family_outlier + health_score < threshold).

**Called by:** `webhook_dispatcher.evaluate_and_dispatch()` after every successful
detection cycle. Must not raise — failures are logged and swallowed.

**Session lifecycle:**
- A session opens when a family first appears in `qualifying` for a site.
- Each subsequent cycle where the family is still qualifying extends `last_seen`.
- A session closes (`resolved_at = now`) when a successful cycle completes with the
  family absent from `qualifying`. Absence after a failed/skipped cycle does NOT close
  the session — only a successful cycle with explicit absence does.

**Key design notes:**
- `last_seen` is updated every cycle; `resolved_at` is only written on explicit resolution.
  This prevents a scheduler restart or missed cycle from falsely closing active sessions.
- Sessions that span multiple UTC days appear in each day in the history API, with
  `window_start`/`window_end` clipped to each day's boundaries.
- Org-scope (`org_scope=True`) is not tracked — org findings are composites; per-site
  tracking captures the same signal at the site level.

**Key functions:**
- `record_cycle(site_id, wlan, active_families, redis_client=None)` — write path, called each cycle
- `get_recent_sessions(days, wlan, redis_client=None)` — read path, called by history API

---

### `summary_cache.py`

**Purpose:** Pre-computed dashboard aggregates so the GUI's Site WLAN Family
Insights, Org Family Insights, Findings, and Alerts pages serve out of a single
Redis GET between detection cycles. Polling cadence on those pages is 30–60s;
detection runs hourly; without this layer the same expensive aggregation
runs ~60–120 times per real data change.

**Cached endpoints** (covered by 8 corresponding `build_*` functions in
`api/routes.py`):
- `/org/summary`, `/org/findings`, `/org/alerts`, `/org/alerts-full`,
  `/org/family-insights`
- `/sites/{id}/findings`, `/sites/{id}/health`, `/sites/{id}/events/summary`

**Excluded by design** — drilldowns are infrequent and need fresh per-row
state, so they bypass this layer:
- `/sites/{id}/anomalies/{mac}`
- `/sites/{id}/families/{family}/if-outliers`
- `/org/families/{family}/drilldown`

**Architecture:**
1. Each cached endpoint has a `build_*(redis_client, …)` aggregator (pure,
   no `HTTPException`, no Mist API calls) and a thin route handler that does
   `cache_get → on miss build_*() + cache_set`.
2. `_run_org_pipeline_body` calls every builder in a Phase 5 tail block
   (after per-site scoring completes, inside the global mutex) and writes
   the results to the corresponding `sasquatch:summary:*` key. Lazy import
   of `api.routes` from `scheduler.py` breaks the circular dependency.
3. Phase 5 is best-effort: each builder is wrapped in its own try/except so
   a single cache failure cannot fail detection. The next read falls
   through to the live recompute path and self-heals the cache.

**Cache invalidation:**
- **Pipeline tail (writer):** overwrites every key after detection. Same
  key, new value — no DEL needed.
- **Read-side self-heal:** every route handler calls `cache_set` after a
  live build, so cold starts and individual missing keys repopulate without
  waiting for the next detection cycle.
- **`POST /org/flush`** calls `flush_org_summary_cache()` to drop every
  `sasquatch:summary:*` key.
- **`POST /sites/{id}/flush`** calls `flush_site_summary_cache(site_id)` to
  drop site-scoped keys AND every org-level key (org views aggregate per-site
  contributions, so they go stale when one site is flushed).
- **2-hour safety TTL** (`SUMMARY_CACHE_TTL = 7200`): a backstop in case a
  writer is skipped (detection failure), short enough to bound staleness
  but longer than the 1-hour detection cycle so a single missed cycle
  still serves cached data.

**Anomaly-config writes do NOT invalidate the cache.** Threshold changes
(e.g. `health_score_threshold`, `alarm_min_family_size`) only take effect
on the next detection cycle, when the pipeline tail rebuilds the cache
with the new thresholds. The GUI surfaces this expectation to the user.

**Built-at stamp:** every cache payload carries an `_built_at` ISO-8601
timestamp from `cache_set`, available for the frontend to surface data
freshness if desired.

---

### `scheduler.py`

**APScheduler jobs:**

```python
# Daily at 00:00 — refresh the org-wide client cache
scheduler.add_job(client_refresh_job, 'cron', hour=0, minute=0)

# Daily at 00:30 — unconditional Markov baseline rebuild
scheduler.add_job(markov_baseline_job, 'cron', hour=0, minute=30)

# Once at startup — only rebuilds baselines that are missing/expired in Redis
# (baselines carry a 48hr TTL, so restarts inside that window are near-instant)
scheduler.add_job(markov_baseline_job, 'date',
                  run_date=datetime.now(timezone.utc),
                  kwargs={"skip_existing": True})

# Daily at 03:00 — purge SQLite events older than the 7-day retention window
scheduler.add_job(sqlite_retention_job, 'cron', hour=3, minute=0)

# Hourly — top-up org event collection (gated by Redis flag, see below)
scheduler.add_job(org_event_poll_job, 'interval', hours=1)
```

**ARCH-4: Anomaly detection is no longer scheduled.** Detection runs on manual
trigger via `POST /api/v1/org/detect`, and automatically chains after a
successful collect (full or hourly) when the auto-detect flag is on.
`_org_detect_background_task` invokes `run_org_pipeline()` (defined in
`scheduler.py`); the auto-chain paths invoke `_run_org_pipeline_body()`
directly so the collect's background task runs detect in the same task under
the same mutex without releasing and re-acquiring.

`run_org_pipeline()` walks each site and each unique SSID per site through
this sequence:
1. `feature_engineer.build_features(site_id, wlan)`
2. `health_scorer.score_health(site_id, wlan)`   ← must run before webhook dispatch
3. `anomaly_detector.score_org_wide(...)` once per WLAN over the org-wide
   feature pool, then `anomaly_detector.score(site_id, wlan)` per site
4. `webhook_dispatcher.evaluate_and_dispatch(...)` for org scope, then per site

Any code path that calls `build_features` + `score` must also call `score_health`
in between, so health data is never stale relative to anomaly data.

**Auto-detect chaining:** The Redis flag `sasquatch:auto_detect_enabled`
(default **disabled** — a missing key counts as off; only the explicit string
`"1"` enables the chain) controls whether detection automatically runs after
a successful collect. When on, `_org_collect_background_task` calls
`_run_org_pipeline_body()` inline after `collect_org_full()`, and
`org_event_poll_job` does the same after its hourly event pull. Default is
off because back-to-back collect+detect on a multi-million-event org has
caused OOM kills under constrained Docker memory limits. The global
mutex is handed off from `collecting` → `detecting` in place via
`_transfer_global_lock()` so a competing manual trigger cannot sneak in
between the two phases. `get_auto_detect_enabled()` / `set_auto_detect_enabled()`
helpers live in `scheduler.py`; the admin toggles it via
`GET/POST /api/v1/org/auto-detect` (exposed in the UI action bar next to the
Event Polling button).

**`org_event_poll_job` — hourly event-only top-up:**
- Gated by the Redis key `sasquatch:event_polling_enabled` (set to `"1"` to enable).
  Default: disabled. A missing key counts as off — the operator must explicitly
  enable the hourly poll via `POST /api/v1/org/polling`.
- The job calls `collect_org(MIST_ORG_ID)`, which streams the trailing 1 hour by
  Unix timestamp and flushes to SQLite every `_ORG_HOURLY_FLUSH_BATCH_SIZE` (25k)
  events. When `sasquatch:auto_detect_enabled` is on, detection is chained
  in-place after the events land; otherwise the job stops at collection.
- The job acquires the global mutex (`_acquire_global_lock("collecting")`) so it
  cannot overlap with a manual collect or detection run.
- Writes progress to `sasquatch:progress:org_hourly_poll` (5-minute TTL) so the
  frontend can display a status bar via `GET /api/v1/org/hourly-progress`.

If any step raises, log the error and skip remaining steps for that cycle. Do not
let one bad cycle corrupt Redis state from the previous good cycle.

**`client_refresh_job` — daily org-wide client cache refresh:**
- Calls `refresh_client_cache_org(MIST_ORG_ID)` once. The cache is org-scoped
  (MAC unique across the org), so a single API run populates the entire table.
- After the refresh, loads the cache via `get_client_cache()` and re-enriches
  stored events for every site that has data in the retention window
  (`db.get_site_ids_with_events()`), passing the same shared cache to
  `reenrich_stale_events(site_id, cache)`. This catches MACs that previously
  resolved to "Unknown" but now have a manufacturer/family.
- Skips entirely if `MIST_ORG_ID` is not configured.

---

### FastAPI Routes (`api/routes.py`)

```
GET  /api/v1/sites/{site_id}/findings                → current findings from Redis
GET  /api/v1/sites/{site_id}/health                  → per-family health scores from Redis
GET  /api/v1/sites/{site_id}/clients                 → client list filtered from the org cache by last_site_id
GET  /api/v1/sites/{site_id}/events/summary          → event category counts for GUI charts
GET  /api/v1/sites/{site_id}/anomalies/{mac}         → full event timeline + scores for one MAC
GET  /api/v1/sites/{site_id}/families/{family}/if-outliers → per-family IF deviation list
POST /api/v1/org/refresh                             → trigger an org-wide client cache refresh
GET  /api/v1/sites/{site_id}/status                  → last run timestamp, event count, finding count

GET  /api/v1/org/summary                             → per-site event counts, finding counts, alert_count,
                                                       plus org-wide finding counts (org_significant_count,
                                                       org_moderate_count, org_minimal_count, org_alert_count,
                                                       org_finding_count) read from sasquatch:org_findings:{wlan}
POST /api/v1/org/collect-full                        → trigger a full org-wide event collection over the
                                                       trailing 12 hours (start/end Unix timestamps); runs in
                                                       a background task. Hourly polling and auto-detect
                                                       remain disabled unless the operator has explicitly
                                                       toggled them on.
GET  /api/v1/org/collect-progress                    → phase/page/event counters for an in-flight collect
GET  /api/v1/org/hourly-progress                     → phase/page/event counters for an in-flight hourly poll
                                                       (mirrors collect-progress schema, no clients phase)
GET  /api/v1/org/polling                             → {enabled: bool} — current state of the hourly poll flag
POST /api/v1/org/polling                             → {enabled: bool} — manually toggle the hourly poll flag
GET  /api/v1/org/auto-detect                         → {enabled: bool} — current state of the auto-detect flag
                                                       (default disabled; controls whether detection chains
                                                       after a successful collect)
POST /api/v1/org/auto-detect                         → {enabled: bool} — manually toggle the auto-detect flag
POST /api/v1/org/detect                              → re-runs build_features + score_health + score (per-site) for all
                                                       sites, then score_org_wide; updates both per-site findings
                                                       (sasquatch:findings:{site_id}:{wlan}) and org findings
GET  /api/v1/org/clients/search?mac=                 → prefix search over the clients SQLite PK; returns metadata
                                                       + most-recent (site_id, wlan, timestamp) per hit via events idx
GET  /api/v1/org/alerts                              → org-wide alerts + per-site alerts in one response;
                                                       org_alerts = org findings with health_score < 0.75;
                                                       site_alerts = per-site findings × per-site health, grouped by site
GET  /api/v1/org/alert-history?days=7&wlan={ssid}    → alert session history grouped by UTC day; sessions spanning
                                                       multiple days appear in each day with window clipped to day
                                                       boundaries; response: {days: [{date, label, alarms: [...]}]}
GET  /api/v1/org/findings                            → org-wide findings (cross-site scoring)
GET  /api/v1/org/family-insights                     → per-family heatmap + health scores org-wide
GET  /api/v1/org/families/{family}/drilldown         → per-MAC drilldown for a family across all sites
```

**`GET /org/summary` response shape:**
```json
{
  "sites": [
    {
      "site_id": "...", "site_name": "...", "event_count": 26071,
      "finding_count": 5, "critical_count": 2, "warning_count": 3, "info_count": 0,
      "alert_count": 1,
      "has_data": true
    }
  ],
  "total_sites": 20,
  "org_significant_count": 2,
  "org_moderate_count": 2,
  "org_minimal_count": 0,
  "org_alert_count": 1,
  "org_finding_count": 4
}
```
- `alert_count` per site: families at that site that are both in per-site findings AND have `health_score < 0.75` (cross-referenced from `sasquatch:health:{site_id}:{wlan}`)
- `org_*` counts: derived from `sasquatch:org_findings:{wlan}`, not aggregated from per-site data

All responses are JSON. All reads come from Redis — no real-time Mist API calls in the
request path. The API is read-only except for the manual refresh POST.

The `/health` endpoint returns `{family: {health_score, components, total_events, mac_count}}`.
The `/org/family-insights` endpoint includes `health_score` and `health_components` per family,
computed as a mac_count-weighted average of per-site health scores across all sites (each device gets equal vote, matching health_scorer.py's per-device-average principle).

---

### React Frontend

**1. Site WLAN Family Insights (`SiteOverview.jsx`)**
- Tab is labelled "Site WLAN Family Insights" (was "Site Overview"). The component
  filename is unchanged for git-history continuity.
- Heatmap: rows = device families, columns = event categories, cell = failure ratio
- Color scale: green (0%) → yellow → red (100%)
- Anomaly badge per device family row (`family` / `significant` / `moderate` / OK)
- **Health column**: bar + percentage showing family health score (green ≥85%, yellow 75–85%, orange 55–75%, red <55%). Hover for per-category breakdown.
- **PCA column**: per-row checkbox controlling which families render in the
  adjacent `ClusterViz`. Selection is seeded once per dataset to
  `{flagged families} ∪ {top 3 by client count}` and reset whenever the WLAN or
  site changes. The "uncheck all PCA" link clears the selection. ClusterViz
  itself owns no toggle state — the table is the single source of truth.
- The Markov badge fires from the canonical rollup
  (`anomalous_macs / total_family_macs ≥ markov_family_outlier_ratio` AND
  `total ≥ anomaly_finding_min_size`), matching `markov_analyzer.run_markov_analysis`
  so the badge can never light up unless a finding would actually fire.
- Data source: `events/summary` + `findings` + `health` (three concurrent fetches)
- Auto-refreshes every 60s

**2. Org Family Insights (`OrgFamilyInsights.jsx`)**
- Same heatmap layout but aggregated across all org sites
- Anomaly badge reflects worst finding across all sites for that family
- **Health column**: mac_count-weighted average health score from all sites (each device equal vote). Hover tooltip shows per-category failure rates.
- **PCA column**: same checkbox-driven selection as the site view, controlling
  the embedded `OrgClusterViz`. When the table passes an explicit selection,
  the org viz honors it as-is and skips the `MIN_DISPLAY_CLIENTS` declutter
  (the user opted that family in by hand). When no selection is passed it
  falls back to the legacy size threshold.
- No "Device Family Behavior Explanation" / Shapley column — that detail belongs in drilldowns
- Data source: `/api/v1/org/family-insights`

**3. Findings Feed (`FindingsFeed.jsx`) — site context**
- Each anomaly card shows a **WLAN/SSID badge** using `finding.wlan` / `finding.predominant_wlan` (same logic as OrgAlerts).
- Three sections rendered top-to-bottom: **ALERT → HEALTH → ANOMALOUS**
  - **ALERT** (red): device families that are both anomalous (in findings) AND unhealthy (`health_score < 0.75`). This is the dual-gate condition that mirrors the webhook dispatch logic.
  - **HEALTH** (amber): device families from the health endpoint with `health_score < 0.75` that have no anomaly finding — unhealthy but not yet anomalous.
  - **ANOMALOUS** (green): anomaly findings where health is OK (`health_score ≥ 0.75`).
- Anomaly severity color scheme — **green spectrum** (anomalies alone are not alerts):
  - Significant: bright green `#39e84e`
  - Moderate: medium green `#2eb845`
  - Minimal: forest green `#1a6b27`
- Each anomaly card shows an "unhealthy X%" amber badge when `health_score < 0.75`
- Health score is cross-referenced from the separately-fetched health endpoint by `device_family` — do NOT rely on `health_score` embedded on the finding object, as per-site findings in Redis may not carry it
- Data source: `/api/v1/sites/{site_id}/findings` + `/api/v1/sites/{site_id}/health` (parallel fetch)

**4. Org Alerts (`OrgAlerts.jsx`) — default org view**
- **Default tab** shown when the user selects Organization in the site picker.
- Two sections rendered top-to-bottom: **ORG-WIDE ALERTS** → **SITE ALERTS**
  - **ORG-WIDE ALERTS**: org findings (from `sasquatch:org_findings:{wlan}`, cross-site scoring) where `health_score < 0.75`. Each card shows severity, outlier ratio, device count, health score, failure category breakdown, pattern label, and top contributing features. Family name is a clickable link that opens `OrgFamilyDrilldown` in-place.
  - **SITE ALERTS**: per-site findings cross-referenced with per-site health, grouped by site. Only sites with ≥ 1 alert are shown. Family name opens `FamilyDrilldown` (site-scoped) in-place.
- Each alert card shows a **WLAN/SSID badge** (green pill) after the pattern label, sourced from `finding.wlan` (detection always runs scoped to a specific SSID).
- WLAN dropdown scopes both sections via `?wlan=` query param.
- No example MACs on cards — click the family name to drilldown instead.
- Auto-refreshes every 30s. Data source: `GET /api/v1/org/alerts?wlan=`

**5. Org Findings Feed (`OrgFindingsFeed.jsx`) — org context**
- Same three-section layout as site Findings Feed (ALERT → HEALTH → ANOMALOUS)
- HEALTH section populated from org/family-insights for families not in org findings
- Org findings carry `health_score` directly on the finding object (written by `score_org_wide`)
- Family name on each card is a clickable link — opens `OrgFamilyDrilldown` in-place.
- No example MACs on cards — drilldown is the navigation path.
- Each card shows a **WLAN/SSID badge** using the same `wlan` / `predominant_wlan` logic as OrgAlerts.
- Data source: `/api/v1/org/findings` + `/api/v1/org/family-insights` (parallel fetch)

**6. Org Overview (`OrgOverview.jsx`)**
- Four tabs, left-to-right: **Org Alerts** (default, red accent), **Org Overview**, **Org Family Insights**, **Findings**
- "Org Alerts" tab styled with red border/background (`#e05555`) to distinguish it from the blue-accented tabs.
- **Org Overview tab**: Site cards only — no embedded PCA. The org PCA lives
  inside the Org Family Insights tab where the table-driven family selection
  can control it. Cards sorted by `event_count` descending (highest-traffic sites first); sites with no data sort to the bottom. Site card alert state uses the dual-gate: a site is "Alert" (red) only when `alert_count > 0`.
- Site card anomaly severity badges use the green color spectrum (not red/amber)
- Header badges show **org-wide finding counts** from `sasquatch:org_findings:{wlan}` — not aggregates of per-site data. Counts are returned by `GET /org/summary` in `org_significant_count`, `org_moderate_count`, `org_minimal_count`, `org_alert_count`, `org_finding_count`.

**7. MAC Drill-down (`MacDrilldown.jsx`)**
- 24hr event timeline (chronological event list with timestamps and types)
- Feature vector bar chart vs. family baseline
- Isolation Forest score and DBSCAN label display
- Navigation: accessible by clicking a MAC in the Findings Feed
- Data source: `/api/v1/sites/{site_id}/anomalies/{mac}`

### Findings Alert Logic — Health Threshold

The health threshold is **dynamic** — set via the Anomaly Config GUI, persisted to `config_overrides.json`, and read at runtime by all consumers. The env var `ANOMALY_HEALTH_SCORE_THRESHOLD` (default 0.75) is used only as a fallback when no GUI override exists. The single source of truth is `webhook_dispatcher.get_health_score_threshold()`, which reads the config overrides file first. Backend routes (`get_org_alerts`, `get_org_summary`) import this function. Frontend components (`FindingsFeed.jsx`, `OrgFindingsFeed.jsx`) fetch the threshold from `GET /api/v1/anomaly-config` on mount. Changes take effect immediately — no restart required.

### Drilldown Navigation

Clicking a device family name anywhere in `OrgFindingsFeed` or `OrgAlerts` opens a drilldown in-place (replacing the feed view within the same tab):

- **Org-wide context** (org findings, org alerts ORG-WIDE section): opens `OrgFamilyDrilldown` — cross-site MACs for that family.
- **Site context** (org alerts SITE ALERTS section): opens `FamilyDrilldown` scoped to that specific site.

Back navigation returns to the feed. There are no example MAC buttons on finding cards — drilldown is the only navigation path into individual devices.

---

## Environment Variables (`.env`)

```bash
# Mist
MIST_API_TOKEN=your_token_here
# Cloud host varies by region: api.mist.com, api.gc1.mist.com, api.gc2.mist.com,
# api.gc4.mist.com, api.eu.mist.com. Do NOT include /api/v1 — that is path, not host.
MIST_CLOUD_HOST=api.gc4.mist.com
# REQUIRED: org-wide collection and detection are the only supported modes.
# Per-site MIST_SITE_ID is retired.
MIST_ORG_ID=3549f835-42c3-40d1-90cc-5e70ccc537ee

# Redis
REDIS_URL=redis://localhost:6379

# ML Tuning — Isolation Forest + DBSCAN
ANOMALY_IF_CONTAMINATION=0.05
# DBSCAN min_samples and eps are auto-tuned per run from the population.
# Only the percentage knob is operator-tunable: integer 1–10 → 0.01–0.10.
# min_samples = max(3, int(n_clients * pct))
# eps         = k-distance elbow per run (no env var)
ANOMALY_DBSCAN_MIN_SAMPLES_PCT=3
ANOMALY_MIN_PEERS=5
ANOMALY_MIN_MAC_EVENTS=10
ANOMALY_CENTROID_DIST_THRESHOLD=0.35   # cosine distance (L2-normalized unit vectors) above which a family centroid is flagged as is_family_outlier
ANOMALY_CENTROID_HEALTHY_REF_THRESHOLD=0.75  # families below this health are excluded from the centroid reference pool
ANOMALY_CENTROID_HEALTHY_REF_MIN=2     # minimum healthy families to activate healthy-only reference; otherwise falls back to all-family reference

# Markov Chain stuck-loop detector (markov_analyzer.py)
MARKOV_STUCK_LOOP_THRESHOLD=0.4        # fraction of transitions dominated by one failure pair to flag stuck-loop
MARKOV_STUCK_LOOP_MIN_EVENTS=20        # minimum events before stuck-loop detection runs

# Health Score (health_scorer.py)
# Families with health_score below this value are considered degraded for webhook gating.
# Range: 0.0 (all failing) to 1.0 (no failures). Tune down if too noisy.
ANOMALY_HEALTH_SCORE_THRESHOLD=0.30

# Service-alarm device-percentage gate. A family fires an alarm via the
# service-alarm path when at least this fraction of its MACs have individually
# tripped a service alarm (any of auth/roam/dhcp/dns/arp below the per-MAC
# SERVICE_HEALTH_THRESHOLD). Lives under General Config alongside
# ANOMALY_HEALTH_SCORE_THRESHOLD in the "Health Thresholds for Alarm Generation"
# panel; both gate the webhook dispatcher and the org/site alert feeds. Default
# 0.50 requires at least half of the family's MACs to have tripped.
ALARM_SERVICE_DEVICE_PCT=0.50

# Alarm suppression — skip findings whose total family MAC count is below this floor.
# Applies to webhook dispatch AND UI alert feeds (/org/alerts, /org/summary).
# Default 10 suppresses families smaller than 10 MACs; set to 1 to disable
# suppression and let every family through. Findings below the floor still
# appear in the main findings UI — only alerting is muted.
ALARM_MIN_FAMILY_SIZE=10

# DBSCAN-or-Markov rollup alarm gate. A device family fires an alarm via this
# path when the per-MAC union of is_dbscan_outlier and is_markov_outlier reaches
# this fraction of total_mac_count (a single client flagged by both detectors
# counts once). Inter-family centroid (is_family_outlier) is independent of this
# gate and remains independently sufficient to fire an alarm. Lives under the
# General Config tab in the GUI; applies to both webhook dispatch and the
# OrgAlerts feed at site and org level.
ALARM_DBSCAN_MARKOV_RATIO=0.70

# Event collector — drop any event whose RSSI is below this floor (dBm),
# regardless of type. Events with no rssi field (synthetic/boundary markers)
# always pass through. Set to -120 (below noise floor) to disable.
ANOMALY_RSSI_MIN_THRESHOLD=-87

# Webhook — gates: (is_family_outlier OR DBSCAN/Markov per-MAC union >= ALARM_DBSCAN_MARKOV_RATIO)
# AND (health_score < ANOMALY_HEALTH_SCORE_THRESHOLD OR service-alarm device pct met)
# AND total_mac_count >= ALARM_MIN_FAMILY_SIZE. Any severity triggers dispatch —
# severity is informational only.
ANOMALY_WEBHOOK_URL=https://project-sasquatch-production.up.railway.app/webhook/anomaly

# Frontend
VITE_API_BASE_URL=http://localhost:8000
```

---

## Org-Level Scope

Project Sasquatch is org-only. `MIST_ORG_ID` is required; per-site detection
modes have been retired (ARCH-1 through ARCH-7).

Detection runs only on manual trigger via `POST /api/v1/org/detect`, which
invokes `run_org_pipeline()` in `scheduler.py`:
1. Acquires the global mutex (`sasquatch:lock:global_operation`)
2. Builds features + health scores for every site/WLAN that has events in SQLite
3. Runs `score_org_wide()` over the combined org-wide MAC population — each MAC
   is scored relative to all org peers, not just its own site — and writes
   `sasquatch:org_anomalies:{site_id}:{wlan_key}` and
   `sasquatch:org_findings:{wlan_key}`
4. Dispatches the org-wide webhook
5. Runs per-site `score()` for each site/WLAN and dispatches per-site webhooks
6. Releases the mutex

Event collection is decoupled from detection. The hourly `org_event_poll_job`
streams 1-hour windows from the org events endpoint into SQLite when
`sasquatch:event_polling_enabled = "1"`. The flag defaults to disabled and
is only toggled on by an explicit `POST /api/v1/org/polling` — manual full
collects no longer auto-enable it. Both jobs use the same global mutex so a
poll cannot overlap with a manual collect or detect run.

The org-level pipeline uses the same `score_org_wide()` function in
`anomaly_detector.py` and the same dual alert gate in `webhook_dispatcher.py`.

**Org PCA outlier source:** `GET /api/v1/org/cluster-viz` reads outlier flags
from `sasquatch:org_anomalies:{site}:{wlan}` (written by `score_org_wide`),
not the per-site `anomalies` key. A MAC is therefore circled on the Org PCA
only when it is an outlier against the combined org-wide population of its
family — the same pool the Org Findings tab fires on. Reading the per-site
key would double-count site-local outliers that the org rollup discards.

---

## Client Event Payload Reference

The Mist client events API returns events in this shape. The `type` field is the primary
discriminator — its value determines which other fields are present.

```json
{
  "type": "CLIENT_IP_ASSIGNED",
  "mac": "d4b761509fa6",
  "timestamp": 1775014952.642,
  "dhcp_xid": 146387326,
  "dhcp_server": "10.0.160.1",
  "dhcp_latency": 0.000453221,
  "dhcp_lease_time": 86400000,
  "dhcp_renewal_time": 43200000,
  "gateway": ["10.0.160.1"],
  "dns_server": ["209.130.139.2", "209.244.0.3"],
  "subnet": "10.0.160.0/19",
  "ip": "10.0.164.145",
  "vlan": 160,
  "ap": "5c5b35f16ee0",
  "bssid": "d420b0a48de3",
  "ssid": "Public",
  "band": "24",
  "channel": 6,
  "rssi": -51,
  "proto": "n",
  "num_streams": 1,
  "key_mgmt": "WSEC=0x0",
  "status_code": 0,
  "reason_code": 0,
  "time_since_assoc": 1943897279,
  "wlan_id": "bca07e4d-caae-4395-b033-f086a07ab7e6",
  "org_id": "e9a92864-12ab-4323-a666-23941f069669",
  "site_id": "d6d174be-4fc2-4819-865e-eacf2d979d37",
  "random_mac": false,
  "text": "DHCP Ack IP 10.0.164.145",
  "type_code": 8
}
```

**Fields always present:** `type`, `mac`, `timestamp`, `site_id`, `org_id`

**Fields used by feature engineering:**

| Field | Used For |
|---|---|
| `type` | Event categorization, chain detection, repetition scoring |
| `mac` | Client lookup key |
| `timestamp` | Inter-event intervals, burst scoring, chain timing, chronological ordering |
| `dhcp_xid` | Detecting DHCP retransmits — same XID appearing multiple times = same exchange, not a new IP assignment |
| `status_code` | Success/failure classification for DHCP and auth events (0 = success) |
| `reason_code` | Failure reason for disassoc/auth events — useful for pattern labeling |
| `random_mac` | Flag clients using MAC randomization — exclude from device family rollup, still analyze individually |
| `dhcp_latency` | Secondary signal — very low latency on repeated DHCP_SUCCESS may indicate local reply caching anomaly |

**`dhcp_xid` note:** Two events with the same `dhcp_xid` represent the same DHCP transaction
(e.g., Discover + Offer + Request + Ack). Do NOT count these as separate IP assignments.
When computing `dhcp_to_dns_ratio`, count unique `dhcp_xid` values, not raw event count.

**`random_mac` note:** Clients with `random_mac: true` are still included in per-family
Isolation Forest scoring. MAC randomization on Mist networks is typically per-SSID or
per-network — not rotating mid-session — so the client behaves consistently within the
24hr window. Excluding them would drop a significant portion of the iPhone and Android
population. Include in both per-family IF and site-wide DBSCAN. Store `random_mac` as
a metadata field on the finding for informational purposes only.

**`status_code` / `reason_code`:** Treat 0 as success for all event types where this
field appears. Non-zero = failure. Log any non-zero reason_codes seen in auth/disassoc
events — they map to 802.11 standard reason codes and can inform the `probable_pattern`
field in the webhook payload.

---

## Build Sequence

Build in this order to enable incremental testing:

1. **`client_cache.py`** — Get the org-wide MAC → device metadata lookup working and
   verify SQLite writes via `db.upsert_clients_org`. Test against the live Mist API
   manually before wiring the scheduler.

2. **`event_collector.py`** — Pull events, paginate fully, enrich with client cache.
   Verify event counts look right. Check that category binning covers the event types
   you see in practice (log any uncategorized event types to a set for review).

3. **`feature_engineer.py`** — Build feature vectors and inspect them manually before
   running any ML. Print the distribution of each feature across MACs. If repetition_score
   is 0 for everything, your consecutive-repeat logic may be wrong.

4. **`anomaly_detector.py`** — Run Isolation Forest first, inspect scores manually,
   tune contamination. Then add DBSCAN. Do not trust results until you've manually
   verified a known-bad MAC (use Cupertino env for this).

5. **FastAPI + routes** — Wire Redis reads to API endpoints. Test with curl before
   touching React.

6. **React frontend** — Build SiteOverview first (most useful for validation), then
   FindingsFeed, then MacDrilldown.

7. **`scheduler.py`** — Add scheduling last, after all components are verified
   individually.

8. **`webhook_dispatcher.py`** — Wire and test last. Use a webhook.site endpoint for
   initial testing before pointing at production Sasquatch.

---

## What NOT to Build (Explicit Exclusions)

- No publicly hosted LLM anywhere (no Anthropic/OpenAI API calls) — data must not egress to third-party providers
- No LLM in the detection, scoring, health scoring, or webhook path (locally hosted LLMs are permitted for read-only explanation features only)
- No SLE data — client event stream only
- No per-AP correlation (future enhancement)
- No real-time Mist API calls in the FastAPI request path — reads from Redis only
- No failure weighting in the anomaly ML feature vector — failure signals belong in the health score, not the anomaly vector
- Do not gate webhooks on single-device IF or DBSCAN anomalies — only `is_family_outlier` (centroid IF) qualifies for webhook dispatch

---

## Hardening Log (2026-04-16)

Tracked so future edits don't accidentally regress these. Full context in [TODO.md](TODO.md) under "Pre-submission hardening" and "Code-cleanup pass".

**Security / info leakage**
- CORS pinned to `localhost:3000` / `localhost:5173` (+ `127.0.0.1` twins) in [main.py](sasquatch/main.py). Do not regress to `allow_origins=["*"]`.
- `HTTPException.detail` must never interpolate an exception object. Two routes (`/org/refresh` at [routes.py:993](sasquatch/client_anomaly/api/routes.py#L993), Markov rebuild at [routes.py:3130](sasquatch/client_anomaly/api/routes.py#L3130)) were leaking `str(exc)` to clients — pair every handler's `log.exception(...)` with a constant `detail=`.
- `MIST_API_TOKEN` lives only inside `Authorization` headers. Never interpolate it into log lines or error messages.

**Crash-resistance invariants**
- Both Mist paginators ([event_collector.iter_events_org](sasquatch/client_anomaly/event_collector.py), [client_cache.fetch_all_clients_org](sasquatch/client_anomaly/client_cache.py)) enforce a hard `_MAX_PAGES` ceiling (20k / 10k) and wrap `resp.json()` in an explicit `JSONDecodeError` branch. Protects against circular `next` cursors and HTML error pages.
- `db.get_events` decodes `raw_json` row-by-row with a `(JSONDecodeError, TypeError)` guard. A single corrupt row logs and is skipped rather than crashing every downstream consumer.
- Webhook dispatch is crash-isolated from its auxiliary steps:
  - `alert_tracker.record_cycle()` is wrapped in `try/except Exception` ([webhook_dispatcher.py:483-495](sasquatch/client_anomaly/webhook_dispatcher.py#L483-L495)). Alert history is best-effort; the outbound POST is load-bearing.
  - TSHOOT enrichment uses `asyncio.gather(..., return_exceptions=True)` ([webhook_dispatcher.py:515-530](sasquatch/client_anomaly/webhook_dispatcher.py#L515-L530)) and converts per-MAC failures to empty `tshoot_results`. One bad MAC cannot crash the dispatch.
- `_GLOBAL_LOCK_TTL_SECONDS` is 6h ([scheduler.py:46](sasquatch/client_anomaly/scheduler.py#L46)) — long enough to cover a full 12hr multi-million-event collect. `clear_stale_global_lock()` at startup handles the crash-before-release case; the TTL is the backstop.

**Input validation**
- Every `wlan: str = Query(...)` param in [routes.py](sasquatch/client_anomaly/api/routes.py) carries `min_length=1`. An empty string would otherwise build malformed Redis keys like `sasquatch:findings:{site}:` and silently miss real data.
- The `/org/clients/search` MAC query param has `pattern=r"^[a-fA-F0-9:.\-\s]+$"`.

**Payload-size logging**
- Webhook dispatch logs a summary line at INFO (count + first 3 family names) and puts the full JSON behind `log.isEnabledFor(logging.DEBUG)` ([webhook_dispatcher.py:560-572](sasquatch/client_anomaly/webhook_dispatcher.py#L560-L572)). At org scale a payload is multi-MB — do not regress to `log.info(json.dumps(payload, indent=2))`.

**Correctness invariants**
- Centroid-detection prelude lives in `_family_mean_health()` helper ([anomaly_detector.py:497](sasquatch/client_anomaly/anomaly_detector.py#L497)). Both `score()` and `score_org_wide()` call it — edit the helper rather than re-inlining the prelude.
- Markov merge at [anomaly_detector.py:1267](sasquatch/client_anomaly/anomaly_detector.py#L1267) sets `is_outlier = True` directly (the old `or True` was dead code). JSON-decode failures on per-site anomaly records narrow to `(json.JSONDecodeError, TypeError)` and log site/wlan context.
