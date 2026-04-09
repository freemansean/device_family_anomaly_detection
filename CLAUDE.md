# Project Sasquatch — Client Anomaly Detection Module
## CLAUDE.md — Implementation Guide

This file provides full context for implementing the Client Anomaly Detection sub-module
of Project Sasquatch. Read this entirely before writing any code.

---

## What This Module Does

Detects anomalous client behavior at a Juniper Mist site by:
1. Building a 24-hour client device database (MAC → device metadata)
2. Pulling all client events for the site over the last 24 hours
3. Engineering per-MAC behavioral feature vectors
4. Running a four-stage ML detection pipeline (see `anomaly_detector.py`):
   - **Stage 1 — DBSCAN** (site-wide): flags MACs that don't cluster with any site peer group
   - **Stage 1b — Family Centroid IF**: flags entire device families behaving differently from all other families
   - **Stage 2 — Isolation Forest** (per device family): flags individual MACs anomalous within their family
   - **Stage 4 — Markov Chain** (see `markov_analyzer.py`): scores event-transition sequences within episodes against a 24hr site baseline; flags families where ≥ `MARKOV_FAMILY_OUTLIER_RATIO` of clients have anomalous connection patterns, repeated short (failed) episodes, or stuck failure loops (baseline-independent)
5. Computing a separate per-family **Health Score** (see `health_scorer.py`): mean of per-MAC
   failure rates across AUTH, ROAM, DHCP, DNS, and ARP — independent of the anomaly pipeline
6. Rolling up MAC-level anomalies to device type findings
7. Exposing findings via a React + FastAPI dashboard
8. Firing a webhook when a device family carries **any** family-level anomaly label (is_family_outlier, is_family_dbscan_outlier, or is_family_markov_outlier) **and** is unhealthy (health score below threshold) — dual-gate to prevent single-device noise

**This module has NO LLM in the detection path.** Pure ML + rule-based only.
Client event data must not egress to third-party providers. Do not add any LLM calls to detection or scoring code.

---

## Why This Exists (Problem Statement)

Mist SLEs are aggregate metrics — they smooth over edge cases. This module is designed
to catch things SLEs miss, such as:

- A client OS discarding DHCP offers → client loops on DHCP_SUCCESS with no connectivity
- A client holding a stale PMKID → repeated 11r-FBT roam failures
- A device type (e.g., all HP printers at a site) silently failing DNS
- A specific client model with a firmware bug causing repeated SAE auth failures

The detection strategy: an iPhone behaving nothing like other iPhones at the same site
is the signal. Device type peer comparison is the core insight.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | FastAPI (Python) |
| Frontend | React |
| Cache / State | Redis |
| Scheduling | APScheduler |
| ML | scikit-learn (IsolationForest, DBSCAN) |
| Feature Engineering | pandas, numpy |
| Mist API Client | httpx (async) |
| Alerting | httpx webhook POST (configurable target) |

This module is part of the larger Project Sasquatch codebase which already uses:
- Redis for alarm caching and 24hr history
- SendGrid for email output
- Anthropic SDK (Claude Haiku for triage, Claude Sonnet for RCA)
- A shared Python context object flowing across pipeline stages

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
│   ├── client_cache.py          # Daily client list refresh → Redis
│   ├── event_collector.py       # 24hr event pull + MAC enrichment → Redis
│   ├── feature_engineer.py      # Per-MAC feature vector construction
│   ├── anomaly_detector.py      # Four-stage ML pipeline (DBSCAN/IF/Markov) + finding rollup
│   ├── markov_analyzer.py       # Markov Chain episode analysis (Stage 4)
│   ├── health_scorer.py         # Per-family health score (separate from anomaly pipeline)
│   ├── webhook_dispatcher.py    # Dual-gate alert dispatch (anomaly + health)
│   ├── alert_tracker.py         # Persistent alert session history (7-day, per-site)
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

## Redis Key Schema

| Key | TTL | Contents |
|---|---|---|
| `sasquatch:clients:{site_id}` | 7 days | JSON dict: MAC → {model, os, manufacturer, family} |
| `sasquatch:events:{site_id}` | 7 days | Sorted set: enriched event objects scored by Unix timestamp |
| `sasquatch:wlans:{site_id}` | 7 days | Set: unique SSID names seen for this site |
| `sasquatch:event_type_index` | 7 days | JSON array: ordered list of known Mist client event type strings |
| `sasquatch:features:{site_id}:{wlan_key}` | 24hr | JSON dict: MAC → feature vector dict |
| `sasquatch:anomalies:{site_id}:{wlan_key}` | 24hr | JSON dict: MAC → {if_score, dbscan_label, is_outlier, is_family_outlier, is_markov_outlier, markov_episode_anomaly_ratio, …} |
| `sasquatch:markov_baseline:{site_id}:{wlan_key}` | 48hr | JSON dict: {transition_counts, episode_transition_counts, event_type_index, computed_at} |
| `sasquatch:health:{site_id}:{wlan_key}` | 24hr | JSON dict: family → {health_score, components, total_events, mac_count} |
| `sasquatch:findings:{site_id}:{wlan_key}` | 24hr | JSON array: rolled-up findings for GUI + webhook |
| `sasquatch:org_anomalies:{site_id}:{wlan_key}` | 24hr | JSON dict: per-MAC org-wide scores (written by `score_org_wide`) |
| `sasquatch:org_findings:{wlan_key}` | 24hr | JSON array: org-wide findings (one entry per device family across all sites) |
| `sasquatch:alert_active:{site_id}:{wlan_key}` | none (managed explicitly) | Hash: family → `{first_seen, last_seen}` for currently-active alert sessions |
| `sasquatch:alert_sessions` | none (pruned on write) | Sorted set: session keys scored by `first_seen` unix timestamp; entries older than 8 days are pruned each cycle |
| `sasquatch:alert_session:{session_key}` | 8 days | JSON: `{site_id, family, wlan, first_seen, last_seen, resolved_at, status}` for one alert session |

**TTL note:** Client cache and events are both 7 days — the cache survives across the full
event retention window, so a cache miss on a historical event is not possible due to TTL
expiry. Detection/scoring output keys (features, anomalies, health, findings) are 24hr.

**Startup behavior:** If `sasquatch:clients:{site_id}` is missing at startup, the event
collector must fail fast with a clear error — do NOT silently make a redundant client
list API call from the event collector. The daily job owns that responsibility.

---

## Module Specifications

### `client_cache.py`

**Purpose:** Once-daily refresh of the client device lookup table.

**Mist API call:**
```
GET https://{MIST_CLOUD_HOST}/api/v1/sites/{site_id}/clients/search?limit=1000
```

**Pagination — CRITICAL:** This endpoint uses cursor-based pagination, NOT page/offset.
After each response, check for a `next` field at the top level of the JSON. If present,
it contains a full relative URL. Prepend `https://{MIST_CLOUD_HOST}` and call it verbatim
— do NOT attempt to reconstruct or modify the URL. Loop until `next` is absent.

```python
async def fetch_all_clients(site_id: str) -> list[dict]:
    url = f"https://{MIST_CLOUD_HOST}/api/v1/sites/{site_id}/clients/search?limit=1000"
    all_clients = []
    while url:
        resp = await httpx_client.get(url, headers=auth_headers)
        data = resp.json()
        all_clients.extend(data.get("results", []))
        next_path = data.get("next")
        url = f"https://{MIST_CLOUD_HOST}{next_path}" if next_path else None
    return all_clients
```

**Device family classification:** The client record fields `model`, `device`, and `os`
are ALL arrays (can be empty lists). Use this fallback hierarchy to determine family:

```python
def classify_family(client: dict) -> str:
    model   = (client.get("last_model") or "").strip()
    device  = (client.get("last_device") or "").strip()
    os_str  = (client.get("last_os") or "").strip()
    mfg     = (client.get("mfg") or "").strip()

    # Prefer last_* scalar fields over array fields for classification
    combined = f"{model} {device} {os_str} {mfg}".lower()

    if "iphone" in combined:                          return "iPhone"
    if "ipad" in combined:                            return "iPad"
    if "mac" in combined and "apple" in combined:     return "MacBook"
    if "apple" in combined:                           return "Apple"          # catch-all
    if "android" in combined and "tablet" in combined: return "Android Tablet"
    if "android" in combined:                         return "Android Phone"
    if "windows" in combined:                         return "Windows"
    if "chrome" in combined:                          return "Chromebook"
    if "linux" in combined:                           return "Linux"
    if "printer" in combined or "print" in combined:  return "Printer"
    if mfg and model == "" and os_str == "":          return f"IoT ({mfg})"
    return "Unknown"
```

**Output:** Redis key `sasquatch:clients:{site_id}`, value:
```json
{
  "d67e8486da0b": {
    "family": "Apple",
    "model": "",
    "os": "Apple OS",
    "manufacturer": "Apple",
    "random_mac": true,
    "last_ssid": "Public",
    "last_ap": "a8f7d9818ea2"
  }
}
```

**Note on `model` field:** The `model` array is frequently empty even for known devices
(confirmed in real payload — Apple client with `model: []`). Do not depend on model
for family classification. `device` + `mfg` is more reliable.

**Schedule:** Daily at 00:00 via APScheduler.

---

### `event_collector.py`

**Purpose:** Pull all client events for the last 24hr, enrich with device metadata,
store in Redis.

**Mist API call:**
```
GET https://{MIST_CLOUD_HOST}/api/v1/sites/{site_id}/clients/events?limit=1000
```

**Pagination — GUARANTEED REQUIRED:** This endpoint will always require multiple pages
for any active site. Use the same cursor pattern as the client search endpoint — check
for a `next` field in each response and loop until absent.

```python
async def fetch_all_events(site_id: str) -> list[dict]:
    url = f"https://{MIST_CLOUD_HOST}/api/v1/sites/{site_id}/clients/events?limit=1000"
    all_events = []
    page = 0
    while url:
        resp = await httpx_client.get(url, headers=auth_headers)
        data = resp.json()
        batch = data.get("results", [])
        all_events.extend(batch)
        page += 1
        log.info(f"Events page {page}: {len(batch)} events, total so far: {len(all_events)}")
        next_path = data.get("next")
        url = f"https://{MIST_CLOUD_HOST}{next_path}" if next_path else None
    log.info(f"Event collection complete: {len(all_events)} total events")
    return all_events
```

The `next` cursor format confirmed from real API response:
```
/api/v1/sites/{site_id}/clients/search?end=...&limit=1000&search_after=[timestamp,+record_id]&start=...
```
Always use the `next` URL verbatim — the `search_after` parameter is a composite
cursor that cannot be reconstructed manually.

**Enrichment:** For each event, look up `mac` in the Redis client cache. Add fields:
- `device_family`
- `device_model`
- `device_manufacturer`

If MAC is not in client cache, attempt OUI lookup from the first 3 octets of the MAC
to get manufacturer. Set `device_family = "Unknown"`, `device_model = "Unknown"`.
Do not drop events for unknown MACs — they still contribute to site-wide DBSCAN.

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
`sasquatch:unknown_event_types:{site_id}` for review and future vector expansion.

---

### `feature_engineer.py`

**Purpose:** Build per-MAC feature vectors from the event stream.

**Input:** Redis `sasquatch:events:{site_id}`
**Output:** Redis `sasquatch:features:{site_id}`

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

#### ML Input: Raw Event Frequency Vector

**Design principle:** The ML models (Isolation Forest + DBSCAN) receive only raw,
assumption-free features. No pre-computed ratios, no chain completion logic, no
domain knowledge about what sequences "should" look like. The model discovers what
normal looks like from the population itself.

**Primary input — normalized event type frequency vector (59 dimensions):**

One dimension per known event type. Value = count of that event type for this MAC /
total events for this MAC. This is a probability distribution over event types.

```python
# For each MAC, build a vector like:
{
    "CLIENT_IP_ASSIGNED": 0.04,        # 4% of this client's events were DHCP success
    "CLIENT_AUTH_REASSOCIATION": 0.31, # 31% were successful roam reassociations
    "CLIENT_GW_ARP_OK": 0.18,          # etc.
    "MARVIS_EVENT_STA_LEAVING": 0.21,
    "CLIENT_DNS_OK": 0.18,
    "CLIENT_AUTHENTICATED": 0.08,
    "MARVIS_EVENT_CLIENT_AUTH_FAILURE": 0.0,
    # ... all 59 dimensions, zero-filled for absent types
}
```

The vector always sums to 1.0. Zero-fill for event types not seen for this MAC.
Use the event type index from Redis `sasquatch:event_type_index` to ensure consistent
vector ordering across all MACs and all runs.

**Secondary inputs — two timing features (assumption-free):**

| Feature | Type | Description |
|---|---|---|
| `median_inter_event_seconds` | float | Median time gap between consecutive events. Very low = machine-like burst activity. |
| `inter_event_cv` | float | Coefficient of variation (std/mean) of inter-event gaps. Low CV = suspiciously regular cadence. High CV = natural human/device variation. |

These two features capture temporal behavior without encoding any assumption about
which event types should or shouldn't appear together.

**Total ML input dimensionality: 61 features** (59 event type frequencies + 2 timing features).

**Normalization:** Apply StandardScaler across the full MAC population before passing
to Isolation Forest or DBSCAN. Fit on the full population per run. Do not persist the
scaler — refit each cycle.

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

**Stage 1 — DBSCAN (site-wide) + Family Centroid IF:**

DBSCAN runs per-MAC across all MACs in the WLAN scope:

```python
from sklearn.cluster import DBSCAN

db = DBSCAN(
    eps=float(os.getenv("ANOMALY_DBSCAN_EPS", "0.5")),
    min_samples=int(os.getenv("ANOMALY_DBSCAN_MIN_SAMPLES", "5"))
)
labels = db.fit_predict(full_feature_matrix)  # -1 = noise/outlier
```

DBSCAN label -1 means the MAC doesn't fit any cluster — a site-wide behavioral outlier
regardless of device type. Families with fewer than `ANOMALY_DBSCAN_MIN_FAMILY_SIZE`
(default 2) MACs are excluded from DBSCAN (too small to form a meaningful cluster).
DBSCAN sets `dbscan_label`, `is_dbscan_outlier`, and `dbscan_family_noise_ratio` on
each MAC record. These values are stored on anomaly records and used by the frontend,
but DBSCAN noise ratio no longer determines which families are flagged at the family level.

**`is_family_outlier` is set by the inter-family centroid detection step (separate from Stage 2):**

After DBSCAN, a centroid detection pass runs across family-level centroids. For each device
family with ≥ 2 MACs, a dual-representation row is built: element-wise median of all per-MAC
feature vectors concatenated with the component-wise maximum. This is then fed into one of
two methods depending on how many qualifying families are present:

- **N < `ANOMALY_CENTROID_IF_MIN_FAMILIES` (default 3):** Step skipped entirely. `is_family_outlier` remains False.
- **`ANOMALY_CENTROID_IF_MIN_FAMILIES` ≤ N ≤ `ANOMALY_CENTROID_DIST_MAX_FAMILIES` (default 10):** Cosine-distance fallback. Each family row is L2-normalized to a unit vector before computing distances (cosine distance is scale-invariant but requires non-zero-magnitude vectors — do NOT use StandardScaler here as it makes rows zero-mean and causes the median reference to approach the zero vector, producing spuriously high distances everywhere). The element-wise median of L2-normalized rows is re-normalized to a unit vector and used as the population reference. Each family's cosine distance from that reference is computed. Families exceeding `ANOMALY_CENTROID_DIST_THRESHOLD` (default 0.55) are flagged.
- **N > `ANOMALY_CENTROID_DIST_MAX_FAMILIES`:** Full `IsolationForest` run across all family centroid rows. Families with `decision_function < 0` are flagged.

**Healthy-only reference centroid:** Both the distance and IF paths support a health-aware
reference mode. Before centroid detection runs, `score()` / `score_org_wide()` computes
per-family mean health scores from the feature vectors. Families with mean health >=
`ANOMALY_CENTROID_HEALTHY_REF_THRESHOLD` (default 0.75) form the "healthy reference pool":

- **Distance path:** The reference centroid (element-wise median) is built from healthy
  families only. All families — including unhealthy ones — are measured against this
  healthy reference. This prevents a group of failing families from hiding behind each
  other: even if Awair, Raspberry Pi, and Texas Instruments all share the same auth-failure
  behavioral signature (and thus look "normal" relative to each other), their centroids
  point far from the healthy reference and get flagged.
- **IF path:** The IsolationForest is fitted on healthy family rows only, then all family
  rows are scored via `decision_function`. Families that don't resemble the healthy model
  score as anomalous.
- **Fallback:** If fewer than `ANOMALY_CENTROID_HEALTHY_REF_MIN` (default 2) families are
  healthy, both paths fall back to the standard all-family reference. The log line reports
  which mode ran each cycle.

The cosine-distance path exists because IF is statistically unreliable at small N (5–8 rows): contamination-derived thresholds carry little statistical meaning and scores can be noisy between cycles. The distance approach is simpler, more stable, and produces interpretable scores that can be logged and monitored.

Both paths populate `centroid_if_score` / `centroid_dist_score` and `centroid_detection_method` on anomaly records and findings so the method used is always observable.

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

**Stage 4 — Markov Chain stuck-loop detection (baseline-independent):**

In addition to the existing Markov episode analysis (event-level transition scoring,
episode-type sequence scoring, repeated-short-episode detection — all baseline-relative),
`markov_analyzer.py` includes a **stuck-loop detector** (`detect_stuck_loop()`) that runs
independently of the Markov baseline.

The stuck-loop detector counts all consecutive `(A→B)` event-type transition pairs across
a MAC's full event stream. If the single most common pair accounts for ≥
`MARKOV_STUCK_LOOP_THRESHOLD` (default 0.4) of all transitions AND at least one of the
two event types is a failure/disassoc type, the MAC is flagged `is_stuck_loop=True` →
`is_markov_outlier=True`.

This is critical for catching devices that contaminate their own Markov baseline: a device
cycling through `AUTH_FAILURE → DISASSOC` at 149k events will dominate the site-level
transition matrix, making that pattern appear "normal" to the baseline-relative scorer.
The stuck-loop detector ignores the baseline entirely — it flags based on absolute
transition concentration, so the contamination problem is bypassed.

New fields on anomaly records: `is_stuck_loop`, `stuck_loop_pair` (e.g.
`"MARVIS_EVENT_CLIENT_AUTH_FAILURE→CLIENT_DEAUTHENTICATION"`), `stuck_loop_fraction`.

**Finding rollup logic:**

After all stages, roll up to device family findings:
- For each device family: count `is_outlier` MACs / total MACs in family
- `is_outlier = is_if_outlier OR is_dbscan_outlier OR is_family_outlier OR is_markov_outlier`
- If outlier_ratio >= `ANOMALY_FINDING_THRESHOLD` (default 0.2), generate a finding
- Minimum family size to generate a finding:
  - Families that used org-level IF pooling: **MIN_PEERS** (`ANOMALY_MIN_PEERS`, default 3) — higher bar because cross-site data was borrowed; avoids hallucinated site findings driven by org noise
  - All others (site-local IF or IF skipped): **`ANOMALY_FINDING_MIN_SIZE`** (default 2) — even 2 devices flagged by centroid detection is real site signal worth reporting
- Top contributing features: mean comparison of outlier MACs vs non-outlier MACs in
  the same family. For family-wide outliers (all MACs flagged), compares against all
  other families at the site.
- **`predominant_wlan`**: when `wlan == "__all__"`, the finding includes a `predominant_wlan`
  field — the SSID that accounts for the majority of events across the outlier MACs,
  determined by counting `wlan` values in `mac_raw_events` for each outlier MAC. Set to
  `null` for scoped WLAN queries (where `finding.wlan` is already the exact SSID).
  In `score_org_wide()`, events are loaded from per-site Redis sets to compute the tally
  (loaded anyway for pattern classification in the non-family-outlier path; loaded
  additionally for the family-outlier path when in `__all__` mode).

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
Default alert threshold: `ANOMALY_HEALTH_SCORE_THRESHOLD = 0.75`.

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

### `webhook_dispatcher.py`

**Purpose:** Apply the dual alert gate and POST qualifying findings to the webhook URL.

**Dual alert gate — both conditions must be true to fire the webhook:**
1. `finding["is_family_outlier"] == True` — the centroid IF flagged the whole family as
   behaviorally different from all other device types. Single-device IF or DBSCAN outliers
   are visible in the UI but never trigger the webhook.
2. `family health_score < ANOMALY_HEALTH_SCORE_THRESHOLD` — the family is also measurably
   failing, not just behaviorally unusual.

Finding severity (`minimal` / `moderate` / `significant`) is informational — it is stored
on findings and displayed in the UI, but does not gate webhook dispatch.

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

**Webhook payload:**
```json
{
  "source": "sasquatch_client_anomaly",
  "site_id": "04edb3ac-542a-4d1d-ad90-b1e2fd682a67",
  "timestamp": "2025-01-15T14:32:00Z",
  "finding_count": 1,
  "findings": [
    {
      "device_family": "iPhone",
      "severity": "significant",
      "wlan": "Corp-WiFi",
      "outlier_ratio": 0.72,
      "affected_mac_count": 18,
      "is_family_outlier": true,
      "health_score": 0.61,
      "health_components": {"auth": 0.42, "roam": 0.08, "dhcp": 0.02, "dns": 0.01, "arp": 0.0},
      "example_macs": ["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"],
      "worst_health_macs": [
        {"mac": "aabbccddee01", "health_score": 0.21, "health_components": {"auth": 0.42}},
        {"mac": "aabbccddee02", "health_score": 0.34, "health_components": {"roam": 0.28}},
        {"mac": "aabbccddee03", "health_score": 0.41, "health_components": {"dhcp": 0.19}}
      ],
      "top_features": [
        {"feature": "AUTH_FAILURE", "outlier_mean": 0.38, "baseline_mean": 0.03},
        {"feature": "AUTH_SUCCESS", "outlier_mean": 0.12, "baseline_mean": 0.41}
      ],
      "probable_pattern": "auth_failure_terminal",
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
        {"mac": "aabbccddee02", "tshoot_results": [...]},
        {"mac": "aabbccddee03", "tshoot_results": [...]}
      ]
    }
  ]
}
```

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

### `scheduler.py`

**APScheduler jobs:**

```python
# Daily at midnight — refresh client cache
scheduler.add_job(client_refresh_job, 'cron', hour=0, minute=0)

# Every N minutes — collect events and run detection
scheduler.add_job(event_and_detect_job, 'interval',
                  minutes=int(os.getenv("SITE_FOCUS_DETECTION_INTERVAL", "15")))
```

`event_and_detect_job` runs these in sequence per WLAN scope (`__all__` + each unique SSID):
1. `event_collector.collect(site_id)`
2. `feature_engineer.build_features(site_id, wlan)`
3. `health_scorer.score_health(site_id, wlan)`   ← must run before webhook dispatch
4. `anomaly_detector.score(site_id, wlan)`
5. `webhook_dispatcher.evaluate_and_dispatch(site_id)`

The same sequence runs in `_run_wlan_detection_bg()` in `routes.py` (triggered by the
"Re-detect Anomalies" button). Any code path that calls `build_features` + `score` must
also call `score_health` in between, so health data is never stale relative to anomaly data.

If any step raises, log the error and skip remaining steps for that cycle. Do not
let one bad cycle corrupt Redis state from the previous good cycle.

---

### FastAPI Routes (`api/routes.py`)

```
GET  /api/v1/sites                                   → list configured sites from .env
GET  /api/v1/sites/{site_id}/findings                → current findings from Redis
GET  /api/v1/sites/{site_id}/health                  → per-family health scores from Redis
GET  /api/v1/sites/{site_id}/clients                 → client list with device type breakdown
GET  /api/v1/sites/{site_id}/events/summary          → event category counts for GUI charts
GET  /api/v1/sites/{site_id}/anomalies/{mac}         → full event timeline + scores for one MAC
GET  /api/v1/sites/{site_id}/families/{family}/if-outliers → per-family IF deviation list
POST /api/v1/sites/{site_id}/refresh                 → manually trigger client cache refresh
GET  /api/v1/sites/{site_id}/status                  → last run timestamp, event count, finding count

GET  /api/v1/org/summary                             → per-site event counts, finding counts, alert_count,
                                                       plus org-wide finding counts (org_significant_count,
                                                       org_moderate_count, org_minimal_count, org_alert_count,
                                                       org_finding_count) read from sasquatch:org_findings:{wlan}
POST /api/v1/org/detect                              → re-runs build_features + score_health + score (per-site) for all
                                                       sites, then score_org_wide; updates both per-site findings
                                                       (sasquatch:findings:{site_id}:{wlan}) and org findings
GET  /api/v1/org/alerts                              → org-wide alerts + per-site alerts in one response;
                                                       org_alerts = org findings with health_score < 0.75;
                                                       site_alerts = per-site findings × per-site health, grouped by site
GET  /api/v1/org/alert-history?days=7&wlan=__all__   → alert session history grouped by UTC day; sessions spanning
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

**1. Site Overview (`SiteOverview.jsx`)**
- Heatmap: rows = device families, columns = event categories, cell = failure ratio
- Color scale: green (0%) → yellow → red (100%)
- Anomaly badge per device family row (`family` / `significant` / `moderate` / OK)
- **Health column**: bar + percentage showing family health score (green ≥85%, yellow 75–85%, orange 55–75%, red <55%). Hover for per-category breakdown.
- Data source: `events/summary` + `findings` + `health` (three concurrent fetches)
- Auto-refreshes every 60s

**2. Org Family Insights (`OrgFamilyInsights.jsx`)**
- Same heatmap layout but aggregated across all org sites
- Anomaly badge reflects worst finding across all sites for that family
- **Health column**: mac_count-weighted average health score from all sites (each device equal vote). Hover tooltip shows per-category failure rates.
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
- Each alert card shows a **WLAN/SSID badge** (green pill) after the pattern label. For scoped WLAN queries the badge shows `finding.wlan`; for `__all__` scope it shows `finding.predominant_wlan` — the SSID carrying the majority of outlier MAC events, computed at finding-rollup time from raw event WLAN counts.
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
- **Org Overview tab**: Site cards sorted by `event_count` descending (highest-traffic sites first); sites with no data sort to the bottom. Site card alert state uses the dual-gate: a site is "Alert" (red) only when `alert_count > 0`.
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
MIST_SITE_ID=04edb3ac-542a-4d1d-ad90-b1e2fd682a67
MIST_ORG_ID=3549f835-42c3-40d1-90cc-5e70ccc537ee

# Redis
REDIS_URL=redis://localhost:6379

# Scheduling
SITE_FOCUS_DETECTION_INTERVAL=15

# ML Tuning — Isolation Forest + DBSCAN
ANOMALY_IF_CONTAMINATION=0.05
ANOMALY_DBSCAN_EPS=2.5
ANOMALY_DBSCAN_MIN_SAMPLES=5
ANOMALY_DBSCAN_MIN_FAMILY_SIZE=5
ANOMALY_FINDING_THRESHOLD=0.2
ANOMALY_MIN_PEERS=5
ANOMALY_MIN_MAC_EVENTS=20
ANOMALY_CENTROID_IF_MIN_FAMILIES=3
ANOMALY_CENTROID_DIST_MAX_FAMILIES=10  # sites with ≤ this many families use cosine-distance; above uses IF
ANOMALY_CENTROID_DIST_THRESHOLD=0.55   # cosine distance (L2-normalized unit vectors) above which a family centroid is flagged
ANOMALY_CENTROID_HEALTHY_REF_THRESHOLD=0.75  # families below this health excluded from centroid reference population
ANOMALY_CENTROID_HEALTHY_REF_MIN=2     # minimum healthy families to activate healthy-only reference; otherwise all-family

# Markov Chain stuck-loop detector (markov_analyzer.py)
MARKOV_STUCK_LOOP_THRESHOLD=0.4        # fraction of transitions dominated by one failure pair to flag stuck-loop
MARKOV_STUCK_LOOP_MIN_EVENTS=20        # minimum events before stuck-loop detection runs

# Health Score (health_scorer.py)
# Families with health_score below this value are considered degraded for webhook gating.
# Range: 0.0 (all failing) to 1.0 (no failures). Tune down if too noisy.
ANOMALY_HEALTH_SCORE_THRESHOLD=0.75

# Webhook — dual gate: is_family_outlier AND health_score < threshold.
# Any severity triggers dispatch — severity is informational only.
ANOMALY_WEBHOOK_URL=https://project-sasquatch-production.up.railway.app/webhook/anomaly

# Frontend
VITE_API_BASE_URL=http://localhost:8000
```

---

## Org-Level Scope

Org-wide cross-site detection is fully implemented. When `MIST_ORG_ID` is configured,
`org_cross_site_detect_job` runs every `ORG_DETECTION_INTERVAL_HOURS` (default: 6h) and:
1. Collects events for every site in the org
2. Builds features + health scores for every site
3. Pools all MACs org-wide and runs DBSCAN, Centroid IF, and per-family IF against the
   combined population — each MAC is scored relative to all org peers, not just its own site
4. Stores results under `sasquatch:org_anomalies:{site_id}:{wlan_key}` and `sasquatch:org_findings:{wlan_key}`
5. Dispatches a single org-wide webhook from the combined findings

The org-level pipeline uses the same `score_org_wide()` function in `anomaly_detector.py`
and the same dual alert gate in `webhook_dispatcher.py`.

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

1. **`client_cache.py`** — Get the MAC → device metadata lookup working and verify
   Redis writes. Test against the live Mist API manually before wiring the scheduler.

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
