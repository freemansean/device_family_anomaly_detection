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
4. Running Isolation Forest (per device type) + DBSCAN (site-wide) to surface outliers
5. Rolling up MAC-level anomalies to device type findings
6. Exposing findings via a React + FastAPI dashboard
7. Firing a webhook for extreme anomalies to the Sasquatch processing pipeline

**This module has NO LLM in the detection path.** Pure ML only. Isolation Forest + DBSCAN.
LLMs (Sonnet/Haiku) only enter if a finding is escalated into the existing Sasquatch RCA
pipeline via the webhook. Do not add LLM calls to any detection or scoring code.

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

## Project Structure

```
sasquatch/
├── client_anomaly/
│   ├── __init__.py
│   ├── client_cache.py          # Daily client list refresh → Redis
│   ├── event_collector.py       # 24hr event pull + MAC enrichment → Redis
│   ├── feature_engineer.py      # Per-MAC feature vector construction
│   ├── anomaly_detector.py      # Isolation Forest + DBSCAN scoring
│   ├── webhook_dispatcher.py    # Threshold evaluation + webhook POST
│   ├── scheduler.py             # APScheduler job definitions
│   └── api/
│       ├── __init__.py
│       └── routes.py            # FastAPI route definitions
├── frontend/
│   └── src/
│       ├── components/
│       │   ├── SiteOverview.jsx     # Heatmap: event categories × device types
│       │   ├── FindingsFeed.jsx     # Ranked anomaly findings list
│       │   └── MacDrilldown.jsx     # Per-MAC 24hr timeline + feature breakdown
│       └── App.jsx
├── .env                         # See env vars section below
└── CLAUDE.md                    # This file
```

---

## Redis Key Schema

| Key | TTL | Contents |
|---|---|---|
| `sasquatch:clients:{site_id}` | 25hr | JSON dict: MAC → {model, os, manufacturer, family} |
| `sasquatch:events:{site_id}` | 24hr | JSON array: enriched event objects |
| `sasquatch:features:{site_id}` | 24hr | JSON dict: MAC → feature vector dict |
| `sasquatch:anomalies:{site_id}` | 24hr | JSON dict: MAC → {if_score, dbscan_label, is_outlier} |
| `sasquatch:findings:{site_id}` | 24hr | JSON array: rolled-up findings for GUI + webhook |

**TTL note:** Client cache is 25hr (not 24hr) to provide a buffer so the daily refresh
job can run before the key expires. All other keys are 24hr.

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

**Purpose:** Score each MAC using Isolation Forest (within device family) and DBSCAN
(across all MACs). Produce per-MAC anomaly scores and roll up to device type findings.

**Stage 1 — Isolation Forest (per device family):**

```python
from sklearn.ensemble import IsolationForest

# Run separately for each device_family group with >= MIN_PEERS MACs
MIN_PEERS = 5  # Don't run IF on a family with fewer than 5 MACs — not enough signal

clf = IsolationForest(
    contamination=float(os.getenv("ANOMALY_IF_CONTAMINATION", "0.1")),
    random_state=42,
    n_estimators=100
)
scores = clf.fit_predict(feature_matrix)  # -1 = outlier, 1 = normal
raw_scores = clf.decision_function(feature_matrix)  # continuous score
```

For families below MIN_PEERS, set `if_score = None`, `is_if_outlier = False`.

**Stage 2 — DBSCAN (site-wide):**

```python
from sklearn.cluster import DBSCAN

db = DBSCAN(
    eps=float(os.getenv("ANOMALY_DBSCAN_EPS", "0.5")),
    min_samples=int(os.getenv("ANOMALY_DBSCAN_MIN_SAMPLES", "5"))
)
labels = db.fit_predict(full_feature_matrix)  # -1 = noise/outlier
```

DBSCAN label -1 means the MAC doesn't fit any cluster — a site-wide behavioral outlier
regardless of device type. This catches the "all HP printers are failing DNS" case where
the entire printer family is an outlier from the site population.

**Finding rollup logic:**

After scoring all MACs, roll up to device family findings:
- For each device family: count `is_outlier` MACs / total MACs in family
- If outlier_ratio > `ANOMALY_FINDING_THRESHOLD` (default 0.3), generate a finding
- A finding includes: family, outlier_ratio, top contributing features, example MACs
- Top contributing features: identify which feature dimensions are most extreme for
  the outlier MACs vs the non-outlier MACs in the same family (simple mean comparison)

**Finding severity:**
- `INFO`: outlier_ratio 0.1–0.3
- `WARNING`: outlier_ratio 0.3–0.6
- `CRITICAL`: outlier_ratio > 0.6

Only `CRITICAL` findings trigger the webhook by default. Configurable via
`ANOMALY_WEBHOOK_SEVERITY_THRESHOLD` in `.env`.

---

### `webhook_dispatcher.py`

**Purpose:** POST findings that exceed the severity threshold to the configured webhook URL.

**Webhook payload:**
```json
{
  "source": "sasquatch_client_anomaly",
  "site_id": "04edb3ac-542a-4d1d-ad90-b1e2fd682a67",
  "timestamp": "2025-01-15T14:32:00Z",
  "finding_count": 2,
  "findings": [
    {
      "device_family": "iPhone",
      "severity": "CRITICAL",
      "outlier_ratio": 0.72,
      "affected_mac_count": 18,
      "example_macs": ["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"],
      "top_features": [
        {"feature": "repetition_score", "outlier_mean": 0.84, "baseline_mean": 0.12},
        {"feature": "failure_ratio_dhcp", "outlier_mean": 0.91, "baseline_mean": 0.03}
      ],
      "probable_pattern": "dhcp_loop"
    }
  ]
}
```

**`probable_pattern` field:** Derive from top contributing features using rule-based
lookup — NO LLM. Evaluated in priority order (first match wins):

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

---

### `scheduler.py`

**APScheduler jobs:**

```python
# Daily at midnight — refresh client cache
scheduler.add_job(client_refresh_job, 'cron', hour=0, minute=0)

# Every N minutes — collect events and run detection
scheduler.add_job(event_and_detect_job, 'interval',
                  minutes=int(os.getenv("DETECTION_INTERVAL_MINUTES", "15")))
```

`event_and_detect_job` runs these in sequence:
1. `event_collector.collect(site_id)`
2. `feature_engineer.build_features(site_id)`
3. `anomaly_detector.score(site_id)`
4. `webhook_dispatcher.evaluate_and_dispatch(site_id)`

If any step raises, log the error and skip remaining steps for that cycle. Do not
let one bad cycle corrupt Redis state from the previous good cycle.

---

### FastAPI Routes (`api/routes.py`)

```
GET  /api/v1/sites                              → list configured sites from .env
GET  /api/v1/sites/{site_id}/findings           → current findings from Redis
GET  /api/v1/sites/{site_id}/clients            → client list with device type breakdown
GET  /api/v1/sites/{site_id}/events/summary     → event category counts for GUI charts
GET  /api/v1/sites/{site_id}/anomalies/{mac}    → full event timeline + scores for one MAC
POST /api/v1/sites/{site_id}/refresh            → manually trigger client cache refresh
GET  /api/v1/sites/{site_id}/status             → last run timestamp, event count, finding count
```

All responses are JSON. All reads come from Redis — no real-time Mist API calls in the
request path. The API is read-only except for the manual refresh POST.

---

### React Frontend — Three Views

**1. Site Overview (`SiteOverview.jsx`)**
- Heatmap: rows = device families, columns = event categories, cell = failure ratio
- Color scale: green (0%) → yellow → red (100%)
- Anomaly score badge per device family row (INFO / WARNING / CRITICAL)
- Data source: `/api/v1/sites/{site_id}/events/summary` + `/api/v1/sites/{site_id}/findings`
- Auto-refreshes every `DETECTION_INTERVAL_MINUTES`

**2. Findings Feed (`FindingsFeed.jsx`)**
- Ranked list of active findings, highest severity first
- Each card shows: device family, severity badge, outlier ratio, top feature evidence,
  affected MAC count, timestamp
- Expandable to show example MACs with links to MAC drill-down view
- Data source: `/api/v1/sites/{site_id}/findings`

**3. MAC Drill-down (`MacDrilldown.jsx`)**
- 24hr event timeline (chronological event list with timestamps and types)
- Feature vector bar chart vs. family baseline
- Isolation Forest score and DBSCAN label display
- Navigation: accessible by clicking a MAC in the Findings Feed
- Data source: `/api/v1/sites/{site_id}/anomalies/{mac}`

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
DETECTION_INTERVAL_MINUTES=15

# ML Tuning
ANOMALY_IF_CONTAMINATION=0.1
ANOMALY_DBSCAN_EPS=0.5
ANOMALY_DBSCAN_MIN_SAMPLES=5
ANOMALY_FINDING_THRESHOLD=0.3
ANOMALY_MIN_PEERS=5

# Webhook
ANOMALY_WEBHOOK_URL=https://project-sasquatch-production.up.railway.app/webhook/anomaly
ANOMALY_WEBHOOK_SEVERITY_THRESHOLD=CRITICAL

# Frontend
VITE_API_BASE_URL=http://localhost:8000
```

---

## Org-Level Scope (Future Enhancement)

The same client search and event endpoints exist at org level:
```
GET https://{MIST_CLOUD_HOST}/api/v1/orgs/{org_id}/clients/search?limit=1000
GET https://{MIST_CLOUD_HOST}/api/v1/orgs/{org_id}/clients/events?limit=1000
```
Pagination behavior is identical. v1 of this module targets a single site via
`MIST_SITE_ID`. Org-level monitoring (all sites in one poll) is a natural v2
enhancement — the architecture supports it by parameterizing `site_id` throughout.

---

## Known Mist API Notes

- Site ID in use: `04edb3ac-542a-4d1d-ad90-b1e2fd682a67` (REMOTE_SITE)
- Org ID: `3549f835-42c3-40d1-90cc-5e70ccc537ee`
- The Live-Demo Cupertino env (org `9777c1a0-6ef6-11e6-8bbf-02e208b2d34f`) has known
  chronic issues (vSRX disconnects, STP loop, DHCP VLAN 2 failures) — useful for
  testing anomaly detection since real anomalies exist there
- Client events endpoint returns up to 1000 per page — always paginate
- `duration` parameter accepts strings like `"1d"`, `"24h"`, `"86400"` (seconds)

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

- No LLM in the detection, scoring, or webhook path
- No SLE data — client event stream only
- No per-AP correlation (future enhancement)
- No real-time Mist API calls in the FastAPI request path — reads from Redis only
- No authentication on the FastAPI/React interface (internal tool)
- No multi-site support in v1 — single MIST_SITE_ID from .env is sufficient
