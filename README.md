# Project Sasquatch — Client Anomaly Detection

Unsupervised anomaly detection for Juniper Mist wireless networks. Detects device behavior that aggregate SLE metrics miss — clients stuck in DHCP loops, stale PMKIDs causing roam failures, entire device families silently failing DNS.

**Core insight:** an iPhone behaving nothing like other iPhones at the same site is the signal.

---

## How It Works

On a configurable interval (default: 60 minutes), Sasquatch:

1. Pulls the last 24 hours of client events from the Mist API (paginated, enriched with device metadata)
2. Builds a per-MAC behavioral feature vector — normalized event type frequencies, so volume is never the signal
3. Runs a four-stage ML pipeline:
   - **DBSCAN** across all MACs site-wide (finds clients that don't fit any cluster)
   - **Family Centroid Isolation Forest** across device-family centroids (finds families behaving differently from all other families)
   - **Per-family Isolation Forest** within each device type (finds individual devices anomalous relative to their peers)
   - **Markov Chain episode analysis** — scores event-transition sequences within episodes against a 24hr site baseline; flags families where a large fraction of clients show anomalous connection patterns or repeated short (failed) episodes
4. Computes a **separate** per-family health score from failure ratios — independent of anomaly detection
5. Fires a webhook only when a family carries **any** anomaly label (centroid IF, DBSCAN noise, or Markov) **and** is unhealthy (health score < 0.75) — dual-gate to prevent single-device noise

Results are stored in Redis and served through a React dashboard with org-wide and per-site views.

**No data egresses to third-party AI providers.** Detection is pure ML + rule-based.

---

## Architecture

```
Mist API
  ├── client_cache.py (daily)      ─→ Redis: MAC → {family, model, os, manufacturer}
  └── event_collector.py (15 min)  ─→ Redis: sorted set of enriched events

                    feature_engineer.py
                          ↓
           Redis: per-MAC feature vectors + health scores

                    anomaly_detector.py
                    (DBSCAN → Centroid IF → Per-family IF → Markov)
                          ↓
              Redis: anomaly scores + findings

          webhook_dispatcher.py (dual gate)
          ├── POST webhook (if eligible)
          └── FastAPI routes → React dashboard
```

| Layer | Technology |
|---|---|
| Backend | FastAPI + APScheduler (Python) |
| Frontend | React + Vite |
| State / Cache | Redis 7+ |
| ML | scikit-learn — IsolationForest, DBSCAN; numpy Markov Chain |
| Feature Engineering | pandas, numpy |
| Mist API Client | httpx (async) |

---

## Prerequisites

- Python 3.10+
- Node.js 18+
- Redis 7+
- Juniper Mist API token + site/org IDs

---

## Quick Start

```bash
cd unsupervised_anomaly

# One-time setup: installs venv, npm deps, builds frontend
./setup.sh

# Copy and fill in your credentials
cp .env.example .env
$EDITOR .env

# Start everything (Redis, backend on :8000, frontend on :3000)
./start.sh
```

Open [http://localhost:3000](http://localhost:3000).

To stop all services:

```bash
./stop.sh
```

---

## Manual Install

```bash
# Backend
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

# Frontend
cd sasquatch/frontend
npm install
npm run build
cd ../..

# Start backend
PORT=8000 .venv/bin/uvicorn main:app --app-dir sasquatch --host 0.0.0.0

# Start frontend (separate terminal)
cd sasquatch/frontend
npx serve dist --listen 3000
```

API docs (Swagger): [http://localhost:8000/docs](http://localhost:8000/docs)

---

## Configuration

Copy `.env.example` to `.env`. Variables are grouped below by concern.

### Mist API

| Variable | Description |
|---|---|
| `MIST_API_TOKEN` | Mist API token with read access to client events |
| `MIST_CLOUD_HOST` | Regional API host — `api.mist.com`, `api.gc1.mist.com`, `api.gc4.mist.com`, `api.eu.mist.com`, etc. Do **not** include `/api/v1`. |
| `MIST_SITE_ID` | UUID of the primary site to monitor |
| `MIST_ORG_ID` | UUID of the org — enables org-wide cross-site detection |

### Scheduling

| Variable | Default | Description |
|---|---|---|
| `SITE_FOCUS_DETECTION_INTERVAL` | `60` | How often (minutes) to pull the latest events from Mist and run the full detection pipeline for the currently focused site. Each run pulls only the **last hour** of events from the Mist API and appends them to the rolling 24-hour Redis dataset — scoring always runs against the full 24-hour window. Lower values = more frequent detection but more Mist API calls. |
| `ORG_DETECTION_INTERVAL_HOURS` | `1` | How often (hours) to run the org-wide cross-site detection job. Each run pulls the last N hours of events per site from Mist (where N = this interval), then scores all sites against each other from Redis. Default of 1 hour matches the per-site cadence and spreads API calls evenly — a larger interval (e.g. 6h) is worse for rate limits because it concentrates the same total API calls into a single burst. Mist enforces ~5,000 calls/hr/token. Org detection can also be disabled entirely from the GUI for single-site focus on large orgs. |

### ML Tuning — Isolation Forest

| Variable | Default | Description |
|---|---|---|
| `ANOMALY_IF_CONTAMINATION` | `0.1` | Fraction of MACs within a device family expected to be outliers (Stage 2 — intra-family IF). Lower = stricter, fewer individual MACs flagged. Range: 0.01–0.5. |
| `ANOMALY_CENTROID_IF_CONTAMINATION` | `0.15` | Fraction of device families expected to be behavioral outliers (inter-family centroid IF). Intentionally higher than `IF_CONTAMINATION` — at a site with a real problem, 1 in 6–8 families being anomalous is plausible. |
| `ANOMALY_IF_N_ESTIMATORS` | `100` | Number of trees in every IsolationForest. More trees = more stable scores at diminishing returns. Increase to 200–500 if scores are noisy across consecutive cycles. |
| `ANOMALY_RANDOM_STATE` | `42` | Global random seed for all ML components (IsolationForest, PCA). Fixed integer gives reproducible scores across cycles. Set to `-1` to use a random seed each run. |
| `ANOMALY_MIN_PEERS` | `5` | Minimum MACs a device family must have at a site before per-family IF runs. Families below this are eligible for org-level pooling; if still short after pooling, IF is skipped. |

### ML Tuning — DBSCAN

| Variable | Default | Description |
|---|---|---|
| `ANOMALY_DBSCAN_PCA_VARIANCE` | `0.95` | Fraction of variance PCA must retain when reducing dimensions before DBSCAN. The 61-dim feature vectors are sparse; PCA typically collapses to 8–15 components at 0.95. Does not affect IsolationForest. |
| `ANOMALY_DBSCAN_EPS` | `0.5` | Maximum distance between two MACs (in PCA-reduced, StandardScaler-normalized space) to be considered neighbors. Higher = larger clusters (less noise). Lower = tighter clusters (more noise points). |
| `ANOMALY_DBSCAN_MIN_SAMPLES` | `5` | Minimum neighbors within `eps` for a point to be a core point. Lower = easier to form clusters. |
| `ANOMALY_DBSCAN_MIN_FAMILY_SIZE` | `5` | Minimum MACs a device family must have to participate in site-wide DBSCAN. Families smaller than this are excluded (too small to anchor a cluster) but still go through Isolation Forest. |
| `ANOMALY_DBSCAN_FAMILY_NOISE_THRESHOLD` | `0.5` | Fraction of a family's MACs that must be DBSCAN noise before the family is considered a DBSCAN-level outlier. Stored on anomaly records and shown in the UI; does **not** control `is_family_outlier` (that is set by centroid IF). |

### ML Tuning — Family Centroid Detection

| Variable | Default | Description |
|---|---|---|
| `ANOMALY_CENTROID_IF_MIN_FAMILIES` | `3` | Minimum qualifying device families (each with ≥ `ANOMALY_MIN_PEERS` MACs) before any inter-family centroid detection runs. Below this the step is skipped and `is_family_outlier` remains False for all families. |
| `ANOMALY_CENTROID_DIST_MAX_FAMILIES` | `8` | Upper bound for the cosine-distance fallback path. Sites with 3–8 qualifying families use distance-from-median instead of IsolationForest (IF is statistically unreliable at small N). Sites above this use full IF. |
| `ANOMALY_CENTROID_DIST_THRESHOLD` | `0.55` | Cosine distance from the L2-normalized population median above which a family centroid is flagged as a behavioral outlier (`is_family_outlier = True`). Vectors are L2-normalized (not StandardScaler) before distance computation. Range: 0.0–1.0. Higher = less sensitive. |

### ML Tuning — Markov Chain

| Variable | Default | Description |
|---|---|---|
| `MARKOV_MIN_EPISODE_LENGTH` | `3` | Episodes shorter than this number of events go into the short-episode state machine and are not scored against the transition matrix. Short episodes represent connection attempts that never completed a full connectivity chain. |
| `MARKOV_EPISODE_LOG_PROB_THRESHOLD` | `-4.0` | Mean log-probability per transition below which an episode is flagged anomalous. More negative = stricter. Default of -4.0 means geometric-mean per-transition probability below e⁻⁴ ≈ 0.018. |
| `MARKOV_OUTLIER_EPISODE_RATIO` | `0.5` | Fraction of a MAC's scoreable normal episodes that must be anomalous to flag the MAC as a Markov outlier. |
| `MARKOV_FAMILY_OUTLIER_RATIO` | `0.5` | Fraction of a family's evaluatable MACs that must be Markov outliers to flag the family (`is_family_markov_outlier = True`). A flagged family can generate a finding even if its combined IF/DBSCAN outlier ratio is below `ANOMALY_FINDING_THRESHOLD`. |

### ML Tuning — Finding Rollup

| Variable | Default | Description |
|---|---|---|
| `ANOMALY_FINDING_THRESHOLD` | `0.3` | Minimum fraction of a family's MACs that must be flagged as outliers (by any of IF, DBSCAN, or centroid IF) before a finding is generated. Severity: minimal (0–0.3), moderate (0.3–0.6), significant (>0.6). |
| `ANOMALY_FINDING_MIN_SIZE` | `2` | Minimum local MACs before a site-level finding is generated. Applies to families that did **not** use org-level IF pooling. Families that did use org pooling use `ANOMALY_MIN_PEERS` as their minimum instead (higher bar — cross-site data was borrowed). |

### ML Tuning — Feature Engineering

| Variable | Default | Description |
|---|---|---|
| `ANOMALY_MIN_MAC_EVENTS` | `5` | Minimum events a MAC must have in the 24hr window to be included in the ML feature matrix. Higher = only analyze devices with meaningful activity; lower = include briefly-seen/transient devices. |
| `CACHE_MISS_REFRESH_THRESHOLD` | `10` | Number of MAC-to-device-family cache misses that can accumulate before the event collector triggers an early client cache refresh. Prevents stale device classification mid-cycle. |

### Health Score

| Variable | Default | Description |
|---|---|---|
| `ANOMALY_HEALTH_SCORE_THRESHOLD` | `0.75` | Per-family health score below this value = unhealthy. Webhook alerts require **both** `is_family_outlier = True` **and** `health_score < threshold`. Formula: `1.0 - (failures / (successes + failures))` across AUTH, ROAM, DHCP, DNS, and ARP. **Note:** also hardcoded in `FindingsFeed.jsx`, `OrgFindingsFeed.jsx`, and `OrgAlerts.jsx` — update those if this threshold changes. |

### Webhook

| Variable | Default | Description |
|---|---|---|
| `ANOMALY_WEBHOOK_URL` | _(empty)_ | Endpoint to POST alerts. Leave empty to disable dispatch — alert sessions are still recorded in Redis. |
| `ANOMALY_WEBHOOK_SEVERITY_THRESHOLD` | `significant` | Minimum finding severity to dispatch a webhook. Valid values: `minimal`, `moderate`, `significant`. Severity is derived from `outlier_ratio`: minimal (0–0.3), moderate (0.3–0.6), significant (>0.6). |

### App Auth & Frontend

| Variable | Default | Description |
|---|---|---|
| `APP_USERNAME` | — | HTTP Basic Auth username for the dashboard |
| `APP_PASSWORD` | — | HTTP Basic Auth password for the dashboard |
| `VITE_API_BASE_URL` | `http://localhost:8000` | Backend URL used by the React frontend at build time |

---

## Feature Design

Feature vectors are probability distributions over Mist event types — each value is `count(event_type) / total_events` for that MAC. Volume is never a signal.

**61-dimensional ML input:**
- 59 dimensions: normalized frequency per Mist client event type (DHCP, DNS, auth, roam, ARP, disassoc, etc.)
- 2 dimensions: `median_inter_event_seconds`, `inter_event_cv` (timing behavior)

**Post-hoc explainer features** (computed only after a MAC is flagged, never fed to ML):
PMKID failure ratio, DHCP XID counts, roam failure types — used to generate human-readable `probable_pattern` labels like `pmkid_stale`, `dhcp_discard_loop`, `auth_failure_terminal`.

---

## Alert Logic

Webhooks fire only when **all three** conditions are met for a device family:

1. Any family-level anomaly label is set — at least one of:
   - `is_family_outlier` — centroid IF/distance flagged the whole family as behaviorally different from all other device types
   - `is_family_dbscan_outlier` — fraction of DBSCAN-noise MACs in the family exceeds the noise threshold
   - `is_family_markov_outlier` — Markov Chain analysis found anomalous event-chain patterns in ≥ `MARKOV_FAMILY_OUTLIER_RATIO` of the family's clients
2. `health_score < 0.75` — family is also measurably failing
3. `severity >= significant` (configurable)

Single-device IF outliers without a family-level flag appear in the UI but never trigger webhooks.

### Marvis TSHOOT Enrichment

Before posting the webhook, Sasquatch calls the Mist Marvis TSHOOT API for the three worst-health MACs in each qualifying finding. All TSHOOT calls are issued concurrently. Results are attached to the finding payload as `marvis_tshoot`:

```json
"marvis_tshoot": [
  {
    "mac": "aabbccddee01",
    "tshoot_results": [
      {
        "category": "Client",
        "reason": "Failed Fast Roam",
        "text": "The client failed fast roam 25% of the time...",
        "site_id": "12f333fe-..."
      },
      {
        "category": "Connectivity",
        "reason": "Poor Coverage",
        "text": "Due to the device connecting at a low signal strength.",
        "recommendation": "1. Ensure sufficient AP coverage. 2. Check for sticky client behavior.",
        "site_id": "12f333fe-..."
      }
    ]
  }
]
```

TSHOOT failures for individual MACs return an empty `tshoot_results` list without blocking the webhook. The field is omitted entirely if `MIST_ORG_ID` or `MIST_API_TOKEN` are not set.

---

## Dashboard

| View | Description |
|---|---|
| **Site Overview** | Heatmap of device families × event categories. Separate IF / DB / Markov anomaly columns and a health bar per row. Auto-refreshes every 60s. |
| **Findings Feed** | Four detector sections: IF CENTROID (centroid/distance outliers), DBSCAN % OF FAMILY, MARKOV % OF FAMILY, and HEALTH (unhealthy families with no anomaly finding). |
| **Org Overview** | Four-tab shell: Org Alerts, Org Overview, Org Family Insights, Org Findings. |
| **Org Alerts** | Org-wide alerts grouped by family; site alerts grouped by site. Default org view. |
| **MAC Drilldown** | 24hr event timeline + feature vector vs family baseline + IF score + DBSCAN label + Markov episode stats. |
| **Family Drilldown** | Per-MAC breakdown for a device family at a site or across the org. |

---

## API Endpoints

All reads come from Redis — no real-time Mist API calls in the request path.

```
GET  /api/v1/sites
GET  /api/v1/sites/{site_id}/findings
GET  /api/v1/sites/{site_id}/health
GET  /api/v1/sites/{site_id}/events/summary
GET  /api/v1/sites/{site_id}/anomalies/{mac}
POST /api/v1/sites/{site_id}/refresh
GET  /api/v1/org/summary
GET  /api/v1/org/alerts
GET  /api/v1/org/findings
GET  /api/v1/org/family-insights
POST /api/v1/org/detect
```

---

## Redis Key Schema

| Key | TTL | Contents |
|---|---|---|
| `sasquatch:clients:{site_id}` | 7 days | MAC → device metadata (family, model, OS, manufacturer) |
| `sasquatch:events:{site_id}` | 7 days | Sorted set of enriched events scored by Unix timestamp |
| `sasquatch:wlans:{site_id}` | 7 days | Unique SSIDs seen at site |
| `sasquatch:features:{site_id}:{wlan}` | 24 hr | Per-MAC feature vectors |
| `sasquatch:anomalies:{site_id}:{wlan}` | 24 hr | Per-MAC anomaly scores + outlier flags |
| `sasquatch:health:{site_id}:{wlan}` | 24 hr | Per-family health scores + category breakdown |
| `sasquatch:findings:{site_id}:{wlan}` | 24 hr | Rolled-up per-family findings |
| `sasquatch:org_findings:{wlan}` | 24 hr | Cross-site findings (one entry per family across all sites) |
| `sasquatch:markov_baseline:{site_id}:{wlan}` | 48 hr | Markov transition matrices + episode-type state machine built from 24hr events |

Detection runs independently for each unique SSID — there is no combined cross-WLAN scope. All API endpoints require an explicit `?wlan=` parameter.

---

## Project Structure

```
unsupervised_anomaly/
├── sasquatch/
│   ├── client_anomaly/
│   │   ├── client_cache.py          # Daily MAC → device metadata refresh
│   │   ├── event_collector.py       # 24hr event pull, enrichment, deduplication
│   │   ├── feature_engineer.py      # Per-MAC behavioral feature vectors
│   │   ├── anomaly_detector.py      # Four-stage ML pipeline + finding rollup
│   │   ├── markov_analyzer.py       # Markov Chain episode analysis (Stage 4)
│   │   ├── health_scorer.py         # Per-family failure rate scoring (independent)
│   │   ├── webhook_dispatcher.py    # Dual-gate alert dispatch
│   │   ├── scheduler.py             # APScheduler job definitions
│   │   ├── oui_lookup.py            # Local IEEE OUI database (no network calls)
│   │   └── api/
│   │       └── routes.py            # FastAPI route definitions
│   ├── frontend/
│   │   └── src/
│   │       ├── App.jsx
│   │       └── components/
│   │           ├── SiteOverview.jsx
│   │           ├── FindingsFeed.jsx
│   │           ├── OrgOverview.jsx
│   │           ├── OrgAlerts.jsx
│   │           ├── OrgFamilyInsights.jsx
│   │           ├── MacDrilldown.jsx
│   │           └── FamilyDrilldown.jsx
│   └── main.py
├── setup.sh
├── start.sh
├── stop.sh
├── requirements.txt
└── .env.example
```

---

## Known Issues

See [TODO.md](unsupervised_anomaly/TODO.md) for the tracked backlog. Active items include:

- Cache refresh failures have no retry or operator alerting
- `device_family` classification uses first event only (should use majority vote)
- Auth burst → recovery sequences inflate health scores (transient retries before success)
- "Collecting Events" progress bar no longer updates in the UI
- Markov baseline requires one full detection cycle to warm up — first run after deployment skips Markov scoring

---

## Security Notes

- Data never egresses to third-party LLM providers. All ML is local.
- The API has HTTP Basic Auth (`APP_USERNAME` / `APP_PASSWORD`). Put it behind a reverse proxy with TLS in production.
- Redis has no auth by default — bind to localhost or use `requirepass` in production.
