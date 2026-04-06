# Project Sasquatch — Client Anomaly Detection

Unsupervised anomaly detection for Juniper Mist wireless networks. Detects device behavior that aggregate SLE metrics miss — clients stuck in DHCP loops, stale PMKIDs causing roam failures, entire device families silently failing DNS.

**Core insight:** an iPhone behaving nothing like other iPhones at the same site is the signal.

---

## How It Works

Every 15 minutes, Sasquatch:

1. Pulls the last 24 hours of client events from the Mist API (paginated, enriched with device metadata)
2. Builds a per-MAC behavioral feature vector — normalized event type frequencies, so volume is never the signal
3. Runs a three-stage ML pipeline:
   - **DBSCAN** across all MACs site-wide (finds clients that don't fit any cluster)
   - **Family Centroid Isolation Forest** across device-family centroids (finds families behaving differently from all other families)
   - **Per-family Isolation Forest** within each device type (finds individual devices anomalous relative to their peers)
4. Computes a **separate** per-family health score from failure ratios — independent of anomaly detection
5. Fires a webhook only when a family is **both** anomalous (centroid IF) **and** unhealthy (health score < 0.75) — dual-gate to prevent single-device noise

Results are stored in Redis and served through a React dashboard with org-wide and per-site views.

**No data egresses to third-party AI providers.** Detection is pure ML + rule-based. Local Ollama is supported for optional read-only explanation features.

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
                    (DBSCAN → Centroid IF → Per-family IF)
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
| ML | scikit-learn — IsolationForest, DBSCAN, StandardScaler |
| Feature Engineering | pandas, numpy |
| Mist API Client | httpx (async) |

---

## Prerequisites

- Python 3.10+
- Node.js 18+
- Redis 7+
- Juniper Mist API token + site/org IDs
- [Ollama](https://ollama.ai/) (optional — local LLM for AI Assist)

---

## Quick Start

```bash
cd unsupervised_anomaly

# One-time setup: installs venv, npm deps, builds frontend, installs Ollama
./setup.sh

# Copy and fill in your credentials
cp .env.example .env
$EDITOR .env

# Start everything (Redis, backend on :8000, frontend on :3000, Ollama on :11434)
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

Copy `.env.example` to `.env` and set the following:

```bash
# Mist API
MIST_API_TOKEN=your_api_token
MIST_CLOUD_HOST=api.mist.com        # api.gc4.mist.com, api.eu.mist.com, etc.
MIST_SITE_ID=<site-uuid>
MIST_ORG_ID=<org-uuid>

# Redis
REDIS_URL=redis://localhost:6379

# Detection schedule
DETECTION_INTERVAL_MINUTES=15

# ML tuning
ANOMALY_IF_CONTAMINATION=0.05       # Isolation Forest contamination rate
ANOMALY_DBSCAN_EPS=2.5              # DBSCAN neighborhood radius
ANOMALY_DBSCAN_MIN_SAMPLES=5        # DBSCAN min cluster size
ANOMALY_FINDING_THRESHOLD=0.2       # Min outlier ratio to generate a finding
ANOMALY_MIN_PEERS=5                 # Min family size to run per-family IF
ANOMALY_HEALTH_SCORE_THRESHOLD=0.75 # Health score below this = unhealthy

# Webhook — fires only when is_family_outlier AND health < threshold AND severity >= threshold
ANOMALY_WEBHOOK_URL=https://your-endpoint/webhook/anomaly
ANOMALY_WEBHOOK_SEVERITY_THRESHOLD=significant  # minimal | moderate | significant

# Dashboard auth
APP_USERNAME=your_username
APP_PASSWORD=your_password

# Frontend
VITE_API_BASE_URL=http://localhost:8000
```

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

1. `is_family_outlier == True` — centroid IF flagged the whole family as behaviorally different from all other device types
2. `health_score < 0.75` — family is also measurably failing
3. `severity >= significant` (configurable)

Single-device IF or DBSCAN outliers appear in the UI but never trigger webhooks.

---

## Dashboard

| View | Description |
|---|---|
| **Site Overview** | Heatmap of device families × event categories with health bar per row. Auto-refreshes every 60s. |
| **Findings Feed** | Three sections: ALERT (anomalous + unhealthy), HEALTH (unhealthy only), ANOMALOUS (anomalous only). |
| **Org Overview** | Four-tab shell: Org Alerts, Org Overview, Org Family Insights, Org Findings. |
| **Org Alerts** | Org-wide alerts grouped by family; site alerts grouped by site. Default org view. |
| **MAC Drilldown** | 24hr event timeline + feature vector vs family baseline + IF score + DBSCAN label. |
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

Detection runs for `__all__` (combined) plus each unique SSID, enabling per-WLAN scoped dashboards.

---

## Project Structure

```
unsupervised_anomaly/
├── sasquatch/
│   ├── client_anomaly/
│   │   ├── client_cache.py          # Daily MAC → device metadata refresh
│   │   ├── event_collector.py       # 24hr event pull, enrichment, deduplication
│   │   ├── feature_engineer.py      # Per-MAC behavioral feature vectors
│   │   ├── anomaly_detector.py      # Three-stage ML pipeline + finding rollup
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
- Feature vectors collapse time — episode-based detection for PMKID storms not yet implemented

---

## Security Notes

- Data never egresses to third-party LLM providers. All ML is local.
- The API has HTTP Basic Auth (`APP_USERNAME` / `APP_PASSWORD`). Put it behind a reverse proxy with TLS in production.
- Redis has no auth by default — bind to localhost or use `requirepass` in production.
