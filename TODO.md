# TODO — Known Issues & Improvement Backlog

## Collector / Client Cache

### ~~1. Client cache staleness window — up to 23hr gap for new devices~~ RESOLVED
`event_collector.collect()` now counts distinct cache-miss MACs per batch. If the count
reaches `CACHE_MISS_REFRESH_THRESHOLD` (default 10, env-configurable), it calls
`refresh_client_cache()` and re-enriches the batch before writing to Redis. New devices
will be correctly classified within one 15-minute detection cycle.

---

### ~~2. OUI stub is non-functional~~ RESOLVED
Replaced with `oui_lookup.py` — a local IEEE MA-L registry lookup (39 183 entries,
bundled as `data/oui.json`, ~1.3 MB). `_oui_lookup()` in `event_collector.py` now
delegates to `oui_lookup.lookup()`. No network calls at runtime. Run
`python3 -m sasquatch.client_anomaly.oui_lookup` (or `build_db()`) to refresh the
database from the IEEE standards server.

---

### ~~3. Unknown family is a single catch-all peer group~~ RESOLVED
`_enrich_event()` now sets `device_family = "Unknown/{manufacturer}"` for cache-miss MACs
when the OUI resolves to a known manufacturer (e.g. `"Unknown/Cisco Systems"`,
`"Unknown/Extreme Networks"`). MACs with an unrecognised OUI remain `"Unknown"`. The
manufacturer string is comma-split (drops ", Inc.", ", Ltd.") and word-boundary truncated
at 24 chars for consistent, readable peer-group keys. Cache-hit path is unchanged.

---

### ~~4. Stale enrichment labels on re-enriched events~~ RESOLVED
`reenrich_stale_events(site_id, client_cache)` added to `event_collector.py`. Scans the
site's event sorted set for members whose `device_family` starts with `"Unknown"` and
whose MAC is now present in the supplied cache. Re-enriches each match via `_enrich_event`
and atomically replaces it in Redis (ZREM + ZADD at the same timestamp score) via a single
pipeline. Members whose re-enriched JSON is identical to the stored version are skipped.

Called in two places:
- `collect()` — immediately after a miss-triggered cache refresh, before writing new events
- `scheduler.client_refresh_job()` — after every midnight cache refresh for each site

---

### 5. Cache refresh job has no retry or alerting on failure
**File:** `sasquatch/client_anomaly/scheduler.py`, `client_refresh_job()`

If the midnight refresh fails (network error, Mist API outage), the job logs an exception
and moves on. The cache TTL is now 7 days (matching events), so a single failed refresh
no longer causes the cache to expire before the next attempt. However, if the job fails
repeatedly the cache will silently go stale with no operator signal.

**Fix:** Add retry logic (3 attempts with exponential backoff) inside `client_refresh_job`.
On final failure, write an error flag to Redis and surface it in the API health endpoint
so the dashboard can display a warning.

---

## Feature Engineering / ML

### 6. `_enrich_event` device_family taken from first event only
**File:** `sasquatch/client_anomaly/feature_engineer.py:263`

When building feature vectors, `device_family` is read from `evts[0]` — the first event
for that MAC. If a MAC's events span a cache refresh boundary (old events labeled Unknown,
new events labeled correctly), the feature record inherits the label of whichever event
happened to sort first.

**Fix:** Take the majority-vote `device_family` across all events for a MAC, preferring
any non-Unknown label over Unknown.

---

### ~~7. Mist API emits 3 variants per MARVIS_EVENT_CLIENT_AUTH_FAILURE~~ RESOLVED
**File:** `sasquatch/client_anomaly/event_collector.py`

Mist emits the same logical auth failure event 3 times from different internal pipelines. All 3
variants carry the exact same `(mac, type, timestamp, bssid)` but differ in `has_pcap` (true /
false / absent) and `pcap_url` presence. Since our sorted-set member is the full JSON string, all
3 were stored as distinct entries — 3 logical failures appeared as 9 in the timeline.

Additionally, `pcap_url` contains a short-lived JWT (~2hr expiry) that rotates on each API call,
so even the same variant would generate a new sorted-set member every 15-minute `collect()` cycle
if not stripped.

**Fix:** `_dedup_events()` added to `event_collector.py`, called at the top of `_enrich_batch()`.
Strips `pcap_url` from all events before storage, then deduplicates by `(mac, type, timestamp,
bssid)` — keeping the `has_pcap=True` variant when multiple exist.

---

### 8. Auth burst noise — repeated failures before recovery inflate health score and timeline
**Files:** `sasquatch/client_anomaly/feature_engineer.py`, MacDrilldown frontend component

Even after API-level deduplication (item 7), a client retrying EAP auth multiple times before
succeeding will generate several genuine `MARVIS_EVENT_CLIENT_AUTH_FAILURE` events followed by
`CLIENT_AUTHENTICATED`. These inflate `failure_ratio_auth` in the feature vector and depress the
health score more than the real-world impact warrants — the failure resolved itself.

**Fix:**
- **Feature engineer:** Identify "auth burst → recovery" sequences in `build_features()`:
  ≥2 auth failures within 30 seconds followed by `CLIENT_AUTHENTICATED` within 60 seconds.
  Track these as `auth_burst_recovery_count` (recovered) vs `auth_failure_terminal_count`
  (no recovery). Reduce the weight of burst-recovered failures in `failure_ratio_auth` or
  treat them as a distinct feature so the health scorer and post-hoc explainer can distinguish
  transient retry noise from genuine persistent auth failure.
- **MacDrilldown display:** Visually group consecutive same-type events within the same second
  into a single row with a count badge to reduce timeline noise for operators.

---

### 14. Feature vectors collapse time — episode-based roam/auth storm detection missing
**Files:** `sasquatch/client_anomaly/feature_engineer.py`, `sasquatch/client_anomaly/health_scorer.py`

The current feature vector is a 24hr ratio snapshot. A client that was perfectly healthy
for 3 hours, endured 5 minutes of complete roaming chaos across 20 APs, and then recovered
via a full re-auth is indistinguishable from a client that had a mildly elevated failure
ratio evenly distributed across the day. The temporal structure of the failure episode is
invisible to both the anomaly detector and the health scorer.

**Observed example (real timeline, one MAC, 24hr window):**
- 10:02–10:13: Normal association + minor roam turbulence, settles on AP:8727
- 11:32–11:59: Clean roam to AP:3016, joins and leaves a call
- 12:47: Multi-AP roaming storm — client bounces across AP:8727/85fb/7a5c with interleaved
  `MARVIS_EVENT_STA_LEAVING` and `CLIENT_AUTH_REASSOCIATION_11R` events, ends with
  `MARVIS_EVENT_CLIENT_AUTH_FAILURE_11R` + `CLIENT_DEASSOCIATION`
- 1:19: `CLIENT_DEAUTHENTICATION` reason:4 (AP-initiated disassoc)
- 1:22–1:25: **Site-wide PMKID storm** — stale PMKID rejected by ~20 distinct APs
  (`MARVIS_EVENT_CLIENT_FBT_FAILURE` status:53 and `MARVIS_EVENT_WLC_FT_KEY_NOT_FOUND`
  across 2deb, 2c88, 2e18, 2f30, 7a08, 2c0b, 2f49, 3016, 7a5c, 3151, 2bde, 2be3, 2fe9,
  2daf, 2f26, 2cfb, 7fc0, 2c65, 2c47, 2fa8, 2fb7, 2fd5, 301b — essentially every AP in
  the building was rejecting this client's PMKID). The storm runs for ~3 minutes.
- 1:29: Fresh `CLIENT_AUTH_ASSOCIATION` (full re-auth, not reassociation) — client finally
  forced off the stale PMKID and recovered from scratch.

A single good `CLIENT_AUTH_ASSOCIATION` at 10:02 AM represents 9 hours of the client
being happy. The 3-minute storm at 1:22–1:25 PM generates hundreds of failure events but
those get diluted in the 24hr ratio alongside the quiet periods.

**What the current model misses:**
- Episodes: a concentrated burst of failures followed by recovery is qualitatively different
  from the same number of failures spread uniformly across the day.
- Temporal weight: 9 hours of quiet shouldn't wash out a 3-minute site-wide failure storm.
- Cross-AP blast radius: when the same failure type appears across many distinct APs within
  a short window, that strongly indicates a client-side state problem (stale PMKID, invalid
  PMK), not an AP-specific issue.

**Proposed additions to feature engineering:**

*Episode detection:*
- Identify "failure episodes" — windows where failure events of the same failure class
  (`FBT_FAILURE`, `AUTH_FAILURE`, `WLC_FT_KEY_NOT_FOUND`, etc.) occur at a rate above a
  threshold (e.g. ≥3 within 60 seconds), separated by quiet periods.
- Per episode, record: `episode_duration_s`, `episode_failure_count`, `episode_ap_count`
  (distinct APs involved), `episode_recovery` (bool — did a clean auth/reassoc follow
  within N minutes?).

*Summary features (safe to feed to ML — still ratios/counts, not raw volumes):*
- `max_episode_ap_count`: peak distinct APs rejecting the client in a single episode.
  A client storm hitting 20 APs simultaneously is structurally different from 20 failures
  spread across the day.
- `max_episode_failure_rate`: failures per minute at the peak episode.
- `pmkid_episode_count`: number of distinct PMKID storm episodes (each representing a
  full PMKID invalidation event requiring re-auth).
- `roam_storm_count`: episodes where `CLIENT_AUTH_REASSOCIATION_11R` + `STA_LEAVING`
  cycle faster than a realistic human roam rate (e.g. >3 AP changes within 30s).

*Health scorer impact:*
- The health scorer currently treats all failures uniformly across the 24hr window.
  Consider a time-decay or episode-weighted variant: failures within an episode that
  ends in recovery are less damaging to health than an episode with no recovery.
  This is related to but distinct from item 8 (auth burst → recovery) — here the episode
  spans multiple APs and multiple minutes, not just rapid retries at a single AP.

*Post-hoc explainer enrichment:*
- `pmkid_storm_episode`: episode with ≥5 distinct APs all returning FBT status:53 within
  90 seconds — strong indicator the client's PMKID is globally stale and requires forced
  full re-auth. Surface this as a distinct `probable_pattern` value.

---

---

## Frontend — Progress / Status

### 13. "Collecting Events" progress bar no longer shows status
**Files:** TBD — frontend progress bar component and/or backend SSE/polling endpoint

The "Collecting Events" progress bar has stopped updating even though backend.log
confirms API calls are being made during collection. The bar renders but shows no
progress — the UI is not receiving or reflecting the collection status updates.

**Symptoms:**
- `backend.log` shows paginated event collection calls completing normally
- Progress bar appears but remains static (no advancement or status text updates)

**Investigation starting points:**
- Check whether the frontend is still polling / receiving SSE events from the backend during collection
- Check whether the backend is still emitting progress updates (Redis pub/sub, SSE, or polling endpoint)
- Verify the progress bar component is wired to the correct state/prop

---

## Frontend — Action Bar

### ~~9. "Flush Events" button gives no visual feedback after click~~ RESOLVED
Confirm → loading → ok/error label flow implemented in `handleFlush`. A 4-second
timeout auto-reverts "Confirm Flush?" to idle if the user doesn't confirm, preventing
the button from getting stuck in the confirmation state.

---

### ~~8. "Client Refresh" button gives no visual feedback during the request~~ RESOLVED
`actionBtnStyle("loading")` now applies a `sq-btn-pulse` `@keyframes` animation that
pulses the border between `#2a2a3a` and `#4a4a7a` on a 1.2s cycle — clearly distinct
from the static disabled appearance. Keyframes are injected via a `<style>` tag in the
App render. Client Refresh is also now wired for the Org view: calls `POST /api/v1/org/refresh`
(new backend endpoint) when `selectedSite === "__org__"`, and the button label updates to
"Org Client Refresh" in that context.

---

### 10. Page load is slow — serial fetch waterfall before any content renders
**Files:** `sasquatch/frontend/src/App.jsx`, `sasquatch/frontend/src/components/SiteOverview.jsx`

On initial load the browser makes a serial chain of requests before anything is visible:
1. `GET /api/v1/org/sites` — populate site picker
2. `GET /api/v1/focus` — determine selected site
3. `GET /api/v1/wlans?site_id=...` — populate WLAN dropdown
4. (only now) parallel: `events/summary` + `findings` + `health`

Steps 1 and 2 are in separate `useEffect` calls in App.jsx and fire sequentially. Step 3 is
gated on `selectedSite` resolving from step 2. Step 4 is gated on step 3. Until all four
chains complete, SiteOverview renders only "Loading site overview…" — nothing progressive is
shown to the user.

**Fix (in priority order):**
- **Parallelize steps 1+2:** Fetch `/org/sites` and `/focus` in a single `Promise.all` in one
  `useEffect` rather than two separate effects that chain.
- **Parallelize step 3 with steps 1+2:** The WLAN fetch only needs `site_id`, which is available
  from `/focus` — start it the moment `focus` resolves, not after `sites` resolves too.
- **Skeleton UI:** Replace the "Loading site overview…" string with a placeholder skeleton
  (grey bars matching the heatmap layout) so the page feels populated while data loads.
- **Stale-while-revalidate:** On subsequent navigations to a site already visited in the session,
  render cached data immediately and refresh in the background rather than showing a loading state.

---

## Frontend — Navigation / Layout

### 9. Site-view tabs ("Site Overview" / "Findings") should be inlined in the view, not the global header nav
**File:** `sasquatch/frontend/src/App.jsx:429-450`, `sasquatch/frontend/src/components/SiteOverview.jsx`, `sasquatch/frontend/src/components/FindingsFeed.jsx`

The top-level `<nav>` in the header iterates `["overview", "findings"]` and renders
two buttons whose labels swap between "Site Overview" and "Findings" depending on
`selectedSite`. For the Org view these buttons disappear entirely (`if (selectedSite === ORG_FOCUS_VALUE && v !== "overview") return null`) because `OrgOverview.jsx` owns its
own internal four-tab nav bar (`Org Alerts | Org Overview | Org Family Insights | Findings`).

The site-view has no equivalent internal tab bar — its navigation lives in the global
header. This creates an inconsistency: the org view's sub-navigation is scoped to the
view component, while the site view's sub-navigation bleeds into the shared header,
making layout awkward especially as additional tabs are added.

**Fix:** Remove the `["overview", "findings"]` iteration from the global header `<nav>`
and add an equivalent inline tab bar inside the site-view section (the `div` at
`App.jsx:567-575`). Pattern it after `OrgOverview.jsx`'s internal tab row. The active
`view` state and `setView` handler will need to be passed down or co-located. The global
header nav can then be simplified or removed entirely.

---

### 10. "Findings" tab in the Org four-tab bar should be labelled "Org Findings"
**File:** `sasquatch/frontend/src/components/OrgOverview.jsx:136`

The label ternary chain in `OrgOverview` resolves to plain `"Findings"` for
`view === "findings"`. The other three tabs are prefixed "Org …", making this tab
inconsistent and ambiguous when comparing to the site-level Findings tab that will
appear after item 9 is implemented.

**Fix:** Change the last branch of the ternary from `"Findings"` to `"Org Findings"`.
No backend change required — this is purely a display label.

---

## Frontend — PCA / Cluster Viz

### 11. Org PCA view silently omits sites that have not yet completed Full Discovery
**Files:** `sasquatch/client_anomaly/api/routes.py:1038` (`get_org_cluster_viz`), `sasquatch/frontend/src/components/OrgClusterViz.jsx:98-100`

`get_org_cluster_viz` iterates every site returned by `_get_org_site_map` but skips any
site whose `sasquatch:features:{site_id}:{wlan}` key is absent from Redis
(`if not raw_feat: continue`). A site that has never had Full Discovery run, or whose
24hr features TTL has expired, is silently dropped from the plot. The response includes
`site_count` in the header but this count reflects only sites with data, not total org
sites — there is no indication in the UI that some sites were excluded.

Additional filtering in `OrgClusterViz.jsx` further removes families with fewer than
`MIN_DISPLAY_CLIENTS = 5` MACs across the displayed data set and hides entries in
`HIDDEN_FAMILIES`. For small or newly-onboarded sites this can eliminate all their
MACs from the chart entirely.

**Fix (multiple angles):**
- **Backend:** Return a `sites_with_data` count alongside `total_org_sites` so the
  frontend can surface a "X of Y sites included" note below the chart title.
- **Backend/frontend:** Consider returning a `missing_sites` list (site names with no
  features) so the legend or a tooltip can identify which sites are excluded.
- **Frontend:** The existing `sampledNote` pattern can be extended to show an
  "X sites have no data" badge when `sites_with_data < total_org_sites`.
- **`MIN_DISPLAY_CLIENTS` filter:** This per-family threshold is applied to the
  _filtered org-wide_ population. For a 20-site org a family with 4 devices per site
  (80 total) may still be below this cutoff if they cluster tightly. Consider making
  the threshold configurable or applying it per-site before pooling.

---

## Backend — Error Handling

### 12. Empty sites (no events) throw errors surfaced to the status bar
**Files:** `sasquatch/client_anomaly/scheduler.py`, `sasquatch/client_anomaly/event_collector.py`, `sasquatch/client_anomaly/feature_engineer.py`, `sasquatch/client_anomaly/anomaly_detector.py`

CLAUDE.md specifies that scheduler jobs should "log the error and skip remaining steps
for that cycle" — but currently, sites with zero events (brand-new sites, sites that
were offline, or sites whose event window is legitimately empty) propagate exceptions
through `build_features` → `score` into the scheduler job, which logs them as errors.
These appear in the status bar and are indistinguishable from actual failures (API
errors, Redis failures, ML crashes).

A site returning zero events is a valid operational state: it could be a newly-added
site, an office that was closed, or a site on a non-overlapping detection window.
Treating it as an error creates alert fatigue and obscures real failures.

**Fix:** In `event_collector.collect()`, after pagination completes, if `len(all_events) == 0`
log at INFO level and return early (do not write an empty sorted set). In
`feature_engineer.build_features()` and `anomaly_detector.score()`, guard against an
empty feature dict or empty MAC population with an early return and INFO-level log
rather than raising. In `scheduler.py`, distinguish between `EventCollectionEmpty`
(info) and actual exceptions (warning/error) so the status bar only lights up for
genuine problems. The `GET /sites/{site_id}/status` response should convey
`event_count: 0` as a normal state, not an error condition.

---

## Documentation

### ~~7. Redis key schema in CLAUDE.md is partially stale~~ RESOLVED
Updated as part of client cache TTL change — schema table now reflects 7-day TTLs for
clients and events, and adds `sasquatch:wlans:{site_id}` and `sasquatch:event_type_index`.
