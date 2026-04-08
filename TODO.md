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

### ~~17. `MARVIS_EVENT_CLIENT_AUTH_FAILURE` status_code -79 should be excluded from AUTH_FAILURE~~ RESOLVED
**Files:** `sasquatch/client_anomaly/event_collector.py`

Status code -79 on `MARVIS_EVENT_CLIENT_AUTH_FAILURE` is a **transmission failure** (802.11
frame not acknowledged at the radio layer) — the AP never received the client's frame, so
there is no meaningful auth decision. These are caused by poor RF coverage, not device-level
authentication behavior.

`_AUTH_FAILURE_IGNORED_STATUS_CODES = frozenset({-79})` added to `event_collector.py`.
In `_enrich_batch()`, any `MARVIS_EVENT_CLIENT_AUTH_FAILURE` event whose `status_code` is in
this set is dropped before enrichment and storage — it never reaches Redis, so `feature_engineer.py`
and `health_scorer.py` require no changes. A DEBUG-level log records the count of skipped
events per batch for observability.

---

### 20. Centroid IF flags family outliers relative to other family centroids — not against a grand mean

**Files:** `sasquatch/client_anomaly/anomaly_detector.py` — `_run_family_centroid_if()` (line ~252), `score()` (line ~391), `score_org_wide()` (line ~672)

**How it actually works:**
For each qualifying family (≥ 2 MACs), `_run_family_centroid_if()` computes a centroid = element-wise mean of all MACs' raw feature vectors (`FEATURE_KEYS` ordering). It then collects all qualifying family centroids into a single matrix, runs `StandardScaler` + `IsolationForest` across those N rows (one row per family), and flags any family whose `decision_function` score is negative. A negative IF score means the centroid was isolated in fewer random partitions than average — i.e., it occupies a sparse region of the family-centroid feature space.

**This is not a distance-from-grand-mean test.** IF does not compute a reference centroid or a threshold distance. It uses random recursive partitioning — a family is flagged because its centroid is hard to "mix in" with the others, not because it exceeds some deviation from the population average.

**Problems to investigate:**

1. **Small N makes IF unreliable.** A typical site has 5–10 qualifying device families. Running IsolationForest on a 5-row matrix is statistically weak — the model has almost no population to learn a normal distribution from. At N=5, contamination=0.05 means 0.25 expected outliers, so the flag-threshold of `score < 0` is doing the real work, not the contamination setting. At N=10, contamination=0.05 still means only 0.5 expected outliers, so the model is biased toward flagging nothing.

2. ~~**Contamination mismatch.**~~ **RESOLVED** — split into two separate constants and env vars: `ANOMALY_IF_CONTAMINATION` (Stage 2 intra-family, default 0.1) and `ANOMALY_CENTROID_IF_CONTAMINATION` (Stage 1b inter-family centroid IF, default 0.15). The centroid IF `IsolationForest` call now uses `CENTROID_IF_CONTAMINATION` instead of the shared `IF_CONTAMINATION`. With N=5–10 families, 0.15 calibrates IF to expect ~1 anomalous family, compared to the previous 0.05 which expected 0–0 and biased the model to never flag anything.

3. **`score < 0` is the effective decision boundary, not contamination.** `IsolationForest.decision_function()` returns 0 at the contamination-derived threshold. The code flags on `score < 0` rather than on `predict() == -1`. These are equivalent when the model is properly calibrated, but at small N they can diverge. Worth confirming whether `predict()` and `score < 0` agree on the same families and which is more appropriate here.

4. ~~**Centroid averaging may suppress the signal.**~~ **RESOLVED** — switched from mean centroid to a dual-representation row (median + max) concatenated into a single IF input. See fix description below.

**Remaining investigation:**
- Log `centroid_if_scores` (all family scores, not just flagged ones) at INFO level each cycle so the score distribution is observable in production without code changes. **PARTIALLY RESOLVED** — `_dispatch_centroid_detection` now logs all scores (both IF and distance paths) at INFO each cycle.
- Check whether `predict()` and `score < 0` agree on the same families — if they diverge at this N, prefer `score < 0` and document why. **Only relevant for the IF path (N > 8).**
- ~~Trial a separate `ANOMALY_CENTROID_IF_CONTAMINATION` env var (decoupled from `ANOMALY_IF_CONTAMINATION`) set to 0.15 or 0.20, and compare which families get flagged vs. the current shared 0.05.~~ **RESOLVED** — see fix description above.
- ~~For sites with very few families (N < `CENTROID_IF_MIN_FAMILIES`), evaluate whether a distance-based fallback (e.g., cosine distance from the population centroid, threshold-gated) would give more interpretable results than skipping the step entirely.~~ **RESOLVED** — implemented as cosine-distance fallback for 3 ≤ N ≤ 8. See `_run_family_centroid_distance` and `_dispatch_centroid_detection` in `anomaly_detector.py`. New env vars: `ANOMALY_CENTROID_DIST_MAX_FAMILIES` (default 8) and `ANOMALY_CENTROID_DIST_THRESHOLD` (default 0.35).

**Fix applied (`anomaly_detector.py` — `_run_family_centroid_if`):**
Replaced `vectors.mean(axis=0)` with a concatenation of two vectors per family:
- **Median vector** (`np.median(vectors, axis=0)`): more robust than the mean for whole-family shift detection — a single anomalous MAC no longer shifts the centroid.
- **Max vector** (`vectors.max(axis=0)`): component-wise maximum across all MACs. Captures the behavioral ceiling — what the most extreme any member of the family does on each feature dimension.

For a 2-MAC family with 1 healthy + 1 anomalous device: the median still collapses toward the midpoint (unavoidable at N=2), but the max vector preserves the anomalous MAC's feature values on the dimensions where it is extreme. IF can now see that this family's behavioral ceiling is anomalous relative to other families' ceilings, even when the median looks normal. The input to IF is now `2 × len(FEATURE_KEYS)` wide rather than `len(FEATURE_KEYS)` — `StandardScaler` normalizes this before IF sees it.

---

### 18. Evaluate whether 7-day event window improves anomaly detection vs. current 24hr
**Files:** `sasquatch/client_anomaly/event_collector.py`, `sasquatch/client_anomaly/feature_engineer.py`, `sasquatch/client_anomaly/anomaly_detector.py`

Events and client cache both use a 7-day TTL, but `feature_engineer.build_features()` and
`anomaly_detector.score()` currently operate on the last 24 hours only. The question is
whether extending the detection window to 7 days would improve signal quality.

**Arguments for a longer window:**
- More events per MAC → more stable frequency distributions, especially for low-volume
  devices (IoT, printers) that may only generate a handful of events per day.
- DBSCAN and IF both benefit from larger populations — richer peer groups for per-family IF.
- A device experiencing a slow-onset degradation (gradually increasing PMKID failures over
  days) would be more detectable against a week of baseline than a single day.

**Arguments for keeping 24hr:**
- The 24hr window is the natural unit of network behavior — a device that was broken last
  Tuesday but healthy since Wednesday should not still be flagged today.
- Longer windows dilute acute anomalies: a 3-minute PMKID storm (see item 14) already gets
  washed out in a 24hr ratio — a 7-day window makes this worse, not better.
- Health scores are designed to reflect current state, not historical state. A 7-day health
  score would lag real recovery.
- Feature vectors are probability distributions — extending the window shifts the reference
  point but doesn't change the structural sparsity problem.

**Recommended investigation:**
- Run both 24hr and 7-day feature builds against the same event set and compare the
  resulting feature vector distributions (variance, sparsity, inter-MAC distance) to see
  if the longer window actually stabilises the vectors.
- Check whether low-volume device families (IoT, printers) have materially different
  IF scores under a longer window.
- Consider a hybrid: use 7-day events for the IF training population (better peer baseline)
  but 24hr events for the scored MAC's own feature vector (current behaviour, not historical).
  This gives IF a richer reference frame while keeping the anomaly signal time-local.

---

### ~~16. DBSCAN curse of dimensionality — apply PCA reduction before clustering~~ RESOLVED
**Files:** `sasquatch/client_anomaly/anomaly_detector.py`

DBSCAN uses Euclidean distance, which degrades in high-dimensional space — all points
tend toward the same inter-point distance, making `eps` hard to tune meaningfully. The
61-dimension feature vectors are also sparse probability distributions (most clients have
5–10 non-zero entries out of 59 event-type dimensions), which makes Euclidean distance
worse: similarity is dominated by whichever few non-zero dimensions happen to overlap
between two MACs rather than reflecting true behavioral similarity.

Isolation Forest is not affected — it splits on one random feature at a time and never
computes full-space distances, so it handles sparse high-dimensional vectors well.

**Fix:** Apply PCA before DBSCAN only (not before IF). Reduce to the number of components
capturing ~95% of variance. Given the sparsity of the frequency vectors, this will likely
collapse from 61 to 8–15 components in practice.

```python
from sklearn.decomposition import PCA

pca = PCA(n_components=0.95, random_state=42)
X_scaled = scaler.fit_transform(feature_matrix)
X_reduced = pca.fit_transform(X_scaled)   # pass to DBSCAN
# IF still receives X_scaled — no PCA
```

Log `pca.n_components_` at INFO level each detection cycle so the actual dimensionality
reduction is visible in the logs and can be monitored over time. The family centroid IF
step can also benefit from PCA-reduced vectors since it operates on mean centroids, but
this is lower priority.

PCA is applied in `_run_dbscan()` between StandardScaler and DBSCAN. Uses
`n_components=0.95` (capped at n_samples-1 for small populations). IF is unchanged —
no PCA applied there. `pca.n_components_` is logged at INFO each cycle.

---

### ~~14. Feature vectors collapse time — episode-based roam/auth storm detection missing~~ RESOLVED
**Files:** `sasquatch/client_anomaly/markov_analyzer.py` (new), `sasquatch/client_anomaly/anomaly_detector.py`, `sasquatch/client_anomaly/scheduler.py`

Two-layer Markov Chain episode analysis implemented as Stage 4 in `anomaly_detector.py`:
- **Layer 1 — Event-level transition matrix:** A site/wlan-scoped NxN matrix is built from all
  consecutive event-type pairs in normal-length episodes over the last 24hr. Each episode is
  scored by mean log-probability of its transitions against this baseline. Episodes below
  `MARKOV_EPISODE_LOG_PROB_THRESHOLD` (-4.0) are flagged anomalous.
- **Layer 2 — Episode-type state machine:** Tracks a "short" (failed, < `MARKOV_MIN_EPISODE_LENGTH`
  events) vs "normal" episode-type sequence per MAC. A MAC stuck repeatedly cycling through
  short episodes (e.g., connect → DHCP_NAK → disconnect, repeated) is flagged as having
  `has_repeated_short_episodes = True`.

The baseline is built from Redis events once per day by `markov_baseline_job` (00:30 daily) and
stored in `sasquatch:markov_baseline:{site_id}:{wlan_key}` with a 48hr TTL. Detection builds the
baseline on first run if it is absent. New family-level flag `is_family_markov_outlier` bypasses
`FINDING_THRESHOLD` — a family where enough clients have anomalous episode patterns generates a
finding regardless of the combined IF/DBSCAN MAC-level outlier ratio.

**Previously proposed episode-detection approach (feature vector extensions):**
The proposed additions (`max_episode_ap_count`, `max_episode_failure_rate`, etc.) were not
implemented — the Markov approach provides episode-level anomaly detection without requiring
changes to the feature vector schema or the IF/DBSCAN pipeline. Cross-AP blast-radius detection
(PMKID storm hitting 20 APs simultaneously) remains unimplemented in the Markov layer; the
transition matrix captures event-type sequences but not the spatial dimension (AP count).

**Remaining gap:** Original issue — filed under `sasquatch/client_anomaly/feature_engineer.py`, `sasquatch/client_anomaly/health_scorer.py`

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

### 21. Markov baseline warm-up delay on first deployment / flush
**Files:** `sasquatch/client_anomaly/markov_analyzer.py`, `sasquatch/client_anomaly/scheduler.py`

The Markov baseline requires 24hr of events to build a meaningful transition matrix.
On first deployment (or after `POST /api/v1/org/flush`), the baseline key is absent and
the first detection cycle builds it on-demand from whatever events are already in Redis
— which may be hours short of 24hr. Stage 4 is silently skipped until the baseline is
available, which is the correct behavior, but there is no operator-visible signal that
Markov scoring is inactive.

**Fix:** Surface `markov_baseline_age_hours` (or `markov_baseline_built_at`) in the
`GET /api/v1/sites/{site_id}/status` response and display it in the dashboard status bar
alongside the last detection timestamp.

---

### 22. Markov transition matrix does not capture cross-AP blast radius
**Files:** `sasquatch/client_anomaly/markov_analyzer.py`

The Markov event-level analysis captures *what types of events* happen in sequence, but
not *how many distinct APs* are involved in a failure episode. The PMKID storm described
in item 14 (20 APs rejecting the same client's PMKID within 3 minutes) would show an
anomalous `FBT_FAILURE → FBT_FAILURE` transition sequence, but the transition score
cannot distinguish "2 failures at the same AP" from "20 failures across 20 APs."

**Proposed addition:**
- Add `max_episode_ap_count` feature to the Markov episode record: count of distinct APs
  in the episode. If > `MARKOV_BLAST_RADIUS_AP_THRESHOLD` (env, default 5), add to the
  episode's anomaly score regardless of transition probability.
- This would make `pmkid_storm_episode` (≥5 distinct APs returning FBT status:53 in 90s)
  detectable as a distinct high-confidence pattern.

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

### ~~10. Page load is slow — serial fetch waterfall before any content renders~~ PARTIALLY RESOLVED
**Files:** `sasquatch/frontend/src/App.jsx`, `sasquatch/frontend/src/components/SiteOverview.jsx`

Steps 1+2 (`/org/sites` and `/focus`) are already parallelized in a single `useEffect` in
App.jsx. Step 3 (WLAN fetch) fires immediately when `selectedSite` resolves from `/focus`,
in parallel with SiteOverview's own data fetches.

**Skeleton UI:** Implemented in `SiteOverview.jsx` — replaces "Loading site overview…" with
an animated shimmer skeleton matching the heatmap table layout (18 columns, 6 placeholder rows).

**Remaining (not yet done):**
- **Stale-while-revalidate:** On subsequent navigations to a previously-visited site, render
  cached data immediately and refresh in the background rather than showing the skeleton again.

---

## Frontend — Navigation / Layout

### ~~9. Site-view tabs ("Site Overview" / "Findings") should be inlined in the view, not the global header nav~~ RESOLVED
Removed the `["overview", "findings"]` nav from the global header. Added an inline tab
bar directly in the site-view section of `App.jsx`, rendered only when a site (not org)
is selected and the view is "overview" or "findings". Styled to match the OrgOverview
internal tab row pattern — active tab uses `#0d2a38` background with `#7ec8e3` border/text,
inactive uses `#161616` with `#333` border.

---

### ~~10. "Findings" tab in the Org four-tab bar should be labelled "Org Findings"~~ RESOLVED
Changed last branch of label ternary in `OrgOverview.jsx:136` from `"Findings"` to
`"Org Findings"` — consistent with the other three "Org …" prefixed tabs.

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

## Configuration

### 15. Webhook URL in .env is stale — needs reconfiguration
**File:** `.env` (`ANOMALY_WEBHOOK_URL`)

The current `ANOMALY_WEBHOOK_URL` value in `.env` points to an old endpoint and is no
longer valid. The webhook dispatch code is correct; only the target URL needs updating.

**Fix:** Determine the correct webhook target and update `ANOMALY_WEBHOOK_URL` in `.env`.
Test with a manual `POST /api/v1/org/detect` after updating.

---

## Alerting / History

### ~~19. Alerts have no persistence — no duration tracking, no history after the detection window expires~~ RESOLVED
**Files:** `sasquatch/client_anomaly/anomaly_detector.py`, `sasquatch/client_anomaly/webhook_dispatcher.py`, `sasquatch/client_anomaly/api/routes.py`, frontend alert components

Currently a dual-gate alert (is_family_outlier + health < 0.75) exists only for as long
as the 24hr findings TTL is alive. Once the detection cycle rolls over or the key expires,
there is no record that the alert ever existed — no way to know when it started, how long
it persisted, or when it resolved. An operator seeing an alert has no context on whether
this started 5 minutes ago or has been active for two days.

**What needs to be added:**

*Backend — alert history store:*
- New Redis key `sasquatch:alert_history:{site_id}` (hash, 7-day TTL, field = `{family}:{wlan}`).
- On each detection cycle, in `webhook_dispatcher.evaluate_and_dispatch()` (or a new
  `alert_tracker.py`), for every finding that satisfies the dual gate:
  - If no existing record: write `{first_seen: now, last_seen: now, status: "active"}`.
  - If an existing active record: update `last_seen: now` (extend without resetting `first_seen`).
- For every family that *no longer* satisfies the dual gate but has an active record:
  write `resolved_at: now, status: "resolved"` — keep the record for at least 7 days
  so operators can see recently-resolved alerts.
- Alert duration is computable as `last_seen - first_seen` (for active) or
  `resolved_at - first_seen` (for resolved).
- Org-level alert history: `sasquatch:org_alert_history` with field = `{family}:{wlan}`,
  written by the org-wide detection job using the same logic.

*New API endpoints:*
```
GET /api/v1/sites/{site_id}/alert-history?wlan=__all__
GET /api/v1/org/alert-history?wlan=__all__
```
Each returns a list of `{family, wlan, first_seen, last_seen, resolved_at, status, duration_seconds}`.

*Frontend — alert card enhancements:*
- On every active alert card (in `OrgAlerts.jsx`, `FindingsFeed.jsx`), show a duration
  badge: **"Active Xh Ym"** using `first_seen` from alert history. This is the most
  important operator-facing signal — a 3-hour alert is very different from a 3-day alert.
- Recently-resolved alerts (resolved within the last 24hr) should remain visible in a
  "Recently Resolved" section below the active alerts, showing duration and resolved
  timestamp. This prevents operators losing context when a recovery coincides with a
  detection cycle.
- For active alerts without a `first_seen` record (history not yet populated), fall back
  to showing no duration badge rather than erroring.

*Env var:*
```
ALERT_HISTORY_TTL_DAYS=7   # How long to retain resolved alert history (default 7)
```

**Why `last_seen` matters separately from `resolved_at`:** A detection cycle runs every
15 minutes. If the scheduler misses a cycle (restart, error), the alert should not be
considered resolved just because `last_seen` is 20 minutes ago. Only write `resolved_at`
when a cycle completes successfully and the dual-gate condition is no longer met — i.e.,
absence-of-flag on a successful run, not just absence-of-update.

---

### ~~21. Automated troubleshooting for impacted device family — include TSHOOT API results in webhook payload~~ RESOLVED
**Files:** `sasquatch/client_anomaly/webhook_dispatcher.py`, `sasquatch/client_anomaly/api/routes.py`

When a device family clears the dual gate (is_family_outlier + health < 0.75), the webhook
fires with behavioral findings but no network-side corroboration. Mist's Troubleshooting API
(`POST /api/v1/sites/{site_id}/devices/{device_id}/troubleshoot` and the client equivalent)
can run automated diagnostics against the AP/client at the time of the alert, providing
live network-side context alongside the ML finding.

**What to add:**

*TSHOOT API call (per impacted site + family):*
- For each site where the family is flagged, identify a representative example MAC
  (`example_macs[0]` from the finding) and the AP it was last seen on (`last_ap` from the
  client cache).
- Fire `POST /api/v1/sites/{site_id}/clients/{mac}/troubleshoot` (or the equivalent
  Mist Marvis client troubleshoot endpoint) immediately after the dual-gate check, before
  composing the webhook payload.
- Poll or await the async result (Mist troubleshoot jobs are typically async with a job ID).
  Cap the wait at a configurable timeout (default `TSHOOT_TIMEOUT_SECONDS=30`).

*Webhook payload additions:*
```json
{
  "findings": [
    {
      "device_family": "iPhone",
      ...existing fields...,
      "tshoot": {
        "site_id": "04edb3ac-...",
        "mac": "aa:bb:cc:dd:ee:ff",
        "ap": "5c5b35f16ee0",
        "status": "completed",   // "completed" | "timeout" | "skipped" | "error"
        "results": { ... }       // raw Mist troubleshoot response, site-dependent
      }
    }
  ]
}
```

*When to skip:*
- If `MIST_TSHOOT_ENABLED=false` (new env var, default false until tested) — skip silently.
- If the example MAC is no longer connected (last_seen > `TSHOOT_STALENESS_SECONDS=300`),
  set `status: "skipped"` with reason `"client_offline"` and omit `results`.
- If the TSHOOT API returns an error or times out, set `status: "timeout"` or `"error"`,
  include the error message, and proceed with webhook dispatch — TSHOOT failure must never
  block the alert.

*New env vars:*
```
MIST_TSHOOT_ENABLED=false          # Safety gate — off by default until validated
TSHOOT_TIMEOUT_SECONDS=30          # Max wait for async troubleshoot job completion
TSHOOT_STALENESS_SECONDS=300       # Skip TSHOOT if client last_seen older than this
```

**Implemented:**
- `_get_mac_last_event_ts()` — scans `sasquatch:events:{site_id}` for events within
  `TSHOOT_STALENESS_SECONDS`; returns most recent timestamp for the MAC, or None if
  the client is offline.
- `_run_client_tshoot(site_id, mac)` — POSTs to
  `POST /api/v1/sites/{site_id}/clients/{mac}/troubleshoot`. If the response contains
  `results` directly (synchronous path), returns immediately. Otherwise polls
  `GET /api/v1/sites/{site_id}/jobs/{job_id}` until the job reaches a terminal state
  or `TSHOOT_TIMEOUT_SECONDS` elapses.
- `_enrich_with_client_tshoot(qualifying, site_id, wlan)` — orchestrates the
  staleness check + concurrent TSHOOT dispatch for all `worst_health_macs` across
  all qualifying findings. Attaches `tshoot` list (per-MAC `{mac, ap, status, results}`)
  to each finding. Skips offline MACs with `status: "skipped", reason: "client_offline"`.
  Called in `evaluate_and_dispatch` after Marvis TSHOOT, only when
  `MIST_TSHOOT_ENABLED=true` and `org_scope=False`.
- `run_family_tshoot(site_id, family, wlan)` — public function for the manual trigger.
  Skips the staleness check (operator intent assumed). Called by:
  `POST /api/v1/sites/{site_id}/families/{family}/tshoot` in `routes.py`.
- Three new env vars added to `.env`: `MIST_TSHOOT_ENABLED=false`,
  `TSHOOT_TIMEOUT_SECONDS=30`, `TSHOOT_STALENESS_SECONDS=300`.

---

## Documentation

### ~~7. Redis key schema in CLAUDE.md is partially stale~~ RESOLVED
Updated as part of client cache TTL change — schema table now reflects 7-day TTLs for
clients and events, and adds `sasquatch:wlans:{site_id}` and `sasquatch:event_type_index`.
