# TODO — Known Issues & Improvement Backlog

## Open Work

- [X]  Break down client disassociation / AP disassociation
- [X]  Validate if we need “Security” Events
- [x]  Make Device Family Drilldown cached — `client_summary` SQLite table (2026-04-15)
- [X]  Create site/org level ML detection for the search option

### Post-hackathon architecture — false-positive reduction (2026-04-18)

Two structural noise sources identified during pre-submission review. Both create alerts that compete with real device-family anomalies for operator attention. Not shipping before presentations; capture for the next iteration.

1. **Manufacturer-only families inflate false positives.** Device family classification in `client_cache._build_client_record` / `classify_family` composes `manufacturer | model | os_major`. Clients that fail authentication early never get DHCP/DNS/ARP traffic, so Mist never fingerprints them beyond the OUI-derived manufacturer. They collapse to single-token families (`"Apple"`, `"Samsung"`) that become catch-alls for exactly the failing devices the detector is meant to find — so the centroid legitimately looks bad, but the "family" is a coverage artifact, not a real device group.
   - **Option A — hidden catch-all:** extend `anomaly_detector.HIDDEN_FAMILIES` (and its duplicate in `health_scorer._HIDDEN_FAMILIES`) to suppress any 1-token family at site / org finding rollup and health scoring. Simple. Risk: hides a legitimate "all Awair devices are broken" signal where the vendor genuinely has no model/OS data.
   - **Option B — alarm-gate suppression (leaning):** let findings surface in the UI for browsing, but skip manufacturer-only families at the webhook + OrgAlerts feed. Mirrors the existing `ALARM_MIN_FAMILY_SIZE` pattern. Implement next to `webhook_dispatcher.family_passes_dbscan_markov_gate` so `get_org_alerts` / `get_org_summary` / `get_org_alerts_full` all apply the same rule.
   - **Option C — composite-depth weighting:** penalize 1-field families in the healthy-reference pool and distance calc inside `_run_family_centroid_distance`. More nuanced; adds a knob; obscures the signal. Probably not worth the complexity.

2. **Markov stuck-loop detector will amplify site-wide outages.** Design goal is "don't create 500 device-family alerts on top of the one real RADIUS-down alert." The `detect_stuck_loop()` path in `markov_analyzer.py` fires whenever the dominant transition pair involves a failure/disassoc event and crosses `MARKOV_STUCK_LOOP_THRESHOLD`. During a site-wide auth outage, every family trips `AUTH_FAILURE → DEAUTH` simultaneously and every family's Markov rollup fires — one root cause, N alerts.
   - **Option A — site-level storm suppressor:** when ≥ X% of families at a site trip stuck-loop in the same cycle with the same dominant pair, suppress the per-family Markov flag and emit a single "site-wide failure mode detected" finding instead. Best long-term shape; adds a new finding type.
   - **Option B — pair-frequency dedup (leaning for MVP):** if the same `stuck_loop_pair` dominates ≥ X% of families at a site that cycle, suppress Markov flags for all of them. No new finding type — just a gate in the finding rollup in `anomaly_detector.score` / `score_org_wide`. Operator sees "Markov went quiet for this site" and cross-references Mist SLE / dashboard for the infrastructure outage. ~20 lines, directly addresses the RADIUS-down scenario.
   - **Option C — cross-site specificity:** in `score_org_wide`, require that a family's stuck-loop pair is *not* the dominant pair across the whole site population before firing Markov. Catches "iPhones are uniquely stuck" vs "everyone is stuck." Narrower than B.
   - Suggested path: ship B as the first iteration with a note pointing at A as the right long-term design.

3. **Roaming auth-failure strings inflate failure counts.** A device roaming across APs may emit several `MARVIS_EVENT_CLIENT_AUTH_FAILURE` / `MARVIS_EVENT_CLIENT_MAC_AUTH_FAILURE` / `MARVIS_EVENT_CLIENT_FBT_FAILURE` / `MARVIS_EVENT_CLIENT_AUTH_FAILURE_OKC` events before landing a successful `CLIENT_AUTHENTICATED` / `CLIENT_AUTH_REASSOCIATION_*`. The client recovered — from its perspective this is a normal mobility event, not a failure — but today every failed attempt counts toward `auth_failure` in both the health score (`health_scorer.compute_family_health`, per-MAC `auth_success / (auth_success + auth_failure)` ratio) and the feature vector (per-event-type frequency dimension). Compounding issue: these strings can also trip the Markov stuck-loop detector when the AUTH_FAILURE→AUTH_FAILURE pair dominates transitions.
   - **Core rule:** an auth-failure event is "recovered" if it's followed by a successful auth/reassoc for the same MAC within some short window (likely 30–60s based on real-payload fast-roam timing in CLAUDE.md). Recovered failures should be suppressed or downweighted; terminal failure strings (no successful auth after N seconds) should still count at full weight.
   - **Where to apply the suppression — has to be chosen carefully:**
     - At event collection / enrichment (`event_collector._enrich_batch`): drop or tag recovered failures before they land in SQLite. Cheapest consumer side but requires holding a lookahead buffer during the streaming write and means the raw event row no longer reflects what Mist sent. Probably wrong — we'd lose forensic data.
     - At feature-engineering time (`feature_engineer.build_features`): when emitting per-MAC counts, sweep the event stream and reclassify recovered failures (either drop them from `auth_failure` or bucket them into a new `auth_failure_recovered` semantic category separate from `auth_failure`). Preserves raw events; costs one extra pass per MAC. This is likely the right layer.
     - At health-score time only (`health_scorer.compute_family_health`): leave the ML feature vector alone and only suppress recovered failures from the health score's success/failure ratio. Narrowest change; limits the impact to the alert gate but leaves the IF / centroid detectors seeing the unmodified behavioral signature (which is arguably still meaningful — a device doing 10 roams with 3 failures each looks different from one doing clean roams, even if it "recovered" each time).
   - **Weighting options:**
     - **Hard suppression:** recovered failures drop from the auth_failure count entirely. Simplest. Risk: a device that genuinely has 50% auth-failure-then-retry behavior looks perfect.
     - **Partial weighting:** recovered failures count at e.g. 0.25×. Preserves some signal for pathological retry behavior.
     - **Separate category:** add `AUTH_FAILURE_RECOVERED` to `EVENT_CATEGORIES` and the `category_vector`, keep it out of the `FAILURE_CATS` used by the health scorer, but let it show up in the feature vector so IF / centroid / Markov can still learn on it. Most faithful representation; most invasive change.
   - **Interaction with Markov stuck-loop:** the stuck-loop detector in `markov_analyzer.detect_stuck_loop()` should probably be taught to ignore AUTH_FAILURE→AUTH_FAILURE pairs when the MAC's overall auth-failure run ends in a success within window. This is a separate code path from health / features and will need its own fix.
   - **Risks to weigh before implementing:** a device caught in a genuine roam-fail loop (PMKID stale, repeated FBT failures) that *eventually* succeeds via fallback would have its failure signal suppressed by any of the above rules. The "terminal vs recovered" window needs to be tight enough that "failed for 2 minutes, then recovered" still looks bad. Need real-payload validation before picking a threshold — the 60s fast-roam expectation from CLAUDE.md is a starting point, not a final value.
   - Suggested path: apply at feature-engineering time with a separate `AUTH_FAILURE_RECOVERED` category (option C of the weighting set) so detection and health both see the distinction but nothing is silently dropped. Validate against a known roaming-heavy site before tuning the window.

### SQLite concurrency — WAL mode + read connection pool (2026-04-18)

Phase 3 (per-site scoring) was parallelized with `asyncio.Semaphore(4)` on `score(site, wlan)`. Confirmed running concurrently via interleaved log timestamps across WLANs, but throughput improved only ~15-20% (sequential ~7 min → concurrent ~6 min on a 290-scope org). The bottleneck is the **single shared `aiosqlite` connection** in `db.get_connection()`: every `score()` call begins with `get_events(site, wlan)` which issues a SQL scan over a multi-million-row events table; with one connection, those queries serialize even though the calling tasks are concurrent. The post-query sklearn CPU work parallelizes fine (numpy releases the GIL), but it's a small fraction of per-scope time.

**Fix shape:** enable WAL mode (`PRAGMA journal_mode=WAL`, `PRAGMA synchronous=NORMAL`) and switch from a single shared connection to a small read pool (~4 connections) plus one dedicated write connection. WAL is SQLite's standard concurrent-reader mode and has shipped for 15+ years — the change itself is well-trodden. The work is in routing every call site to the correct pool.

**Why we punted on it before Tuesday's stability cut:**
- Risk profile is medium, not low. WAL mode introduces `-wal` and `-shm` sidecar files next to the `.db` — any backup/snapshot script that copies just the `.db` file produces a corrupt snapshot. Audit ops scripts before flipping the PRAGMA.
- Every write call site (`db.insert_events`, `db.upsert_clients_org`, `db.upsert_client_summaries`, `db.purge_old_events`, anything in `event_collector` / `client_cache` / `client_summary_builder`) must route to the dedicated write connection. A read connection issuing a write under WAL+pool will produce intermittent `database is locked` errors that only appear under collect+detect concurrency.
- The current ~14 min total detect runtime is comfortably inside the 1hr budget after the Phase 2 + Phase 5 fixes, so there's no operational pressure to ship this now.

**Implementation outline (~3-4 hours of focused work + ~1 hour validation):**
- `db.py`: replace `_shared_connection` singleton with `_read_pool: list[aiosqlite.Connection]` (size 4) and `_write_connection`. Add `get_read_connection()` async context manager that acquires from the pool, `get_write_connection()` that returns the single writer.
- `db.py` startup: enable WAL on the write connection (`PRAGMA journal_mode=WAL`, `PRAGMA synchronous=NORMAL`, `PRAGMA wal_autocheckpoint=1000`).
- Audit every `get_connection()` call site (~20 in `db.py` + a few in `event_collector` / `client_cache` / `client_summary_builder`). Read paths use `get_read_connection()`, write paths use `get_write_connection()`.
- Test plan: full event collect (12hr window) → full org detect → confirm zero `database is locked` errors in logs, finding counts match a sequential baseline, backup snapshot procedure handles the new WAL sidecars.
- Rollback: one-line PRAGMA change + revert the pool wiring. Keep on a feature branch until validated.

**Expected speedup:** Phase 3 from ~6 min to ~2 min (true 4-way parallelism instead of CPU-only). Total pipeline ~14 min → ~10 min. If concurrency is bumped to 8 alongside, possibly ~8 min total. Combined with future Phase 2 SQL aggregation (already conceived — push per-MAC event-type counts into a SQL `GROUP BY` like we did for `build_site_events_summary`), Phase 2 could drop further too.

**Schedule for after Tuesday's cut.** Quiet day, dedicated branch, validate the full collect+detect cycle end-to-end before merging.

### Centroid at manufacturer granularity — `<mfg>.catch_all` virtual families (2026-04-19)

Cross-references the "Manufacturer-only families inflate false positives" item (#1) above — this is the structural fix that replaces it. Capturing full design conversation so work can resume cold.

**Problem, sharpened.** Centroid currently runs per-fingerprint: `Apple | MacBook Pro | macOS 14`, `Apple | iPhone | iOS 17`, and bare `Apple` are three independent Centroid candidates. Two failure modes result:

1. **False positives on bare 1-token manufacturer families.** A device labelled only `Intel Corporate` is almost always a fingerprint-resolution failure (device never fully connected, Mist never got past OUI). Its event mix is dominated by connection failures because that's why it's unfingerprinted in the first place. Centroid faithfully reports this as "anomalous" — technically true, operationally noise.
2. **Asymmetric signal quality by manufacturer.** Live cache audit (2026-04-19):

   | Manufacturer | 1-token MACs | Fingerprinted MACs | Fingerprinted families | 1-token share |
   |---|---:|---:|---:|---:|
   | Intel Corporate | 1,538 | 3,959 | 38 | 28.0% |
   | Apple | 3,924 | 26,579 | 700 | 12.9% |
   | **Amazon** | **109** | **58** | **22** | **65.3%** |
   | Samsung | 89 | 265 | 85 | 25.1% |

   Intel noise is loud (1,538 bare stragglers, 38 healthy fingerprinted siblings to bury them in). Amazon is inverted — the 1-token row is the real signal because there are barely any fingerprinted Amazons. Today's per-fingerprint Centroid can't tell these cases apart.

**Design.** Per manufacturer `mfg`, build one virtual family `<mfg>.catch_all` that aggregates **every MAC whose manufacturer == mfg, regardless of fingerprint depth**. That catch-all is the **only** Centroid candidate for that manufacturer. Per-fingerprint rows (`Apple | iPhone | iOS 17`, bare `Apple`, etc.) stay in the system for DBSCAN, Markov, Health, Family Insights display, and drilldowns — they just drop out of the Centroid pass entirely. Modeled on the existing `.service_account` plumbing (composite key `{mac}#ca`, parallel feature record, emitted at `feature_engineer.build_features` time).

**Why this resolves both failure modes.** The fingerprinted-sibling population acts as statistical ballast:
- **Intel.** Bare `Intel Corporate` (1,538 stragglers) + fingerprinted siblings (3,959 healthy) merge into `Intel Corporate.catch_all` (~5,500 MACs). Healthy siblings outnumber stragglers 3:1, aggregate direction sits inside the healthy reference, **Centroid stops flagging Intel.**
- **Amazon.** Bare `Amazon` (109 mostly-failing) + fingerprinted siblings (58, also mostly-failing) merge into `Amazon.catch_all` (~167 MACs). Aggregate still points at failure, **Centroid still flags Amazon.** Signal preserved.

**Division of labor after this change.**
- **Centroid = per-manufacturer direction-of-aggregate-behavior.** Replaces today's per-fingerprint pass. Answers "is this whole manufacturer's population pointing at failure?"
- **DBSCAN = per-site within-population behavioral outliers.** Runs on fingerprinted families where the peer cohort is homogeneous. Unchanged.
- **Markov = per-MAC connection-chain pathology.** Runs on fingerprinted families. Unchanged.
- **Health = per-MAC failure rate.** Runs on everything. Unchanged.

**Evidence against (weighed, not dealbreakers):**
- **Loss of per-fingerprint Centroid signal.** If `Apple | iPhone | iOS 17` is broken but `Apple | iPhone | iOS 18` is fine, today's Centroid catches the iOS-17 pattern; new rule dilutes it 4:1+ under `Apple.catch_all`. DBSCAN + Markov should still catch the site-level anomaly, but validate before committing.
- **UI needs clear labelling.** Fingerprinted rows will show `—` in the Cosine column. Will need a `PER-MFG` badge or tooltip explaining Centroid runs per-manufacturer, DBSCAN/Markov run per-fingerprint.
- **Manufacturer normalization becomes load-bearing.** Any drift in `_clean_token()` output (`Apple Inc.` vs `Apple`) splits a catch-all. Pre-flight audit of distinct mfg values in the live cache before rollout.
- **Naming:** `Apple.catch_all` reads awkwardly next to `srv_Apple_EP.service_account`. Proposed internal suffix `.catch_all` for plumbing parity; display label something like `Apple (all)` or a `CATCH ALL` badge.

**Implementation plan (~1 day + 0.5 day UI):**
1. `feature_engineer.build_features`:
   - Build a `mfg → list[MAC]` map from the client cache (`client.manufacturer` after `_clean_token` normalization).
   - For each manufacturer with ≥ `catch_all_min_macs` (propose 10) MACs, emit a parallel feature record under composite key `{mac}#ca`, family name `<mfg>.catch_all`, with `is_catch_all_record=True` on the record.
   - Primary per-fingerprint records get a new `centroid_eligible=False` flag when family is 1-token OR when mfg has a catch-all (since the catch-all is the new Centroid candidate).
2. `anomaly_detector._run_family_centroid_distance` + `_family_mean_health`: filter to `centroid_eligible=True` families only. The `.catch_all` passes; per-fingerprint and bare-1-token rows don't.
3. `anomaly_detector.score` / `score_org_wide`: skip DBSCAN/Markov rollup for `.catch_all` rows (they're Centroid-only, matching the rule).
4. Rollup + findings: catch-all families generate findings exactly like service-account families. Dual-gate applies.
5. `summary_cache.py` + `api/routes.py`: `family_kind` field extended to include `catch_all`. Webhook payload adds `catch_all_member_families` (list of per-fingerprint family names folded into this catch-all).
6. Frontend: new `CATCH ALL` badge (distinct color from SA's tan), legend copy update, Family Insights catch-all row display.

**Config knobs to add (general section):**
- `catch_all_min_macs` (default 10) — minimum MACs to build a catch-all.
- `centroid_mode` (`per_manufacturer` | `per_fingerprint`, default `per_manufacturer` after rollout, `per_fingerprint` during validation) — kill switch.

**Validation plan before default-on:**
1. Ship with `centroid_mode=per_fingerprint` default so behavior matches today.
2. Toggle to `per_manufacturer` on the EmoryUnplugged WLAN. Compare the Intel alert rate and the Amazon alert rate before/after across 24hr of cycles.
3. Expected: Intel alerts go to zero; Amazon alerts persist. If DBSCAN independently catches per-fingerprint anomalies we care about, promote to default.

**Open questions (from conversation, for the implementer):**
- Does `Unknown/<mfg>` fold into `<mfg>.catch_all`? Lean: yes (same unfingerprinted population).
- Do service-account families still get their own Centroid pass? Lean: yes (different cohort axis — username vs manufacturer).
- Exact `catch_all_min_macs` threshold? Starting proposal 10; may raise.

**Scheduling:** post-hackathon. Replaces (not layers onto) item #1 at the top of this section. Do not ship before presentations.
