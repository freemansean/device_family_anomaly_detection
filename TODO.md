# TODO — Known Issues & Improvement Backlog

## Open Work

- [X]  Break down client disassociation / AP disassociation
- [X]  Validate if we need “Security” Events
- [x]  Make Device Family Drilldown cached — `client_summary` SQLite table (2026-04-15)
- [X]  Create site/org level ML detection for the search option

### Findings / Alerts UI rework (2026-04-11)

Scope: [OrgAlerts.jsx](sasquatch/frontend/src/components/OrgAlerts.jsx), [OrgFindingsFeed.jsx](sasquatch/frontend/src/components/OrgFindingsFeed.jsx), [FindingsFeed.jsx](sasquatch/frontend/src/components/FindingsFeed.jsx). Related backend: `get_org_alerts` / per-site findings response shape in `api/routes.py` (check whether site-level findings already carry the dual-gate alert data the UI will need for item 4).

1. **Grid layout for finding / alert cards.** Org Alerts (ORG-WIDE ALERTS + SITE ALERTS sections), Org Findings, and Site Findings currently render cards in a single full-width column (`display: flex; flexDirection: column`). Convert each card list to a responsive CSS grid (e.g. `display: grid; gridTemplateColumns: repeat(auto-fill, minmax(480px, 1fr)); gap: 10px`) so cards tile side-by-side. Verify card internals (the right-aligned device / health / failure-rate block) still fit at the narrower per-cell width — may need to drop `flex-shrink: 0` on the right column or reflow it below the title row.
   - Files: [OrgAlerts.jsx:376-384](sasquatch/frontend/src/components/OrgAlerts.jsx#L376-L384) (ORG-WIDE ALERTS list), [OrgAlerts.jsx:244-253](sasquatch/frontend/src/components/OrgAlerts.jsx#L244-L253) (SiteAlertGroup inner list), [OrgFindingsFeed.jsx:365-399](sasquatch/frontend/src/components/OrgFindingsFeed.jsx#L365-L399) (all three detector sections), [FindingsFeed.jsx:474-507](sasquatch/frontend/src/components/FindingsFeed.jsx#L474-L507) (all three detector sections + GENERAL HEALTH).
   - Leave the 7-day history rows in OrgAlerts as full-width — they are timeline entries, not finding cards.

2. **Unify Site Findings card shape with Org Findings.** [FindingsFeed.jsx](sasquatch/frontend/src/components/FindingsFeed.jsx) renders a `ShapleyBlock` ("Device Family Behavior Explanation" + cosine-distance bar + top-features list) on every card ([FindingsFeed.jsx:265-278](sasquatch/frontend/src/components/FindingsFeed.jsx#L265-L278)); [OrgFindingsFeed.jsx](sasquatch/frontend/src/components/OrgFindingsFeed.jsx) does not. Remove the Shapley block and the `shapleyScoreFromCentroidDist` / `shapleyColor` / `ShapleyBlock` helpers from `FindingsFeed.jsx`. Port the org card's top-features chip row ([OrgFindingsFeed.jsx:200-212](sasquatch/frontend/src/components/OrgFindingsFeed.jsx#L200-L212)) into the site card so the two look identical. After this, a site finding should render the same as an org finding filtered to a single site.
   - Also align the expand / "Show N example MACs" behavior: OrgFindingsFeed has no example-MAC expander and uses a clickable family name to drilldown instead. Decide whether the site card should adopt the same pattern (likely yes, for true parity) — if so, replace the `example_macs` expander ([FindingsFeed.jsx:308-329](sasquatch/frontend/src/components/FindingsFeed.jsx#L308-L329)) with a family-name click that opens `FamilyDrilldown` scoped to the current site. `FindingsFeed` already receives `siteId`; it will need to manage `selectedFamily` state and render `FamilyDrilldown` in place like OrgFindingsFeed does.

3. **Unify detector-method display — all badges to the right of the family name, no section-header grouping.** Today, both feeds partition findings into `ifCentroidFindings` / `dbscanFindings` / `markovFindings` / `ifDeviceFindings` and render each group under a `SectionHeader` ("CENTROID" / "DBSCAN" / "MARKOV"), which visually places the DBSCAN label to the left / above a DBSCAN-grouped card while per-card Centroid / Markov badges sit to the right of the family name. Collapse this into a single flat list per feed and rely on the per-card detector badges (`Centroid` / `DBSCAN family` / `Markov {reason}`) already rendered next to the family name ([FindingsFeed.jsx:209-228](sasquatch/frontend/src/components/FindingsFeed.jsx#L209-L228), [OrgFindingsFeed.jsx:138-155](sasquatch/frontend/src/components/OrgFindingsFeed.jsx#L138-L155)) for method attribution. Outcome: every finding card shows its detector method(s) as badges to the right of the device family name, regardless of which detector(s) flagged it, and the layout is identical between site and org views.
   - Drop the `ifCentroidFindings` / `dbscanFindings` / `markovFindings` / `ifDeviceFindings` partitioning and the detector-method `SectionHeader` calls in both files ([FindingsFeed.jsx:414-422](sasquatch/frontend/src/components/FindingsFeed.jsx#L414-L422) + [FindingsFeed.jsx:470-498](sasquatch/frontend/src/components/FindingsFeed.jsx#L470-L498), [OrgFindingsFeed.jsx:308-315](sasquatch/frontend/src/components/OrgFindingsFeed.jsx#L308-L315) + [OrgFindingsFeed.jsx:361-389](sasquatch/frontend/src/components/OrgFindingsFeed.jsx#L361-L389)). Keep the GENERAL HEALTH section (separate concept — unhealthy families with no anomaly finding).
   - Decide on ordering for the flat list. Suggested: severity (`significant` → `moderate` → `minimal`), then `outlier_ratio` desc. Alerts (dual-gate) should float to the top within each severity bucket.
   - If a finding is flagged by multiple detectors, all badges should render (already the case per the existing conditional renders — verify no card currently suppresses a second badge).

4. **Surface site-level alerts on the Site Findings view.** When a site finding meets the dual gate (`is_family_outlier` + `health_score < threshold`), the card currently just changes color and adds an inline `ALERT` pill ([FindingsFeed.jsx:168-172](sasquatch/frontend/src/components/FindingsFeed.jsx#L168-L172)). The escalation isn't called out at the page level the way OrgAlerts calls it out at the org level. Two pieces of work:
   - Add a page-level "SITE ALERTS" header block at the top of `FindingsFeed` that lists the site's dual-gate alerts as dedicated cards (mirroring the ORG-WIDE ALERTS section in OrgAlerts), followed by the unified findings list below. Reuse the same alert-card shape so visuals are consistent.
   - Confirm the site findings API payload carries everything the alert card needs (`is_family_outlier`, `health_score`, `worst_health_macs`, `health_components`). Today `FindingsFeed` cross-references `health` from a separate endpoint ([FindingsFeed.jsx:386-389](sasquatch/frontend/src/components/FindingsFeed.jsx#L386-L389)) — that's fine, but `worst_health_macs` is not written to per-site finding records by `score()` in `anomaly_detector.py` (only `score_org_wide` writes it, per CLAUDE.md). If site alert cards need to show worst-health MACs like org alert cards do, either (a) teach per-site `score()` to write the same field, or (b) have the site alert card fall back to querying `/api/v1/sites/{site_id}/health` for the worst MACs. Pick one before implementing the card.
   - Bonus: once site-level alerts are promoted, consider hiding the inline `ALERT` pill + red recoloring on cards in the main findings list for families already lifted into the SITE ALERTS section, to avoid double-surfacing.

### Pre-submission hardening (2026-04-16)

Work bucketed by risk. Within each bucket, ordered by fix cost (cheapest first) so a partial pass still lands the high-ROI items.

#### Bucket A — Security / Info leakage ✅ (2026-04-16)

- [x] **CORS wildcard** — [main.py:50](sasquatch/main.py#L50) was `allow_origins=["*"]`. Now pinned to `http://localhost:3000` + `http://localhost:5173` (and their `127.0.0.1` twins).
- [x] **Exception string leaked in HTTP response** — swept all `detail=f"...{exc}"` in [api/routes.py](sasquatch/client_anomaly/api/routes.py). Two real leaks found and fixed: line 993 (`Org client refresh failed`) and line 3130 (`Markov baseline rebuild failed`). Both already had `log.exception(...)` capturing the traceback server-side. Other `detail=f"..."` instances interpolate user-supplied values (field names, families, MACs) not exceptions — safe.
- [x] **Token-bearing log lines** — audited. `MIST_API_TOKEN` is only ever interpolated into `Authorization: Token ...` headers, never into log or exception messages. The `"MIST_API_TOKEN not configured"` messages leak the variable *name*, not the value. No redaction needed.

#### Bucket B — Crash risks (will kill a live demo) ✅ (2026-04-16)

- [x] **Pagination page-count ceiling** — [event_collector.py:396-413](sasquatch/client_anomaly/event_collector.py#L396-L413) now caps at `_MAX_PAGES = 20000` (20M events) and also guards `resp.json()` with an explicit `JSONDecodeError` branch that includes a 200-char body snippet. Same treatment applied to [client_cache.py:254-273](sasquatch/client_anomaly/client_cache.py#L254-L273) (cap at 10k pages = 10M clients).
- [x] **Per-row JSON decode** — [db.py:339-353](sasquatch/client_anomaly/db.py#L339-L353). `get_events` now decodes row-by-row inside a `try/except (JSONDecodeError, TypeError)`; bad rows are counted and a single summary WARNING is emitted per call.
- [x] **TSHOOT `asyncio.gather`** — [webhook_dispatcher.py:515-530](sasquatch/client_anomaly/webhook_dispatcher.py#L515-L530). Now passes `return_exceptions=True` and the zip loop checks `isinstance(result, BaseException)` → logs a WARNING and falls through with empty `tshoot_results`. One failed MAC can no longer crash the whole dispatch.
- [x] **`alert_tracker.record_cycle()` guarded** — [webhook_dispatcher.py:483-495](sasquatch/client_anomaly/webhook_dispatcher.py#L483-L495). Wrapped in `try/except Exception` with `log.exception`. Alert-history is now best-effort; the outbound webhook is load-bearing.
- [x] **`client_cache.py` `resp.json()` guarded** — handled by the same `JSONDecodeError` wrapper added for the pagination-cap fix ([client_cache.py:263-269](sasquatch/client_anomaly/client_cache.py#L263-L269)).

#### Bucket C — Correctness ✅ (2026-04-16)

- [x] **Dead `or True`** — [anomaly_detector.py:1267](sasquatch/client_anomaly/anomaly_detector.py#L1267) replaced with `= True`. Comment clarifies intent.
- [x] **Bare `except` narrowed** — [anomaly_detector.py:1244](sasquatch/client_anomaly/anomaly_detector.py#L1244) now `except (json.JSONDecodeError, TypeError) as exc:` with a `log.warning` carrying site_id + wlan.
- [x] **Event-type-index fallback** — no action needed. [event_collector.py:336-337](sasquatch/client_anomaly/event_collector.py#L336-L337) already logs via `log.warning(f"Failed to fetch live event type index: {exc} — using hardcoded list")`. The prior review was stale.

#### Bucket D — Robustness ✅ (2026-04-16)

- [x] **Empty `wlan` query param** — all 16 `wlan: str = Query(..., description="...")` occurrences in [api/routes.py](sasquatch/client_anomaly/api/routes.py) now carry `min_length=1`. Applied via `replace_all` on the exact matching string.
- [x] **MAC query param format** — [api/routes.py:1005-1010](sasquatch/client_anomaly/api/routes.py#L1005-L1010) now has `min_length=1, pattern=r"^[a-fA-F0-9:.\-\s]+$"` on the only MAC `Query(...)` call (`/org/clients/search`). Other MACs are path params (validated downstream by normalize helpers) or come in request bodies.
- [x] **Global-lock TTL** — [scheduler.py:46](sasquatch/client_anomaly/scheduler.py#L46) raised from 2h to 6h with an inline note clarifying that `clear_stale_global_lock()` at startup is the real crash-recovery mechanism; TTL is a backstop.
- [x] **Huge payload log** — [webhook_dispatcher.py:560-572](sasquatch/client_anomaly/webhook_dispatcher.py#L560-L572). INFO log now shows `len(qualifying)` + first 3 device families (`(+N more)` suffix when truncated). Full payload moved behind `log.isEnabledFor(logging.DEBUG)`.

#### Suggested execution order

1. **Bucket A + dead `or True` in Bucket C** — ~20 min, all one-line changes, highest "a reviewer will see this" ROI.
2. **Bucket B** — ~45 min, closes the demo-crash surface. The pagination guard and the TSHOOT `return_exceptions=True` are the two fixes most likely to actually trip during judging.
3. **Remaining Bucket C + Bucket D** — polish. If time runs out, skip these; none of them are externally visible on a happy-path demo.

### Code-cleanup pass (2026-04-16)

Dead-code audit after the hardening pass. All fixes verified: modules compile, the FastAPI app imports cleanly at runtime, and repo-wide grep returns no residual references to the deleted symbols.

- [x] **Deleted unused `_tally_outliers` helper** — [api/routes.py](sasquatch/client_anomaly/api/routes.py). Defined but called nowhere in the repo. −6 lines.
- [x] **Deleted orphan `/org/detection-enabled` endpoints (GET + POST)** — [api/routes.py](sasquatch/client_anomaly/api/routes.py). No frontend caller, no internal caller, Redis key `sasquatch:org_detection_enabled` had zero readers/writers elsewhere. Superseded by the `auto-detect` mechanism (`/org/auto-detect`). −25 lines.
- [x] **Deleted abandoned `pass`-loop in `delete_client_summaries_not_in`** — [db.py:912-923](sasquatch/client_anomaly/db.py#L912-L923) built placeholders then did nothing; real logic already followed on the next lines. Half-finished refactor. −11 lines.
- [x] **Extracted `_family_mean_health` helper** — [anomaly_detector.py:497](sasquatch/client_anomaly/anomaly_detector.py#L497). Replaced two near-verbatim 13-line blocks (site-scope at ~703 and org-scope at ~1154) that computed per-family mean health before feeding `_run_family_centroid_distance`. −10 lines net, single source of truth.

#### Known-to-be-real but deferred

These were identified during the audit but the payoff is too small for a hackathon submission. Carry them into the post-hackathon backlog.

- `db.search_clients_by_mac_prefix` issues 2 extra SQLite queries per matched MAC (N+1 pattern; ~100 queries for a 50-result prefix search). Worth fixing if the MAC-search UI feels laggy. Rewrite as a single JOIN with `MAX(timestamp)` + `COUNT(*)`.
- `event_collector._persist_unknown_types` opens a fresh Redis client on every flush. On a 12-hour collect that's ~100 connection setups. Accept an optional `redis_client` parameter the way `health_scorer.score_health()` does.
- `alert_tracker.record_cycle` uses a Redis `pipeline` of individual `.get()` calls where `mget` would collapse to one round-trip.
- `anomaly_detector.score_org_wide` finding rollup makes 3–4 separate passes over `family_cks`. Fuse into one accumulator loop. Measurable in the tens-of-milliseconds range at org scale; invisible to a demo.
- **Frontend card duplication** — `AnomalyFindingCard`, `HealthOnlyCard`, `PATTERN_LABELS`, `healthScoreColor` are re-defined across `OrgFindingsFeed.jsx`, `FindingsFeed.jsx`, `OrgAlerts.jsx`. Captured in items 2–3 of the "Findings / Alerts UI rework (2026-04-11)" section above — leave it there.
- **Markov family rollup may be duplicated** between site-scoped and org-scoped paths in `markov_analyzer.py`. Flagged by the audit but not line-verified; needs a read-through before extraction because the reason-selection logic ("anomaly" vs "repeated") has historically been delicate.
- **Inlining `_empty_markov_result`** at its two callers in `markov_analyzer.py`. Low-value churn; skip.

### Pre-existing

- Error 422 when clicking on a service account at the site level

- Introduce the "All WLANs" again now that we have a better data backend.

- If All WLANs is selected at the Org Alarms Level, have a section at the top that mentions "Cross WLAN Alarms" but then have a section just below that shows "WLAN Specific Alarms" that aggregates from the different WLANs.

- If a device has 0 sucess and all failures it should win the "sort-by-ratio" and be negatively highlighted

- Re-run the simplified inter-family centroid detector (cosine distance, no IF) against a known-bad site to confirm it still catches the target families. Context: the centroid-IF branch was removed in favor of cosine-distance-vs-healthy-reference as the sole family-level detector; intra-family IF is unchanged. Needs an end-to-end validation pass on production data.

- Modify the Centroid Healthy Reference logic to exlude devices in a family that are above the threshold as well so that single abherrent devices in a healthy family don't form the healthy baseline

- Seems we are generating alarms with device health scores above the threshold defined in the config. Validate that this is wired correctly

- Speed optimizations as possible, database is starting to fail during page loads (drilldowns migrated to `client_summary` table — 2026-04-15, remaining: evaluate if other views benefit from the same pattern)

- Phase 4 per-site `score()` is silently skipping (site, wlan) combos in `run_org_pipeline`. Observed: `sasquatch:features:*` keys far outnumber `sasquatch:anomalies:*` keys. The per-site path returns 0 at `anomaly_detector.py:578-597` whenever `build_features` emits an empty dict (every MAC filtered below `ANOMALY_MIN_MAC_EVENTS`). `score_org_wide` is less sensitive because it pools MACs across all sites for the same WLAN, so a site that contributes zero per-site rows can still contribute to the org-wide alert count. Initial mitigation shipped 2026-04-10: `get_org_family_drilldown` now falls back to `sasquatch:org_anomalies:{site}:{wlan}` when the per-site anomalies key is missing, and Phase 4 emits a summary log + WARNING on empty-features returns.
  - [ ] Deploy-verify that `get_org_family_drilldown`'s `org_anomalies` fallback closes the "15/15 devices on the card, 4 MACs in the drilldown" gap for both the SA and non-SA branches.
  - [ ] Note (2026-04-10): the original root-cause write-up claimed `ANOMALY_MIN_MAC_EVENTS` defaults to 20; the actual default in `config.py:33` is **5**. The new WARNING log in `score()` prints the effective value each cycle — once a deploy run exists, confirm whether the 5-event floor really is filtering that many MACs or whether a different filter inside `feature_engineer.py:376-435` is the real cause.
  - [ ] Decide whether to make `org_anomalies` the first-class source (retire per-site `score()` entirely — `score_org_wide` already writes real-MAC-keyed records) or fix Phase 4 so both stores stay in sync (lower `MIN_MAC_EVENTS` when the org pool has enough peers, OR write an empty-but-present anomalies record so the drilldown can distinguish "ran and found nothing" from "never ran"). This is a detection-quality decision, not plumbing — both paths compute different things (site-local vs org-wide peer groups). **Blocked on deploy verification of the instrumentation.**
  - [ ] Once root-caused, backfill the missing per-site anomalies keys on the next pipeline run and verify the ratio closes to ~1:1 with features keys (skip entirely if the first-class-source option is chosen).
