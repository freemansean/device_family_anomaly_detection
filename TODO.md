# TODO — Known Issues & Improvement Backlog

## Open Work

- Remove the Sign-in Function

- Error 422 when clicking on a service account at the site level

- Re-run the simplified inter-family centroid detector (cosine distance, no IF) against a known-bad site to confirm it still catches the target families. Context: the centroid-IF branch was removed in favor of cosine-distance-vs-healthy-reference as the sole family-level detector; intra-family IF is unchanged. Needs an end-to-end validation pass on production data.

- Phase 4 per-site `score()` is silently skipping (site, wlan) combos in `run_org_pipeline`. Observed: `sasquatch:features:*` keys far outnumber `sasquatch:anomalies:*` keys. The per-site path returns 0 at `anomaly_detector.py:578-597` whenever `build_features` emits an empty dict (every MAC filtered below `ANOMALY_MIN_MAC_EVENTS`). `score_org_wide` is less sensitive because it pools MACs across all sites for the same WLAN, so a site that contributes zero per-site rows can still contribute to the org-wide alert count. Initial mitigation shipped 2026-04-10: `get_org_family_drilldown` now falls back to `sasquatch:org_anomalies:{site}:{wlan}` when the per-site anomalies key is missing, and Phase 4 emits a summary log + WARNING on empty-features returns.
  - [ ] Deploy-verify that `get_org_family_drilldown`'s `org_anomalies` fallback closes the "15/15 devices on the card, 4 MACs in the drilldown" gap for both the SA and non-SA branches.
  - [ ] Note (2026-04-10): the original root-cause write-up claimed `ANOMALY_MIN_MAC_EVENTS` defaults to 20; the actual default in `config.py:33` is **5**. The new WARNING log in `score()` prints the effective value each cycle — once a deploy run exists, confirm whether the 5-event floor really is filtering that many MACs or whether a different filter inside `feature_engineer.py:376-435` is the real cause.
  - [ ] Decide whether to make `org_anomalies` the first-class source (retire per-site `score()` entirely — `score_org_wide` already writes real-MAC-keyed records) or fix Phase 4 so both stores stay in sync (lower `MIN_MAC_EVENTS` when the org pool has enough peers, OR write an empty-but-present anomalies record so the drilldown can distinguish "ran and found nothing" from "never ran"). This is a detection-quality decision, not plumbing — both paths compute different things (site-local vs org-wide peer groups). **Blocked on deploy verification of the instrumentation.**
  - [ ] Once root-caused, backfill the missing per-site anomalies keys on the next pipeline run and verify the ratio closes to ~1:1 with features keys (skip entirely if the first-class-source option is chosen).
