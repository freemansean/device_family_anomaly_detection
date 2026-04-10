# TODO — Known Issues & Improvement Backlog

## REMAINING FUNCTIONALITY IMPROVEMENTS
Review and rewrite this as needed at next launch.

We are at a point where the functionality is solid. There are only two outstanding items:

- Introduce some form of service account visibility, track commonly submitted usernames in the data. This can be seen on the clients call under the flag "last_username". Enrich the client events with this data along with the device type. Surface this information as an alternate way to track devices. if there are more than >50 client records with the same username then create another device family titled {username}.service_account/ This may result in client events going into two separate device families. Consider the architecture carefully. For example, the device may be labelled as "Mac" - which would see one device family - but the service account may be "srv_Apple_EP"
  - [x] Capture `last_username` from the Mist org clients endpoint in `client_cache.py` and persist it on the `clients` SQLite row (add `last_username` column + migration)
  - [x] Thread `last_username` through the event enrichment path in `event_collector.py` so every event inherits the username alongside `device_family` / `device_model` / `device_manufacturer`
  - [x] Decide where the ≥50-record threshold is evaluated (cache refresh vs. feature build) and implement the `{username}.service_account` virtual family generator
  - [x] Design the dual-family model: allow a single MAC to contribute to BOTH its device family (e.g. `MacBook`) AND its service-account family (e.g. `srv_Apple_EP.service_account`) without double-counting at the org rollup
  - [x] Update `feature_engineer.py` to emit per-MAC feature rows under both families when applicable
  - [x] Update `anomaly_detector.py` centroid + IF passes so service-account families are scored as first-class families
  - [x] Surface service-account families in Site Overview, Org Family Insights, and Findings feeds (new badge/label so operators can distinguish device-family vs. service-account-family rows)
  - [x] Add drilldown support so clicking a `*.service_account` family shows its member MACs with their primary device family also visible

- The Markov event chain needs to be reconsidered. We track truncated events AND failure pairs. Are these redundant? If so, consider which one should be kept. Simplify the Markov label in the GUI to reflect whether the device is being flagged as an anomaly due to either anomalous event connection chains (anomaly) or due to repeated short connections (repeated). Do this at the mac drilldown, site device family insights, and org family insights
  - [x] Audit `markov_analyzer.py` to document exactly what "truncated events" and "failure pairs" each measure and produce a written comparison
  - [x] Decide which signal to keep (or how to merge them) and remove the redundant code path — kept `is_stuck_loop`, removed Layer 2 episode-sequence scoring and `has_repeated_short_episodes`
  - [x] Collapse the Markov label surface area to two states: `anomaly` (anomalous connection-chain transitions) and `repeated` (stuck failure loops)
  - [x] Update anomaly record fields so downstream consumers read a single `markov_reason` field (per-MAC) + `markov_family_reason` (family rollup)
  - [x] Update `MacDrilldown.jsx` to show the simplified label
  - [x] Update Site Device Family Insights (`SiteOverview.jsx` / `FamilyDrilldown.jsx`) to show the simplified label
  - [x] Update Org Family Insights (`OrgFamilyInsights.jsx` / `OrgFamilyDrilldown.jsx`) to show the simplified label
  - [x] Update the webhook payload `probable_pattern` mapping if either of the removed signals feeds it — no-op; `_classify_probable_pattern` reads from posthoc features, not Markov flags

Once the functionality is complete we need to focus on trimming, optimizing, and clearing bugs.
- We should display a status bar when the hourly refresh is running, same as the full batch refresh
  - [ ] Add progress writes (`sasquatch:progress:org_hourly_poll` or similar) to `org_event_poll_job` in `scheduler.py` mirroring the full-collect progress schema
  - [ ] Expose progress via a `GET /api/v1/org/hourly-progress` endpoint in `api/routes.py`
  - [ ] Reuse the existing full-collect progress component in the frontend and bind it to the hourly endpoint
  - [ ] Ensure the status bar clears cleanly on success, failure, and when polling is disabled

- We should return to running ML detection after the full batch refresh or the hourly refresh automatically. This should be the default but the administrator should be able to disable this, same as they can disable the hourly refresh
  - [ ] Chain `run_org_pipeline()` after `collect_org_full()` inside `_org_collect_background_task`
  - [ ] Chain `run_org_pipeline()` after `org_event_poll_job` completes successfully
  - [ ] Add a Redis flag `sasquatch:auto_detect_enabled` (default `"1"`) gating the auto-run
  - [ ] Add `GET /api/v1/org/auto-detect` and `POST /api/v1/org/auto-detect` endpoints mirroring the hourly-poll toggle
  - [ ] Add an admin toggle in the Anomaly Config GUI next to the hourly-poll toggle
  - [ ] Make sure the global mutex is re-acquired cleanly between collect → detect so the chain does not race against a manual trigger

- We need to ensure that all the config controls are successfully being applied
  - [ ] Enumerate every control in the Anomaly Config GUI and list the runtime key each is supposed to drive
  - [ ] For each control, trace the save path → `config_overrides.json` → runtime read site (grep for the env var / override getter) and confirm the value is actually consumed
  - [ ] Fix any controls that write the override but whose consumer still reads the raw env var
  - [ ] Add a lightweight integration test or manual smoke-test script that flips each control and verifies the behavior change end-to-end

- We need to implement a client mac search, same as the site search. Explore ways to make this efficient
  - [ ] Confirm the `clients` and `events` SQLite tables already have the right indexes on `mac` (add if missing)
  - [ ] Add `GET /api/v1/org/clients/search?mac=` route that matches prefix/substring efficiently
  - [ ] Decide whether to search the `clients` table (metadata-only) or also join `events` (recency / last-seen) and document the choice
  - [ ] Add a MAC search input to the frontend mirroring the existing site search component
  - [ ] Wire the search result click-through to the existing MAC drilldown page

- This is for a hackathon. We need it to be easy to launch for evaluation. Consider the setup.sh and start.sh and make sure that they capture everything. For example, this failed on another computer because we didn't automatically create the sasquatch/frontend directory with the setup.sh script.
  - [ ] Re-read `setup.sh` and list every directory/file it assumes exists — fix the `sasquatch/frontend` gap specifically
  - [ ] Ensure `setup.sh` installs Python deps, frontend deps, creates the SQLite DB file, and writes a default `.env` from a template if one is missing
  - [ ] Ensure `start.sh` launches Redis (or checks it is running), the FastAPI backend, and the Vite frontend in the correct order
  - [ ] Validate the full flow on a throwaway clone / fresh machine or Docker container
  - [ ] Add a short README section documenting the one-command launch path for evaluators

- We need to explore removing the isolation forest technique for device family classification and make the cosine distance from families labelled "healthy" as the main way to detect family shifts. Isolation Forest should just be for intra-device family quirks.
  - [ ] Remove the centroid-IF branch in `anomaly_detector.py` so the cosine-distance-vs-healthy-reference path is the only family-level detector
  - [ ] Drop `ANOMALY_CENTROID_IF_MIN_FAMILIES` and `ANOMALY_CENTROID_DIST_MAX_FAMILIES` if they are no longer used (and update the env var table in CLAUDE.md)
  - [ ] Keep per-family Isolation Forest scoring exactly as-is for intra-family MAC outlier detection
  - [ ] Update finding rollup + frontend badges so "family shift" always reads as a centroid-distance result
  - [ ] Re-run against a known-bad site to confirm the simplified detector still catches the target families

- Service Alarm column should be sortable under Org Family Insights / Site Family Insights
  - [ ] Add sort handler + sort direction state to the Service Alarm column in `OrgFamilyInsights.jsx`
  - [ ] Add the same to the site-level family insights table
  - [ ] Decide the secondary sort key (e.g. health score, family name) for ties

- Introduce a new column in Org Family Insights / Site Family Insights titled "Count" that shows device family quantity. Make this sortable.
  - [ ] Ensure `/api/v1/org/family-insights` and the per-site equivalent return a `mac_count` (or similar) field
  - [ ] Add the "Count" column header + cell to `OrgFamilyInsights.jsx`
  - [ ] Add the same column to the site-level family insights table
  - [ ] Wire up sorting (numeric descending by default)

- Under the Organization -> Org Alerts make Site Alerts hidden by default, click a button to expand and show them.
  - [ ] Collapse the SITE ALERTS section in `OrgAlerts.jsx` on initial render
  - [ ] Add an expand/collapse button with a count badge (e.g. "Site Alerts (7)")
  - [ ] Persist the expanded state across auto-refreshes so it does not snap closed every 30s
  - [ ] Keep the ORG-WIDE ALERTS section visible by default

- Remove Shapley visualizations, keep it at the Findings cards but no need for the bar graphs at the drilldowns (device family or client)
  - [ ] Remove the Shapley bar graph component from `MacDrilldown.jsx`
  - [ ] Remove the Shapley bar graph component from the device-family drilldown (`FamilyDrilldown` / `OrgFamilyDrilldown`)
  - [ ] Leave the Findings card Shapley rendering untouched
  - [ ] Delete any Shapley-specific API response fields that only powered the removed graphs (if they are no longer referenced anywhere)

- Revise the webhook format, remove unnecessary details
  - [ ] List every field currently emitted in `webhook_dispatcher.py` and mark each as keep / drop / consolidate
  - [ ] Confirm with the Sasquatch webhook consumer which fields it actually reads
  - [ ] Trim the payload and update the example JSON in CLAUDE.md so it matches reality
  - [ ] Bump a `schema_version` or `source` suffix if the downstream consumer needs to disambiguate old vs. new payloads

- Apply the RSSI filter to trim out failed auths due to signal strength
  - [ ] Pick the RSSI threshold (e.g. `-80` dBm) and expose it as an env var / config override
  - [ ] In `event_collector.py` (or `feature_engineer.py`, whichever is cleaner) drop AUTH_FAILURE events whose `rssi` is below the threshold before they hit the feature vector
  - [ ] Keep a counter / log line reporting how many events were filtered per collect so the effect is observable
  - [ ] Verify the filter does not accidentally drop successful auths or non-auth event types
