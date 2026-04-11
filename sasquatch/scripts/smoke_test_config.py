#!/usr/bin/env python3
"""
smoke_test_config.py — Offline smoke test for the Sasquatch config controls.

For every GUI-configurable control, verify:
  1. The key exists in client_anomaly.config.DEFAULTS
  2. Writing a test value to config_overrides.json causes config.get()
     to return that value (i.e. the GUI override is honored at runtime)
  3. Restoring the original overrides returns the original resolved value

This catches:
  - GUI controls that drift out of sync with config.py DEFAULTS
  - Regressions where a module-level constant read bypasses config.get()
    (e.g. `VALUE = int(os.getenv("X", "5"))` at import time)

It does NOT verify that every downstream consumer calls config.get() — for
that, trace suspected consumers by hand. This script only confirms the
resolution chain works end-to-end for the current DEFAULTS table.

Does not require the FastAPI server to be running. Run from the repo root:

    python3 -m sasquatch.scripts.smoke_test_config
"""

from __future__ import annotations

import json
import os
import pathlib
import sys

# Make `sasquatch` importable when run as a script from the repo root.
_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO_ROOT))

from sasquatch.client_anomaly import config  # noqa: E402

_OVERRIDES_FILE = pathlib.Path(config.__file__).parent / "config_overrides.json"


# Every control exposed in the frontend GUI (App.jsx Config modal).
# Keep this list in sync with the sliders/inputs rendered in the General
# Config and Anomaly Config tabs.
GUI_CONTROLS: list[tuple[str, str, float | int]] = [
    # (section, key, test_value)
    # General tab
    ("general", "org_detection_interval_hours", 6),
    ("general", "anomaly_min_mac_events", 42),
    ("general", "alarm_min_family_size", 3),
    ("general", "anomaly_health_score_threshold", 0.62),
    # Anomaly tab — Isolation Forest
    ("anomaly", "anomaly_if_contamination", 0.17),
    ("anomaly", "anomaly_min_peers", 7),
    # Anomaly tab — DBSCAN
    # min_samples is auto-tuned per run from population size; the only
    # admin-tunable input is the percentage knob (integer 1–10 → 0.01–0.10).
    # eps is auto-selected per run via the k-distance elbow method.
    ("anomaly", "anomaly_dbscan_min_samples_pct", 4),
    # Anomaly tab — Centroid detection
    ("anomaly", "anomaly_centroid_dist_threshold", 0.42),
    ("anomaly", "anomaly_centroid_healthy_ref_threshold", 0.66),
    # Anomaly tab — Finding rollup (rendered inside DBSCAN section in the GUI)
    ("anomaly", "anomaly_finding_threshold", 0.27),
    # Anomaly tab — Markov
    ("anomaly", "markov_family_outlier_ratio", 0.37),
    ("anomaly", "markov_stuck_loop_threshold", 0.55),
    ("anomaly", "markov_stuck_loop_min_events", 33),
    ("anomaly", "markov_min_episode_length", 6),
    ("anomaly", "markov_outlier_episode_ratio", 0.48),
    ("anomaly", "markov_min_scoreable_episodes", 4),
]


def _load_overrides_raw() -> dict:
    try:
        return json.loads(_OVERRIDES_FILE.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _write_overrides_raw(data: dict) -> None:
    _OVERRIDES_FILE.write_text(json.dumps(data, indent=2))


def _set_override(section: str, key: str, value: float | int) -> None:
    data = _load_overrides_raw()
    data.setdefault(section, {})[key] = value
    _write_overrides_raw(data)


def _clear_override(section: str, key: str) -> None:
    data = _load_overrides_raw()
    if section in data and key in data[section]:
        del data[section][key]
        _write_overrides_raw(data)


def main() -> int:
    # Guard against running against any env-var override masking the test.
    # If an env var is set for one of our keys, we can't prove config.get()
    # honored the file override (env vars would also make it return the same
    # value). We skip those keys with a warning rather than fail the test.
    original_overrides = _load_overrides_raw()

    passed = 0
    failed = 0
    skipped = 0
    failures: list[str] = []

    print(f"Overrides file: {_OVERRIDES_FILE}")
    print(f"Controls to test: {len(GUI_CONTROLS)}")
    print()

    try:
        for section, key, test_value in GUI_CONTROLS:
            # 1. Key must be in DEFAULTS
            spec = config.DEFAULTS.get(section, {}).get(key)
            if spec is None:
                failed += 1
                failures.append(f"{section}.{key}: NOT in config.DEFAULTS")
                print(f"  FAIL  {section}.{key}  — not declared in config.DEFAULTS")
                continue

            env_var = spec["env"]
            env_set = env_var in os.environ
            if env_set:
                skipped += 1
                print(
                    f"  SKIP  {section}.{key}  — ${env_var} is set in the environment; "
                    f"cannot prove GUI override is consumed"
                )
                continue

            # 2. Write the test value to the overrides file
            _set_override(section, key, test_value)
            resolved = config.get(section, key)
            if resolved != spec["cast"](test_value):
                failed += 1
                failures.append(
                    f"{section}.{key}: set override to {test_value!r}, "
                    f"config.get returned {resolved!r}"
                )
                print(
                    f"  FAIL  {section}.{key}  — set {test_value!r}, got {resolved!r}"
                )
                # Restore and continue
                _clear_override(section, key)
                continue

            # 3. Clear the override, verify fallback
            _clear_override(section, key)
            fallback = config.get(section, key)
            expected_fallback = spec["cast"](
                os.environ.get(env_var, spec["default"])
            )
            if fallback != expected_fallback:
                failed += 1
                failures.append(
                    f"{section}.{key}: fallback returned {fallback!r}, "
                    f"expected {expected_fallback!r}"
                )
                print(
                    f"  FAIL  {section}.{key}  — fallback {fallback!r} != "
                    f"{expected_fallback!r}"
                )
                continue

            passed += 1
            print(
                f"  PASS  {section}.{key}  override {test_value!r} "
                f"→ get={resolved!r}, fallback={fallback!r}"
            )
    finally:
        # Always restore original overrides, even on crash.
        _write_overrides_raw(original_overrides)

    print()
    print(f"Summary: {passed} passed, {failed} failed, {skipped} skipped")
    if failures:
        print()
        print("Failures:")
        for line in failures:
            print(f"  - {line}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
