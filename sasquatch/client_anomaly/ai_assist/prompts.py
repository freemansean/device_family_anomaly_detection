"""
prompts.py — Ollama prompt templates for AI Assist device family analysis.

This file is the primary tuning surface for LLM behaviour. Edit the templates
below to change how the model frames its analysis and comparisons. All templates
use Python str.format_map() substitution — keys are wrapped in {braces}.

Templates
---------
SYSTEM_PROMPT        : Shared system role given to the model for every request.
ANALYZE_USER_PROMPT  : User-turn prompt for single-family analysis.
COMPARE_USER_PROMPT  : User-turn prompt for two-family comparison.

Helper
------
format_family_block(stats) : Converts a family stats dict into the text block
                             embedded in the prompts above.
"""

# ---------------------------------------------------------------------------
# System prompt — sets the model's role and tone for every request
# ---------------------------------------------------------------------------
SYSTEM_PROMPT = """\
You are a WiFi network operations expert analysing client device behaviour on a
Juniper Mist enterprise wireless network.

You interpret raw telemetry: event category distributions, Isolation Forest
anomaly scores, DBSCAN cluster outliers, and pattern findings surfaced by
unsupervised ML. Translate this data into clear, actionable summaries for
network administrators.

Guidelines:
- Be specific — cite the numbers in the data, do not fabricate figures.
- Be concise — use bullet points and short paragraphs.
- Prioritise actionable observations over background theory.
- If the data looks normal, say so clearly.
- Avoid generic network advice unrelated to what the data shows.
"""

# ---------------------------------------------------------------------------
# Single-family analysis prompt
# ---------------------------------------------------------------------------
ANALYZE_USER_PROMPT = """\
Analyse the following device family on this Juniper Mist network.

Scope: {scope_label}

{family_block}

Provide:
1. A one-sentence headline summarising the family's overall health.
2. Notable patterns in the event category distribution (highlight anything \
unusually high or low).
3. Anomaly detection summary — what the IF outlier rate and any flagged \
patterns suggest.
4. Specific recommendations, if any, for the administrator.
"""

# ---------------------------------------------------------------------------
# Two-family comparison prompt
# ---------------------------------------------------------------------------
COMPARE_USER_PROMPT = """\
Compare and contrast the following two device families on this Juniper Mist network.

Scope: {scope_label}

--- FAMILY A ---
{family_block_a}

--- FAMILY B ---
{family_block_b}

Provide:
1. A one-sentence headline for each family's overall health.
2. Key similarities in behaviour between the two families.
3. Key differences — focus on event category ratios, outlier rates, and \
severity findings.
4. Which family (if either) warrants more immediate attention, and why.
5. Specific recommendations for the administrator based on the comparison.
"""

# ---------------------------------------------------------------------------
# Helper: format one family's stats dict into a readable text block
# ---------------------------------------------------------------------------

# Event categories considered "failure-indicative" — used to flag them
# in the formatted output. Update this list if EVENT_CATEGORIES changes.
_FAILURE_CATEGORIES = {
    "DHCP_FAILURE",
    "AUTH_FAILURE",
    "DNS_FAILURE",
    "ROAM_FAILURE",
    "ASSOC_FAILURE",
}

# Human-readable labels for event category keys
_CATEGORY_LABELS = {
    "AUTH":           "Authentication",
    "AUTH_FAILURE":   "Auth Failure",
    "DHCP":           "DHCP",
    "DHCP_FAILURE":   "DHCP Failure",
    "DNS":            "DNS",
    "DNS_FAILURE":    "DNS Failure",
    "ROAM":           "Roam",
    "ROAM_FAILURE":   "Roam Failure",
    "ASSOC":          "Association",
    "ASSOC_FAILURE":  "Assoc Failure",
    "DOT1X":          "802.1X / EAP",
    "DYNAMIC_VLAN":   "Dynamic VLAN",
    "ARP":            "ARP",
    "BEACON":         "Beacon / Probe",
    "OTHER":          "Other",
}


def format_family_block(stats: dict) -> str:
    """
    Convert a family stats dict (as returned by data_collector.gather_family_stats)
    into a human-readable text block suitable for embedding in the prompts above.

    stats keys expected:
      name            str
      total_events    int
      client_count    int
      site_count      int  (only meaningful for org scope)
      worst_severity  str | None
      is_family_outlier bool
      if_outlier_count  int
      categories      {cat_key: {count: int, ratio: float}}
      findings        [{probable_pattern, severity, mac_count, example_macs}]
    """
    name = stats.get("name", "Unknown")
    total_events = stats.get("total_events", 0)
    client_count = stats.get("client_count", 0)
    site_count = stats.get("site_count")
    if_outlier_count = stats.get("if_outlier_count", 0)
    worst_severity = stats.get("worst_severity") or "none"
    is_family_outlier = stats.get("is_family_outlier", False)

    lines = [f"Device Family: {name}"]

    # Overview line
    overview_parts = [
        f"{client_count} client(s)",
        f"{total_events:,} events",
    ]
    if site_count is not None:
        overview_parts.append(f"seen across {site_count} site(s)")
    lines.append("Overview : " + ", ".join(overview_parts))
    lines.append("")

    # Event category distribution — sorted by ratio descending
    categories = stats.get("categories", {})
    if categories:
        lines.append("Event Category Distribution:")
        sorted_cats = sorted(categories.items(), key=lambda x: x[1].get("ratio", 0), reverse=True)
        for cat_key, cat_data in sorted_cats:
            count = cat_data.get("count", 0)
            ratio = cat_data.get("ratio", 0.0)
            if count == 0:
                continue
            label = _CATEGORY_LABELS.get(cat_key, cat_key)
            flag = "  ← failure category" if cat_key in _FAILURE_CATEGORIES else ""
            lines.append(f"  {label:<20} {ratio * 100:5.1f}%  ({count:,} events){flag}")
        lines.append("")

    # Anomaly detection summary
    outlier_pct = (if_outlier_count / client_count * 100) if client_count > 0 else 0
    lines.append("Anomaly Detection:")
    lines.append(f"  IF outliers      : {if_outlier_count} / {client_count} clients ({outlier_pct:.1f}%)")
    lines.append(f"  Worst severity   : {worst_severity}")
    lines.append(f"  Family-level flag: {'YES — entire family behaves anomalously vs. other families' if is_family_outlier else 'No'}")
    lines.append("")

    # Findings / patterns
    findings = stats.get("findings", [])
    if findings:
        lines.append("Detected Patterns:")
        for i, f in enumerate(findings, 1):
            pattern = f.get("probable_pattern", "unknown")
            sev = f.get("severity", "?")
            mac_count = f.get("mac_count", 0)
            examples = f.get("example_macs", [])
            ex_str = ", ".join(examples[:3]) if examples else "n/a"
            lines.append(f"  {i}. {pattern} [{sev}] — {mac_count} MAC(s) — e.g. {ex_str}")
    else:
        lines.append("Detected Patterns: none")

    return "\n".join(lines)
