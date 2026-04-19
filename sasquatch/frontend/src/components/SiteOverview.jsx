import { useState, useEffect, useCallback } from "react";
import { apiFetch } from "../api";
import { familyColor } from "./familyColors";
import ClusterViz from "./ClusterViz";

const CATEGORIES = [
  "DHCP_SUCCESS", "DHCP_FAILURE", "DNS_SUCCESS", "DNS_FAILURE",
  "AUTH_SUCCESS", "AUTH_FAILURE", "ROAM_SUCCESS", "ROAM_FAILURE",
  "DISASSOC_AP", "DISASSOC_CLIENT", "ARP_SUCCESS", "ARP_FAILURE", "CAPTIVE_PORTAL", "SECURITY", "COLLABORATION", "OTHER",
];

const SEVERITY_COLOR = { significant: "#e05555", moderate: "#e0a835", minimal: "#4ea8c4" };
const SEVERITY_RANK  = { significant: 3, moderate: 2, minimal: 1 };
const SA_COLOR = "#d4a06a";
const SA_BG    = "#2a1f15";

function SortIndicator({ active, dir }) {
  if (!active) return <span style={{ color: "#333", marginLeft: "3px", fontSize: "9px" }}>⇅</span>;
  return <span style={{ color: "#7ec8e3", marginLeft: "3px", fontSize: "9px" }}>{dir === "asc" ? "▲" : "▼"}</span>;
}

function ratioColor(ratio) {
  // green (#2d7a4f) → yellow (#c8a820) → red (#c83232)
  if (ratio <= 0) return "#1a2d1a";
  if (ratio < 0.3) {
    const t = ratio / 0.3;
    return `rgb(${Math.round(45 + t * 155)}, ${Math.round(122 - t * 50)}, ${Math.round(79 - t * 79)})`;
  }
  const t = Math.min((ratio - 0.3) / 0.7, 1);
  return `rgb(${Math.round(200)}, ${Math.round(168 - t * 118)}, ${Math.round(32 - t * 32)})`;
}

function successColor(ratio) {
  // near-black → bright green, saturating around 40% ratio
  if (ratio <= 0) return "#111";
  const t = Math.min(ratio / 0.4, 1);
  return `rgb(${Math.round(18 + t * 12)}, ${Math.round(44 + t * 116)}, ${Math.round(18 + t * 12)})`;
}

// Health score: 1.0 = fully healthy (green), 0.75 = threshold (yellow), 0.0 = all failing (red)
function healthScoreColor(score) {
  if (score == null) return "#444";
  if (score >= 0.85) return "#2d7a4f";
  if (score >= 0.75) return "#e0a835";
  if (score >= 0.55) return "#c87832";
  return "#e05555";
}

function healthBarColor(score) {
  if (score == null) return "#333";
  if (score >= 0.85) return "#2d9e5f";
  if (score >= 0.75) return "#e0a835";
  if (score >= 0.55) return "#c87832";
  return "#e05555";
}

// Family-level service alarm cards. The list comes from the per-family health
// record (/sites/{site_id}/health) — already filtered to services where >50%
// of active MACs are individually unhealthy.
function ServiceAlarmCards({ alarms, serviceHealth }) {
  if (!alarms || alarms.length === 0) {
    return <span style={{ color: "#333", fontSize: "10px" }}>—</span>;
  }
  return (
    <span style={{ display: "flex", flexWrap: "wrap", gap: "3px" }}>
      {alarms.map((svc) => {
        const sh = serviceHealth?.[svc];
        const pct = sh != null ? `${Math.round(sh * 100)}%` : "";
        return (
          <span
            key={svc}
            title={pct ? `${svc.toUpperCase()} avg health ${pct}` : svc.toUpperCase()}
            style={{
              background: "#e0555522",
              color: "#e05555",
              border: "1px solid #e0555544",
              borderRadius: "3px",
              padding: "1px 5px",
              fontSize: "10px",
              textTransform: "uppercase",
              letterSpacing: "0.04em",
              fontWeight: 600,
            }}
          >
            {svc}
          </span>
        );
      })}
    </span>
  );
}

export default function SiteOverview({ siteId, apiBase, onMacSelect, onFamilySelect, refreshToken, wlan, onLoaded }) {
  const [summary, setSummary] = useState(null);
  const [findings, setFindings] = useState([]);
  const [health, setHealth] = useState({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [lastRefresh, setLastRefresh] = useState(null);
  const [sortKey, setSortKey] = useState("anomaly");
  const [sortDir, setSortDir] = useState("desc");
  const [pcaFamilies, setPcaFamilies] = useState(null);
  const [pcaSeeded, setPcaSeeded] = useState(false);

  useEffect(() => {
    setSummary(null);
    setFindings([]);
    setHealth({});
    setError(null);
    setPcaSeeded(false);
    setPcaFamilies(null);
  }, [siteId, wlan]);

  // Seed default PCA selection once per load: families flagged by IF/DB/Markov plus
  // the top 3 largest by device count at this site.
  useEffect(() => {
    if (pcaSeeded || !summary?.families) return;
    const HIDDEN = new Set(["Unknown", "IoT (Unknown)"]);
    const counts = summary.family_client_counts || {};
    const candidates = Object.keys(summary.families).filter(f => !HIDDEN.has(f));
    const findingByFam = {};
    for (const f of findings) findingByFam[f.device_family] = f;
    const flagged = candidates.filter(f => {
      const fn = findingByFam[f];
      const markovOutlier = summary.family_markov?.[f]?.is_family_markov_outlier
        ?? fn?.is_family_markov_outlier ?? false;
      return !!fn?.is_family_outlier || !!fn?.dbscan_severity || markovOutlier;
    });
    const topByCount = [...candidates]
      .sort((a, b) => (counts[b] ?? 0) - (counts[a] ?? 0))
      .slice(0, 3);
    setPcaFamilies(new Set([...flagged, ...topByCount]));
    setPcaSeeded(true);
  }, [summary, findings, pcaSeeded]);

  const togglePca = (family) => {
    setPcaFamilies(prev => {
      const next = new Set(prev ?? []);
      if (next.has(family)) next.delete(family); else next.add(family);
      return next;
    });
  };

  const load = useCallback(() => {
    setLoading(true);
    const q = `?wlan=${encodeURIComponent(wlan)}`;
    Promise.all([
      apiFetch(`${apiBase}/api/v1/sites/${siteId}/events/summary${q}`).then((r) => r.json()),
      apiFetch(`${apiBase}/api/v1/sites/${siteId}/findings${q}`).then((r) => r.json()),
      apiFetch(`${apiBase}/api/v1/sites/${siteId}/health${q}`).then((r) => r.json()).catch(() => ({ health: {} })),
    ])
      .then(([s, f, h]) => {
        setSummary({ ...s, family_client_counts: s.family_client_counts || {} });
        setFindings(f.findings || []);
        setHealth(h.health || {});
        setLastRefresh(new Date().toLocaleTimeString());
        setError(null);
      })
      .catch((e) => setError(e.message))
      .finally(() => { setLoading(false); onLoaded?.(); });
  }, [siteId, apiBase, refreshToken, wlan]);

  useEffect(() => {
    load();
    const interval = setInterval(load, 60_000);
    return () => clearInterval(interval);
  }, [load]);

  if (loading && !summary) {
    // Skeleton: 8 fixed cols (Family, PCA, Count, IF, DB, Markov, Health, Service Alarm) + 15 CATEGORIES = 23 columns
    const skeletonColWidths = [110, 30, 44, 44, 62, 62, 80, 100, ...Array(15).fill(18)];
    const shimmer = "sq-site-shimmer 1.5s ease-in-out infinite";
    return (
      <div>
        <style>{`@keyframes sq-site-shimmer { 0%,100% { opacity: 0.3; } 50% { opacity: 0.55; } }`}</style>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
          <div style={{ width: "200px", height: "13px", background: "#2a2a2a", borderRadius: "3px", animation: shimmer }} />
          <div style={{ width: "160px", height: "11px", background: "#1e1e1e", borderRadius: "3px", animation: shimmer }} />
        </div>
        <div style={{ overflowX: "auto" }}>
          <table style={{ borderCollapse: "collapse", fontSize: "12px" }}>
            <thead>
              <tr>
                {skeletonColWidths.map((w, i) => (
                  <th key={i} style={{ padding: i >= 3 ? "4px 2px" : "6px 8px", borderBottom: "1px solid #222", textAlign: "left" }}>
                    <div style={{ width: `${w}px`, height: i >= 3 ? "40px" : "10px", background: "#222", borderRadius: "2px", animation: shimmer }} />
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {[100, 85, 72, 90, 65, 78].map((nameW, ri) => (
                <tr key={ri}>
                  {skeletonColWidths.map((w, ci) => (
                    <td key={ci} style={{ padding: ci >= 3 ? "4px 2px" : "6px 8px", borderBottom: "1px solid #1a1a1a" }}>
                      <div style={{
                        width: ci === 0 ? `${nameW}px` : ci >= 3 ? "14px" : `${Math.round(w * 0.65)}px`,
                        height: "10px",
                        background: "#1a1a1a",
                        borderRadius: ci >= 3 ? "2px" : "2px",
                        animation: shimmer,
                      }} />
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    );
  }
  if (error) return <div style={{ color: "#e05555" }}>Error: {error}</div>;
  if (!summary) return null;

  const HIDDEN_FAMILIES = new Set(["Unknown", "IoT (Unknown)"]);
  const MIN_DISPLAY_CLIENTS = 1;
  const allFamilies = Object.keys(summary.families || {}).filter((f) => !HIDDEN_FAMILIES.has(f));
  const families = allFamilies
    .filter((f) => (summary.family_client_counts?.[f] ?? 0) >= MIN_DISPLAY_CLIENTS);
  const otherFamilies = allFamilies.filter((f) => (summary.family_client_counts?.[f] ?? 0) < MIN_DISPLAY_CLIENTS);

  // Aggregate "All Other Devices" row — sum event counts across all small families
  const otherCounts = {};
  let otherClientCount = 0;
  for (const f of otherFamilies) {
    otherClientCount += summary.family_client_counts?.[f] ?? 0;
    const familyData = summary.families[f] || {};
    for (const cat of CATEGORIES) {
      otherCounts[cat] = (otherCounts[cat] ?? 0) + (familyData[cat]?.count ?? 0);
    }
  }
  const otherTotal = Object.values(otherCounts).reduce((s, n) => s + n, 0);
  const showOtherRow = otherFamilies.length > 0;

  // Build findings map: family → finding
  const findingsByFamily = {};
  for (const f of findings) {
    findingsByFamily[f.device_family] = f;
  }

  const handleSort = (key) => {
    setSortKey(prev => {
      if (prev === key) { setSortDir(d => d === "asc" ? "desc" : "asc"); return key; }
      setSortDir(key === "family" ? "asc" : "desc");
      return key;
    });
  };

  // Anomaly sort rank combines IF + DBSCAN + Markov for the default sort
  const anomalyRank = (f) => {
    const finding = findingsByFamily[f];
    if (finding?.is_family_outlier) return 10;
    const dbRank = SEVERITY_RANK[finding?.dbscan_severity] ?? 0;
    const markovOutlier = summary.family_markov?.[f]?.is_family_markov_outlier
      ?? finding?.is_family_markov_outlier ?? false;
    const mRank = markovOutlier ? 1 : 0;
    return dbRank * 2 + mRank;
  };

  const sortedFamilies = [...families].sort((a, b) => {
    let va, vb;
    if (sortKey === "family") {
      va = a.toLowerCase(); vb = b.toLowerCase();
    } else if (sortKey === "anomaly") {
      va = anomalyRank(a); vb = anomalyRank(b);
    } else if (sortKey === "dbscan") {
      va = SEVERITY_RANK[findingsByFamily[a]?.dbscan_severity] ?? 0;
      vb = SEVERITY_RANK[findingsByFamily[b]?.dbscan_severity] ?? 0;
    } else if (sortKey === "markov") {
      va = summary.family_markov?.[a]?.markov_family_anomaly_ratio
        ?? findingsByFamily[a]?.markov_family_anomaly_ratio ?? 0;
      vb = summary.family_markov?.[b]?.markov_family_anomaly_ratio
        ?? findingsByFamily[b]?.markov_family_anomaly_ratio ?? 0;
    } else if (sortKey === "health") {
      va = health[a]?.health_score ?? -1;
      vb = health[b]?.health_score ?? -1;
    } else if (sortKey === "service_alarm") {
      va = (health[a]?.service_alarms ?? []).length;
      vb = (health[b]?.service_alarms ?? []).length;
    } else if (sortKey === "count") {
      va = summary.family_client_counts?.[a] ?? 0;
      vb = summary.family_client_counts?.[b] ?? 0;
    } else {
      // category column — sort by ratio (matches cell color coding)
      va = summary.families[a]?.[sortKey]?.ratio ?? 0;
      vb = summary.families[b]?.[sortKey]?.ratio ?? 0;
    }
    if (va < vb) return sortDir === "asc" ? -1 : 1;
    if (va > vb) return sortDir === "asc" ? 1 : -1;
    // Tiebreak for service_alarm: worse health first (ascending health score)
    if (sortKey === "service_alarm") {
      const ha = health[a]?.health_score ?? 1;
      const hb = health[b]?.health_score ?? 1;
      if (ha !== hb) return ha - hb;
    }
    // tiebreak: client count desc
    return (summary.family_client_counts?.[b] ?? 0) - (summary.family_client_counts?.[a] ?? 0);
  });

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
        <div style={{ display: "flex", alignItems: "baseline", gap: "12px" }}>
          <h2 style={{ margin: 0, fontSize: "15px", color: "#aaa" }}>
            Site WLAN Family Insights — {summary.total_events?.toLocaleString()} events
          </h2>
          <span
            onClick={() => setPcaFamilies(new Set())}
            style={{
              color: "#666", fontSize: "11px", cursor: "pointer",
              textDecoration: "underline", textDecorationColor: "#333",
              userSelect: "none",
            }}
            title="Uncheck all families from the PCA visualization"
          >
            uncheck all PCA
          </span>
        </div>
        <span style={{ fontSize: "12px", color: "#999" }}>
          Refreshed {lastRefresh} · auto-refresh 60s
        </span>
      </div>

      <div style={{ display: "flex", gap: "28px", alignItems: "flex-start" }}>
        <div style={{ overflowX: "auto", flex: "1 1 auto", minWidth: 0 }}>
        <table style={{ borderCollapse: "collapse", fontSize: "12px" }}>
          <thead>
            <tr>
              <th
                style={{ ...thStyle, cursor: "pointer", userSelect: "none" }}
                onClick={() => handleSort("family")}
              >
                Device Family<SortIndicator active={sortKey === "family"} dir={sortDir} />
              </th>
              <th
                style={{ ...thStyle, whiteSpace: "nowrap", textAlign: "center" }}
                title="PCA — include this family in the PCA cluster view on the right."
              >
                PCA
              </th>
              <th
                style={{ ...thStyle, whiteSpace: "nowrap", cursor: "pointer", userSelect: "none" }}
                title="Count — total MACs in this device family at this site."
                onClick={() => handleSort("count")}
              >
                Count<SortIndicator active={sortKey === "count"} dir={sortDir} />
              </th>
              <th
                style={{ ...thStyle, whiteSpace: "nowrap", cursor: "pointer", userSelect: "none" }}
                title="Cosine distance from the healthy-family median centroid — flags the whole family as behaving differently from all other families at this site."
                onClick={() => handleSort("anomaly")}
              >
                Cosine<SortIndicator active={sortKey === "anomaly"} dir={sortDir} />
              </th>
              <th
                style={{ ...thStyle, whiteSpace: "nowrap", cursor: "pointer", userSelect: "none" }}
                title="DBSCAN — fraction of individual MACs in this family flagged as site-wide behavioral outliers."
                onClick={() => handleSort("dbscan")}
              >
                DB<SortIndicator active={sortKey === "dbscan"} dir={sortDir} />
              </th>
              <th
                style={{ ...thStyle, whiteSpace: "nowrap", cursor: "pointer", userSelect: "none" }}
                title="Markov Chain episode analysis — flags families where clients show anomalous event chain patterns or repeated connection failures."
                onClick={() => handleSort("markov")}
              >
                Markov<SortIndicator active={sortKey === "markov"} dir={sortDir} />
              </th>
              <th
                style={{ ...thStyle, whiteSpace: "nowrap", minWidth: "90px", cursor: "pointer", userSelect: "none" }}
                title="Family health score — weighted failure rate across AUTH, ROAM, DHCP, DNS, ARP. 1.0 = no failures."
                onClick={() => handleSort("health")}
              >
                Health<SortIndicator active={sortKey === "health"} dir={sortDir} />
              </th>
              <th
                style={{ ...thStyle, whiteSpace: "nowrap", minWidth: "100px", cursor: "pointer", userSelect: "none" }}
                title="Service Alarm — services where >50% of active MACs in this family are individually below 50% health. Sort by alarm count (ties broken by worst health)."
                onClick={() => handleSort("service_alarm")}
              >
                Service Alarm<SortIndicator active={sortKey === "service_alarm"} dir={sortDir} />
              </th>
              {CATEGORIES.map((c) => (
                <th
                  key={c}
                  style={{
                    ...thStyle,
                    writingMode: "vertical-rl",
                    transform: "rotate(180deg)",
                    padding: "4px 2px",
                    fontSize: "10px",
                    cursor: "pointer",
                    userSelect: "none",
                    color: sortKey === c ? "#7ec8e3" : undefined,
                  }}
                  onClick={() => handleSort(c)}
                >
                  {c}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {sortedFamilies.map((family) => {
              const familyData = summary.families[family] || {};
              const clientCount = summary.family_client_counts?.[family] ?? 0;
              const finding = findingsByFamily[family];
              // is_family_outlier = Stage 3 family centroid IF — whole family collectively
              // behaves differently from other families at this site.
              // dbscan_severity = fraction of individual MACs in this family that are DBSCAN outliers.
              const isFamilyOutlier = finding?.is_family_outlier ?? false;
              const severity = finding?.dbscan_severity ?? null;
              const hasIfOutliers = (finding?.if_outlier_count ?? 0) > 0;
              // Markov data: prefer the per-family aggregation from events/summary so all
              // families are covered, not just those with a finding.
              const familyMarkov = summary.family_markov?.[family] ?? {};
              const isFamilyMarkovOutlier = familyMarkov.is_family_markov_outlier ?? finding?.is_family_markov_outlier ?? false;
              const markovRatio = familyMarkov.markov_family_anomaly_ratio ?? finding?.markov_family_anomaly_ratio ?? null;
              const markovAnomalousCount = familyMarkov.markov_family_anomalous_count ?? finding?.markov_family_anomalous_count ?? 0;
              const markovEvaluatableCount = familyMarkov.markov_evaluatable_count ?? finding?.markov_evaluatable_count ?? 0;
              const markovFamilyReason = familyMarkov.markov_family_reason ?? finding?.markov_family_reason ?? null;
              const color = familyColor(family);
              const familyHealth = health[family];
              const healthScore = familyHealth?.health_score ?? null;
              const healthComponents = familyHealth?.components ?? {};
              const healthTip = healthScore != null
                ? `Health: ${(healthScore * 100).toFixed(0)}%\n` +
                  Object.entries(healthComponents)
                    .map(([k, v]) => `  ${k}: ${(v * 100).toFixed(1)}% failure`)
                    .join("\n")
                : "Health score not yet computed";
              const familyMeta = summary.family_metadata?.[family] || {};
              const isSaFamily = familyMeta.family_kind === "service_account";
              const displayName = isSaFamily ? familyMeta.service_account_label : family;
              const saMembers = familyMeta.service_account_member_families || [];
              const rowBg = isSaFamily ? SA_BG : undefined;
              return (
                <tr key={family} style={rowBg ? { background: rowBg } : undefined}>
                  <td style={{ ...tdStyle, whiteSpace: "nowrap" }}>
                    <span style={{
                      display: "inline-block", width: 8, height: 8,
                      borderRadius: "50%", background: isSaFamily ? SA_COLOR : color,
                      marginRight: "6px", verticalAlign: "middle", flexShrink: 0,
                    }} />
                    <span
                      onClick={() => onFamilySelect(family)}
                      style={{
                        color: isSaFamily ? SA_COLOR : (hasIfOutliers ? "#7ec8e3" : "#ccc"),
                        cursor: "pointer",
                        textDecoration: hasIfOutliers || isSaFamily ? "underline" : "none",
                        textUnderlineOffset: "2px",
                      }}
                      title={isSaFamily
                        ? `Service account spanning: ${saMembers.join(", ") || "(unknown)"}`
                        : (hasIfOutliers ? `View ${finding.if_outlier_count} Isolation Forest deviation(s) in ${family}` : family)}
                    >
                      {displayName}
                    </span>
                    {isSaFamily && (
                      <span
                        style={{ background: "transparent", color: SA_COLOR, border: `1px solid ${SA_COLOR}55`, borderRadius: "3px", padding: "0 4px", fontSize: "9px", fontWeight: "bold", letterSpacing: "0.05em", marginLeft: "6px", verticalAlign: "middle" }}
                        title={saMembers.length ? `Spans ${saMembers.length} device families: ${saMembers.join(", ")}` : "Service account"}
                      >
                        SVC ACCT
                      </span>
                    )}
                  </td>
                  {/* PCA: include this family in the cluster viz */}
                  <td
                    style={{ ...tdStyle, textAlign: "center", cursor: "pointer" }}
                    onClick={() => togglePca(family)}
                    title={`Include ${family} in PCA visualization`}
                  >
                    <input
                      type="checkbox"
                      readOnly
                      checked={pcaFamilies?.has(family) ?? false}
                      style={{ cursor: "pointer", accentColor: "#2a5a7a", pointerEvents: "none" }}
                    />
                  </td>
                  {/* Count — MACs in this family at this site */}
                  <td
                    style={{ ...tdStyle, textAlign: "right", color: "#aaa", fontSize: "11px", fontVariantNumeric: "tabular-nums" }}
                    title={`${clientCount} MAC${clientCount === 1 ? "" : "s"} in ${family} at this site`}
                  >
                    {clientCount}
                  </td>
                  {/* IF: Centroid Isolation Forest — whole-family behavioral outlier */}
                  <td style={{ ...tdStyle, textAlign: "center" }}>
                    {isFamilyOutlier ? (
                      <span style={{
                        background: "#2a1a3a",
                        color: "#b06ad4",
                        border: "1px solid #6a3a8a",
                        borderRadius: "3px",
                        padding: "1px 6px",
                        fontSize: "10px",
                        fontWeight: "bold",
                      }}>
                        family
                      </span>
                    ) : (
                      <span style={{ color: "#2d7a4f", fontSize: "10px" }}>OK</span>
                    )}
                  </td>
                  {/* DB: DBSCAN — fraction of individual MACs flagged site-wide */}
                  <td style={{ ...tdStyle, textAlign: "center" }}>
                    {severity ? (
                      <span style={{
                        background: SEVERITY_COLOR[severity] + "33",
                        color: SEVERITY_COLOR[severity],
                        padding: "1px 6px",
                        borderRadius: "3px",
                        fontSize: "10px",
                        fontWeight: "bold",
                        border: `1px solid ${SEVERITY_COLOR[severity]}55`,
                      }}>
                        {severity}
                      </span>
                    ) : (
                      <span style={{ color: "#2d7a4f", fontSize: "10px" }}>OK</span>
                    )}
                  </td>

                  {/* Markov Chain episode analysis */}
                  <td
                    style={{ ...tdStyle, textAlign: "center" }}
                    title={
                      isFamilyMarkovOutlier
                        ? `Markov ${markovFamilyReason || "anomaly"}: ${markovAnomalousCount}/${markovEvaluatableCount} clients flagged${markovRatio != null ? ` (${(markovRatio * 100).toFixed(0)}%)` : ""}`
                        : markovEvaluatableCount > 0
                          ? `Markov: ${markovAnomalousCount}/${markovEvaluatableCount} clients evaluated — no family-level anomaly`
                          : "Markov baseline not yet available or no scoreable episodes"
                    }
                  >
                    {isFamilyMarkovOutlier ? (
                      <span style={{
                        background: "#1a2a3a",
                        color: "#4ab0e8",
                        border: "1px solid #2a6a8a",
                        borderRadius: "3px",
                        padding: "1px 6px",
                        fontSize: "10px",
                        fontWeight: "bold",
                        whiteSpace: "nowrap",
                      }}>
                        {markovFamilyReason || "chain"}
                      </span>
                    ) : markovEvaluatableCount > 0 ? (
                      <span style={{ color: "#2d7a4f", fontSize: "10px" }}>OK</span>
                    ) : (
                      <span style={{ color: "#333", fontSize: "10px" }}>—</span>
                    )}
                  </td>

                  {/* Health score */}
                  <td style={{ ...tdStyle, minWidth: "90px" }} title={healthTip}>
                    {healthScore != null ? (
                      <div style={{ display: "flex", alignItems: "center", gap: "5px" }}>
                        <div style={{ flex: 1, height: "5px", background: "#1a1a1a", borderRadius: "3px", overflow: "hidden" }}>
                          <div style={{ width: `${(healthScore * 100).toFixed(0)}%`, height: "100%", background: healthBarColor(healthScore), borderRadius: "3px" }} />
                        </div>
                        <span style={{ fontSize: "11px", fontWeight: "bold", color: healthScoreColor(healthScore), minWidth: "28px", textAlign: "right" }}>
                          {(healthScore * 100).toFixed(0)}%
                        </span>
                      </div>
                    ) : (
                      <span style={{ color: "#333", fontSize: "10px" }}>—</span>
                    )}
                  </td>

                  {/* Service Alarm — family-level cards from the health record */}
                  <td style={{ ...tdStyle, minWidth: "100px" }}>
                    <ServiceAlarmCards
                      alarms={familyHealth?.service_alarms || []}
                      serviceHealth={familyHealth?.service_health || {}}
                    />
                  </td>

                  {CATEGORIES.map((cat) => {
                    const cell = familyData[cat];
                    const ratio = cell?.ratio ?? 0;
                    const count = cell?.count ?? 0;
                    const isFailure = cat.includes("FAILURE") || cat === "SECURITY";
                    const isSuccess = cat.includes("SUCCESS");
                    const bg = isFailure ? ratioColor(ratio)
                      : isSuccess ? successColor(ratio)
                      : ratio > 0 ? "#1a2d1a" : "#111";
                    const textColor = isFailure && ratio > 0.1 ? "#fff"
                      : isSuccess && ratio > 0.15 ? "#fff"
                      : "#bbb";
                    return (
                      <td
                        key={cat}
                        title={`${family} / ${cat}: ${count} events (${(ratio * 100).toFixed(1)}%)`}
                        style={{
                          ...tdStyle,
                          background: bg,
                          textAlign: "center",
                          cursor: count > 0 ? "pointer" : "default",
                          minWidth: "28px",
                        }}
                        onClick={() => count > 0 && finding?.example_macs?.[0] && onMacSelect(finding.example_macs[0])}
                      >
                        {count > 0 && (
                          <span style={{ fontSize: "10px", color: textColor }}>
                            {count > 999 ? `${(count / 1000).toFixed(1)}k` : count}
                          </span>
                        )}
                      </td>
                    );
                  })}
                </tr>
              );
            })}
            {showOtherRow && (
              <tr style={{ borderTop: "1px solid #2a2a2a" }}>
                <td style={{ ...tdStyle, whiteSpace: "nowrap", color: "#aaa", fontStyle: "italic" }}>
                  <span style={{
                    display: "inline-block", width: 8, height: 8,
                    borderRadius: "50%", background: "#666",
                    marginRight: "6px", verticalAlign: "middle",
                  }} />
                  All Other Devices
                  <span style={{ color: "#888", fontSize: "11px", marginLeft: "6px" }}>
                    ({otherClientCount} clients, {otherFamilies.length} types)
                  </span>
                </td>
                <td style={{ ...tdStyle, textAlign: "center" }}>
                  <span style={{ color: "#888", fontSize: "10px" }}>—</span>
                </td>
                <td style={{ ...tdStyle, textAlign: "right", color: "#888", fontSize: "11px", fontVariantNumeric: "tabular-nums" }}>
                  {otherClientCount}
                </td>
                <td style={{ ...tdStyle, textAlign: "center" }}>
                  <span style={{ color: "#888", fontSize: "10px" }}>—</span>
                </td>
                <td style={{ ...tdStyle, textAlign: "center" }}>
                  <span style={{ color: "#888", fontSize: "10px" }}>—</span>
                </td>
                <td style={{ ...tdStyle, textAlign: "center" }}>
                  <span style={{ color: "#888", fontSize: "10px" }}>—</span>
                </td>
                <td style={tdStyle} />
                <td style={tdStyle} />
                {CATEGORIES.map((cat) => {
                  const count = otherCounts[cat] ?? 0;
                  const ratio = otherTotal > 0 ? count / otherTotal : 0;
                  const isFailure = cat.includes("FAILURE") || cat === "SECURITY";
                  const isSuccess = cat.includes("SUCCESS");
                  const bg = isFailure ? ratioColor(ratio)
                    : isSuccess ? successColor(ratio)
                    : count > 0 ? "#1a2d1a" : "#111";
                  const textColor = isFailure && ratio > 0.1 ? "#fff"
                    : isSuccess && ratio > 0.15 ? "#fff"
                    : "#555";
                  return (
                    <td
                      key={cat}
                      title={`All Other Devices / ${cat}: ${count} events`}
                      style={{
                        ...tdStyle,
                        background: bg,
                        textAlign: "center",
                        minWidth: "28px",
                      }}
                    >
                      {count > 0 && (
                        <span style={{ fontSize: "10px", color: textColor }}>
                          {count > 999 ? `${(count / 1000).toFixed(1)}k` : count}
                        </span>
                      )}
                    </td>
                  );
                })}
              </tr>
            )}
          </tbody>
        </table>
        </div>

        <div style={{ flex: "0 0 380px", width: "380px" }}>
          <ClusterViz siteId={siteId} apiBase={apiBase} onMacSelect={onMacSelect} refreshToken={refreshToken} wlan={wlan} selectedFamilies={pcaFamilies} />
        </div>
      </div>

      <div style={{ marginTop: "8px", fontSize: "11px", color: "#444" }}>
        <span style={{ color: "#b06ad4" }}>Cosine: family</span> = whole device class behaves differently from other families at this site (cosine distance from the healthy-family median centroid).
        {" "}<span style={{ fontWeight: "bold", color: "#666" }}>DB:</span> <span style={{ color: "#e0a835" }}>moderate</span> / <span style={{ color: "#e05555" }}>significant</span> = fraction of individual MACs in that family flagged by DBSCAN.
        {" "}Health = weighted failure rate across AUTH · ROAM · DHCP · DNS · ARP (hover for breakdown).
        {" "}Click a family name to see per-device Isolation Forest deviations.
      </div>
    </div>
  );
}

const thStyle = {
  padding: "6px 8px",
  borderBottom: "1px solid #333",
  color: "#ccc",
  textAlign: "left",
  fontWeight: "normal",
  background: "#161616",
};

const tdStyle = {
  padding: "5px 8px",
  borderBottom: "1px solid #1e1e1e",
};
