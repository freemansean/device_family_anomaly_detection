import { useState, useEffect, useCallback } from "react";
import { apiFetch } from "../api";
import { familyColor } from "./familyColors";
import ClusterViz from "./ClusterViz";

const CATEGORIES = [
  "DHCP_SUCCESS", "DHCP_FAILURE", "DNS_SUCCESS", "DNS_FAILURE",
  "AUTH_SUCCESS", "AUTH_FAILURE", "ROAM_SUCCESS", "ROAM_FAILURE",
  "DISASSOC", "ARP_SUCCESS", "ARP_FAILURE", "CAPTIVE_PORTAL", "SECURITY", "COLLABORATION", "OTHER",
];

const SEVERITY_COLOR = { significant: "#e05555", moderate: "#e0a835", minimal: "#4ea8c4" };

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

export default function SiteOverview({ siteId, apiBase, onMacSelect, onFamilySelect, refreshToken }) {
  const [summary, setSummary] = useState(null);
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [lastRefresh, setLastRefresh] = useState(null);

  useEffect(() => {
    setSummary(null);
    setFindings([]);
    setError(null);
  }, [siteId]);

  const load = useCallback(() => {
    setLoading(true);
    Promise.all([
      apiFetch(`${apiBase}/api/v1/sites/${siteId}/events/summary`).then((r) => r.json()),
      apiFetch(`${apiBase}/api/v1/sites/${siteId}/findings`).then((r) => r.json()),
    ])
      .then(([s, f]) => {
        setSummary({ ...s, family_client_counts: s.family_client_counts || {} });
        setFindings(f.findings || []);
        setLastRefresh(new Date().toLocaleTimeString());
        setError(null);
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [siteId, apiBase, refreshToken]);

  useEffect(() => {
    load();
    const interval = setInterval(load, 60_000);
    return () => clearInterval(interval);
  }, [load]);

  if (loading && !summary) return <div style={{ color: "#888" }}>Loading site overview…</div>;
  if (error) return <div style={{ color: "#e05555" }}>Error: {error}</div>;
  if (!summary) return null;

  const HIDDEN_FAMILIES = new Set(["Unknown", "IoT (Unknown)"]);
  const MIN_DISPLAY_CLIENTS = 5;
  const allFamilies = Object.keys(summary.families || {}).filter((f) => !HIDDEN_FAMILIES.has(f));
  const families = allFamilies
    .filter((f) => (summary.family_client_counts?.[f] ?? 0) >= MIN_DISPLAY_CLIENTS)
    .sort();
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

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
        <h2 style={{ margin: 0, fontSize: "15px", color: "#aaa" }}>
          Site Overview — {summary.total_events?.toLocaleString()} events
        </h2>
        <span style={{ fontSize: "12px", color: "#555" }}>
          Refreshed {lastRefresh} · auto-refresh 60s
        </span>
      </div>

      <div style={{ display: "flex", gap: "28px", alignItems: "flex-start" }}>
        <div style={{ overflowX: "auto", flex: "1 1 auto", minWidth: 0 }}>
        <table style={{ borderCollapse: "collapse", fontSize: "12px" }}>
          <thead>
            <tr>
              <th style={thStyle}>Device Family</th>
              <th style={thStyle}>Anomaly</th>
              {CATEGORIES.map((c) => (
                <th key={c} style={{ ...thStyle, writingMode: "vertical-rl", transform: "rotate(180deg)", padding: "4px 2px", fontSize: "10px" }}>
                  {c}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {families.map((family) => {
              const familyData = summary.families[family] || {};
              const clientCount = summary.family_client_counts?.[family] ?? 0;
              const finding = findingsByFamily[family];
              // is_family_outlier = Stage 3 family centroid IF — whole family collectively
              // behaves differently from other families at this site.
              // dbscan_severity = fraction of individual MACs in this family that are DBSCAN outliers.
              const isFamilyOutlier = finding?.is_family_outlier ?? false;
              const severity = finding?.dbscan_severity ?? null;
              const hasIfOutliers = (finding?.if_outlier_count ?? 0) > 0;
              const color = familyColor(family);
              return (
                <tr key={family}>
                  <td style={{ ...tdStyle, whiteSpace: "nowrap" }}>
                    <span style={{
                      display: "inline-block", width: 8, height: 8,
                      borderRadius: "50%", background: color,
                      marginRight: "6px", verticalAlign: "middle", flexShrink: 0,
                    }} />
                    <span
                      onClick={() => onFamilySelect(family)}
                      style={{
                        color: hasIfOutliers ? "#7ec8e3" : "#ccc",
                        cursor: "pointer",
                        textDecoration: hasIfOutliers ? "underline" : "none",
                        textUnderlineOffset: "2px",
                      }}
                      title={hasIfOutliers ? `View ${finding.if_outlier_count} Isolation Forest deviation(s) in ${family}` : family}
                    >
                      {family}
                    </span>
                    {clientCount > 0 && (
                      <span style={{ color: "#444", fontSize: "11px", marginLeft: "6px" }}>
                        ({clientCount})
                      </span>
                    )}
                  </td>
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
                    ) : severity ? (
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
                      : "#555";
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
                <td style={{ ...tdStyle, whiteSpace: "nowrap", color: "#555", fontStyle: "italic" }}>
                  <span style={{
                    display: "inline-block", width: 8, height: 8,
                    borderRadius: "50%", background: "#444",
                    marginRight: "6px", verticalAlign: "middle",
                  }} />
                  All Other Devices
                  <span style={{ color: "#333", fontSize: "11px", marginLeft: "6px" }}>
                    ({otherClientCount} clients, {otherFamilies.length} types)
                  </span>
                </td>
                <td style={{ ...tdStyle, textAlign: "center" }}>
                  <span style={{ color: "#333", fontSize: "10px" }}>—</span>
                </td>
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
          <ClusterViz siteId={siteId} apiBase={apiBase} onMacSelect={onMacSelect} refreshToken={refreshToken} />
        </div>
      </div>

      <div style={{ marginTop: "8px", fontSize: "11px", color: "#444" }}>
        <span style={{ color: "#b06ad4" }}>family</span> = whole device class behaves differently from other families at this site (family centroid IF).
        {" "}<span style={{ color: "#e0a835" }}>moderate</span> / <span style={{ color: "#e05555" }}>significant</span> = fraction of individual MACs in that family flagged by DBSCAN.
        {" "}Click a family name to see per-device Isolation Forest deviations.
      </div>
    </div>
  );
}

const thStyle = {
  padding: "6px 8px",
  borderBottom: "1px solid #333",
  color: "#666",
  textAlign: "left",
  fontWeight: "normal",
  background: "#161616",
};

const tdStyle = {
  padding: "5px 8px",
  borderBottom: "1px solid #1e1e1e",
};
