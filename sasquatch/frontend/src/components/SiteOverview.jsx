import { useState, useEffect, useCallback } from "react";

const CATEGORIES = [
  "DHCP_SUCCESS", "DHCP_FAILURE", "DNS_SUCCESS", "DNS_FAILURE",
  "AUTH_SUCCESS", "AUTH_FAILURE", "ROAM_SUCCESS", "ROAM_FAILURE",
  "DISASSOC", "ARP", "CAPTIVE_PORTAL", "SECURITY", "COLLABORATION", "OTHER",
];

const SEVERITY_COLOR = { CRITICAL: "#e05555", WARNING: "#e0a835", INFO: "#4ea8c4" };

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

export default function SiteOverview({ siteId, apiBase, onMacSelect, onFamilySelect }) {
  const [summary, setSummary] = useState(null);
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [lastRefresh, setLastRefresh] = useState(null);

  const load = useCallback(() => {
    setLoading(true);
    Promise.all([
      fetch(`${apiBase}/api/v1/sites/${siteId}/events/summary`).then((r) => r.json()),
      fetch(`${apiBase}/api/v1/sites/${siteId}/findings`).then((r) => r.json()),
    ])
      .then(([s, f]) => {
        setSummary(s);
        setFindings(f.findings || []);
        setLastRefresh(new Date().toLocaleTimeString());
        setError(null);
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [siteId, apiBase]);

  useEffect(() => {
    load();
    const interval = setInterval(load, 60_000);
    return () => clearInterval(interval);
  }, [load]);

  if (loading && !summary) return <div style={{ color: "#888" }}>Loading site overview…</div>;
  if (error) return <div style={{ color: "#e05555" }}>Error: {error}</div>;
  if (!summary) return null;

  const families = Object.keys(summary.families || {}).sort();

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

      <div style={{ overflowX: "auto" }}>
        <table style={{ borderCollapse: "collapse", fontSize: "12px", width: "100%" }}>
          <thead>
            <tr>
              <th style={thStyle}>Device Family</th>
              <th style={thStyle}>Severity</th>
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
              const finding = findingsByFamily[family];
              // Site Overview shows DBSCAN-only severity — IF deviations are in the family drilldown
              const severity = finding?.dbscan_severity ?? null;
              const hasIfOutliers = (finding?.if_outlier_count ?? 0) > 0;
              return (
                <tr key={family}>
                  <td style={{ ...tdStyle, whiteSpace: "nowrap" }}>
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
                  </td>
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
                  {CATEGORIES.map((cat) => {
                    const cell = familyData[cat];
                    const ratio = cell?.ratio ?? 0;
                    const count = cell?.count ?? 0;
                    const isFailure = cat.includes("FAILURE") || cat === "SECURITY";
                    const displayRatio = isFailure ? ratio : 0;
                    return (
                      <td
                        key={cat}
                        title={`${family} / ${cat}: ${count} events (${(ratio * 100).toFixed(1)}%)`}
                        style={{
                          ...tdStyle,
                          background: isFailure ? ratioColor(displayRatio) : (ratio > 0 ? "#1a2d1a" : "#111"),
                          textAlign: "center",
                          cursor: count > 0 ? "pointer" : "default",
                          minWidth: "28px",
                        }}
                        onClick={() => count > 0 && finding?.example_macs?.[0] && onMacSelect(finding.example_macs[0])}
                      >
                        {count > 0 && (
                          <span style={{ fontSize: "10px", color: isFailure && ratio > 0.1 ? "#fff" : "#555" }}>
                            {count > 999 ? `${(count / 1000).toFixed(1)}k` : count}
                          </span>
                        )}
                      </td>
                    );
                  })}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <div style={{ marginTop: "8px", fontSize: "11px", color: "#444" }}>
        Severity badge reflects DBSCAN site-wide anomalies only. Click a device family name to see Isolation Forest deviations within that family.
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
