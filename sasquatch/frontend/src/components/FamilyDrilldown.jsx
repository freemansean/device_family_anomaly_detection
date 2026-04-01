import { useState, useEffect } from "react";

const SEVERITY_COLOR = { CRITICAL: "#e05555", WARNING: "#e0a835", INFO: "#4ea8c4" };

function scoreBar(ifScore) {
  // IF decision_function: negative = more anomalous, positive = more normal
  // Normalize roughly to 0–1 for display, where 1 = most anomalous
  if (ifScore === null || ifScore === undefined) return null;
  const clamped = Math.max(-0.5, Math.min(0.5, ifScore));
  const anomalyFraction = (0.5 - clamped) / 1.0; // 0 = normal, 1 = anomalous
  const red = Math.round(80 + anomalyFraction * 145);
  const green = Math.round(180 - anomalyFraction * 155);
  return { fraction: anomalyFraction, color: `rgb(${red}, ${green}, 50)` };
}

export default function FamilyDrilldown({ siteId, family, apiBase, onMacSelect, onBack }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    setLoading(true);
    setError(null);
    fetch(`${apiBase}/api/v1/sites/${siteId}/families/${encodeURIComponent(family)}/if-outliers`)
      .then((r) => {
        if (!r.ok) return r.json().then((e) => Promise.reject(e.detail || r.statusText));
        return r.json();
      })
      .then((d) => { setData(d); setLoading(false); })
      .catch((e) => { setError(String(e)); setLoading(false); });
  }, [siteId, family, apiBase]);

  return (
    <div>
      <div style={{ display: "flex", alignItems: "center", gap: "12px", marginBottom: "16px" }}>
        <button
          onClick={onBack}
          style={{
            background: "#1a1a1a",
            color: "#888",
            border: "1px solid #333",
            padding: "4px 10px",
            borderRadius: "4px",
            cursor: "pointer",
            fontSize: "12px",
          }}
        >
          ← Site Overview
        </button>
        <h2 style={{ margin: 0, fontSize: "15px", color: "#aaa" }}>
          {family} — Isolation Forest Deviations
        </h2>
      </div>

      {loading && <div style={{ color: "#888" }}>Loading…</div>}
      {error && <div style={{ color: "#e05555" }}>Error: {error}</div>}

      {data && (
        <>
          <div style={{ fontSize: "12px", color: "#666", marginBottom: "12px" }}>
            {data.if_outlier_count} of {data.total_family_count} clients in this family
            deviated from their peer group (Isolation Forest). Sorted by anomaly score.
          </div>

          {data.outliers.length === 0 ? (
            <div style={{ color: "#555", fontSize: "13px" }}>
              No Isolation Forest deviations found for this family.
            </div>
          ) : (
            <table style={{ borderCollapse: "collapse", fontSize: "12px", width: "100%" }}>
              <thead>
                <tr>
                  {["MAC", "IF Score", "Events", "Also DBSCAN?", "Model", "OS", "Manufacturer"].map((h) => (
                    <th key={h} style={thStyle}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {data.outliers.map((client) => {
                  const bar = scoreBar(client.if_score);
                  const meta = client.client_metadata || {};
                  return (
                    <tr
                      key={client.mac}
                      onClick={() => onMacSelect(client.mac)}
                      style={{ cursor: "pointer" }}
                      onMouseEnter={(e) => e.currentTarget.style.background = "#1a2530"}
                      onMouseLeave={(e) => e.currentTarget.style.background = "transparent"}
                    >
                      <td style={{ ...tdStyle, color: "#7ec8e3", fontFamily: "monospace" }}>
                        {client.mac}
                        {client.random_mac && (
                          <span style={{ color: "#555", fontSize: "10px", marginLeft: "6px" }}>rnd</span>
                        )}
                      </td>
                      <td style={{ ...tdStyle, minWidth: "120px" }}>
                        {bar ? (
                          <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                            <div style={{
                              width: "60px", height: "8px", background: "#222", borderRadius: "2px", overflow: "hidden",
                            }}>
                              <div style={{
                                width: `${Math.round(bar.fraction * 100)}%`,
                                height: "100%",
                                background: bar.color,
                                borderRadius: "2px",
                              }} />
                            </div>
                            <span style={{ color: "#888", fontSize: "11px" }}>
                              {client.if_score.toFixed(3)}
                            </span>
                          </div>
                        ) : (
                          <span style={{ color: "#555" }}>—</span>
                        )}
                      </td>
                      <td style={{ ...tdStyle, color: "#aaa", textAlign: "right" }}>
                        {client.event_count}
                      </td>
                      <td style={{ ...tdStyle, textAlign: "center" }}>
                        {client.is_dbscan_outlier ? (
                          <span style={{
                            color: SEVERITY_COLOR.CRITICAL,
                            fontSize: "10px",
                            background: SEVERITY_COLOR.CRITICAL + "22",
                            padding: "1px 5px",
                            borderRadius: "3px",
                            border: `1px solid ${SEVERITY_COLOR.CRITICAL}44`,
                          }}>
                            YES
                          </span>
                        ) : (
                          <span style={{ color: "#444", fontSize: "10px" }}>—</span>
                        )}
                      </td>
                      <td style={{ ...tdStyle, color: "#999" }}>{meta.model || "—"}</td>
                      <td style={{ ...tdStyle, color: "#999" }}>{meta.os || "—"}</td>
                      <td style={{ ...tdStyle, color: "#999" }}>{meta.manufacturer || "—"}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}

          <div style={{ marginTop: "8px", fontSize: "11px", color: "#444" }}>
            Click a row to open the MAC drill-down timeline. "Also DBSCAN?" = flagged site-wide as well as within-family.
          </div>
        </>
      )}
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
