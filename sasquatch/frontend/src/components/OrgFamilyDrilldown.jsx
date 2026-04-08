import { useState, useEffect } from "react";
import { apiFetch } from "../api";

const SEVERITY_COLOR = { significant: "#e05555", moderate: "#e0a835", minimal: "#4ea8c4" };

function shapleyScoreFromIfScore(ifScore) {
  if (ifScore == null) return null;
  return Math.max(0, Math.min(100, Math.round((0.5 - ifScore) / 1.0 * 100)));
}

function shapleyColor(score) {
  if (score >= 60) return "#e05555";
  if (score >= 35) return "#e0a835";
  return "#4ea8c4";
}

function ShapleyBlock({ label, score, features, description }) {
  const color = score != null ? shapleyColor(score) : "#666";
  return (
    <div style={{
      background: "#0e0e0e",
      border: `1px solid ${color}33`,
      borderLeft: `3px solid ${color}`,
      borderRadius: "3px",
      padding: "10px 12px",
      marginBottom: "14px",
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: "12px", marginBottom: "6px" }}>
        <span style={{ fontSize: "11px", color: "#666", textTransform: "uppercase", letterSpacing: "0.06em" }}>
          {label}
        </span>
        {score != null && (
          <div style={{ display: "flex", alignItems: "center", gap: "8px", flex: 1 }}>
            <div style={{ flex: 1, height: "6px", background: "#1a1a1a", borderRadius: "3px", overflow: "hidden" }}>
              <div style={{ width: `${score}%`, height: "100%", background: color, borderRadius: "3px" }} />
            </div>
            <span style={{ fontSize: "13px", fontWeight: "bold", color, minWidth: "36px", textAlign: "right" }}>
              {score}<span style={{ fontSize: "10px", color: "#555" }}>/100</span>
            </span>
          </div>
        )}
        {score == null && (
          <span style={{ fontSize: "11px", color: "#444" }}>score unavailable</span>
        )}
      </div>
      {description && (
        <div style={{ fontSize: "11px", color: "#555", marginBottom: features?.length > 0 ? "6px" : 0 }}>
          {description}
        </div>
      )}
      {features?.length > 0 && (
        <div style={{ display: "flex", flexDirection: "column", gap: "3px" }}>
          {features.slice(0, 4).map((f, i) => {
            const delta = Math.abs(f.outlier_mean - f.baseline_mean);
            const barWidth = Math.min(delta * 400, 100);
            return (
              <div key={i} style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <span style={{ fontSize: "10px", color: "#777", width: "220px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flexShrink: 0 }}
                  title={f.feature}>
                  {f.feature}
                </span>
                <div style={{ flex: 1, height: "5px", background: "#1a1a1a", borderRadius: "2px", overflow: "hidden" }}>
                  <div style={{ width: `${barWidth}%`, height: "100%", background: color + "99", borderRadius: "2px" }} />
                </div>
                <span style={{ fontSize: "10px", color, minWidth: "42px", textAlign: "right" }}>
                  +{delta.toFixed(3)}
                </span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

const CATEGORY_LABELS = {
  DHCP_SUCCESS:   "DHCP ✓",
  DHCP_FAILURE:   "DHCP ✗",
  DNS_SUCCESS:    "DNS ✓",
  DNS_FAILURE:    "DNS ✗",
  AUTH_SUCCESS:   "Auth ✓",
  AUTH_FAILURE:   "Auth ✗",
  ROAM_SUCCESS:   "Roam ✓",
  ROAM_FAILURE:   "Roam ✗",
  DISASSOC:       "Disassoc",
  ARP_SUCCESS:    "ARP ✓",
  ARP_FAILURE:    "ARP ✗",
  CAPTIVE_PORTAL: "Captive",
  SECURITY:       "Security",
  COLLABORATION:  "Collab",
  OTHER:          "Other",
};

const EVENT_CATEGORIES = Object.keys(CATEGORY_LABELS);

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

function scoreBar(ifScore) {
  if (ifScore === null || ifScore === undefined) return null;
  const clamped = Math.max(-0.5, Math.min(0.5, ifScore));
  const anomalyFraction = (0.5 - clamped) / 1.0;
  const red = Math.round(80 + anomalyFraction * 145);
  const green = Math.round(180 - anomalyFraction * 155);
  return { fraction: anomalyFraction, color: `rgb(${red}, ${green}, 50)` };
}

function computeMacHealth(cats) {
  const success = (cats.DHCP_SUCCESS || 0) + (cats.DNS_SUCCESS || 0) +
                  (cats.AUTH_SUCCESS || 0) + (cats.ROAM_SUCCESS || 0) + (cats.ARP_SUCCESS || 0);
  const failure = (cats.DHCP_FAILURE || 0) + (cats.DNS_FAILURE || 0) +
                  (cats.AUTH_FAILURE || 0) + (cats.ROAM_FAILURE || 0) + (cats.ARP_FAILURE || 0);
  const total = success + failure;
  if (total === 0) return null;
  return 1.0 - (failure / total);
}

function healthColor(score) {
  if (score >= 0.85) return "#4caf7d";
  if (score >= 0.75) return "#e0a835";
  if (score >= 0.55) return "#e07835";
  return "#e05555";
}

export default function OrgFamilyDrilldown({ family, apiBase, onMacSiteSelect, onBack, wlan }) {
  const [data, setData]       = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState(null);

  const [sortCol, setSortCol] = useState("if_score");
  const [sortDir, setSortDir] = useState("asc");

  useEffect(() => {
    setLoading(true);
    setError(null);
    apiFetch(`${apiBase}/api/v1/org/families/${encodeURIComponent(family)}/drilldown?wlan=${encodeURIComponent(wlan)}`)
      .then(r => {
        if (!r.ok) return r.json().then(e => Promise.reject(e.detail || r.statusText));
        return r.json();
      })
      .then(d => { setData(d); setLoading(false); })
      .catch(e => { setError(String(e)); setLoading(false); });
  }, [family, apiBase, wlan]);

  const handleSort = (col) => {
    if (sortCol === col) {
      setSortDir(d => d === "asc" ? "desc" : "asc");
    } else {
      setSortCol(col);
      setSortDir(col === "mac" || col === "site_name" || col === "health" ? "asc" : "desc");
    }
  };

  const sortedRows = data ? [...data.rows].sort((a, b) => {
    if (sortCol === "mac")       return sortDir === "asc" ? a.mac.localeCompare(b.mac) : b.mac.localeCompare(a.mac);
    if (sortCol === "site_name") return sortDir === "asc" ? a.site_name.localeCompare(b.site_name) : b.site_name.localeCompare(a.site_name);
    if (sortCol === "if_score") {
      const av = a.if_score ?? 999;
      const bv = b.if_score ?? 999;
      return sortDir === "asc" ? av - bv : bv - av;
    }
    if (sortCol === "health") {
      const av = computeMacHealth(a.categories) ?? 2;
      const bv = computeMacHealth(b.categories) ?? 2;
      return sortDir === "asc" ? av - bv : bv - av;
    }
    if (sortCol === "markov_ratio") {
      // Flagged MACs sort above non-flagged; within each group sort by ratio descending
      const aFlagged = a.is_markov_outlier ? 1 : 0;
      const bFlagged = b.is_markov_outlier ? 1 : 0;
      if (aFlagged !== bFlagged) return sortDir === "asc" ? bFlagged - aFlagged : aFlagged - bFlagged;
      const av = a.markov_episode_anomaly_ratio ?? 0;
      const bv = b.markov_episode_anomaly_ratio ?? 0;
      return sortDir === "asc" ? bv - av : av - bv;
    }
    if (sortCol === "total_events") {
      return sortDir === "asc" ? a.total_events - b.total_events : b.total_events - a.total_events;
    }
    const av = a.categories[sortCol] || 0;
    const bv = b.categories[sortCol] || 0;
    return sortDir === "asc" ? av - bv : bv - av;
  }) : [];

  const SortTh = ({ col, children, style = {} }) => (
    <th style={{ ...thStyle, ...style }}>
      <button
        onClick={() => handleSort(col)}
        style={{
          background: "none", border: "none", padding: 0, cursor: "pointer",
          color: sortCol === col ? "#7ec8e3" : "#666",
          fontSize: "12px", fontWeight: "normal",
          display: "flex", alignItems: "center", gap: "2px", whiteSpace: "nowrap",
        }}
      >
        {children}
        <span style={{ fontSize: "9px", opacity: sortCol === col ? 1 : 0.3 }}>
          {sortCol === col ? (sortDir === "asc" ? "▲" : "▼") : "⇅"}
        </span>
      </button>
    </th>
  );

  return (
    <div>
      <div style={{ display: "flex", alignItems: "center", gap: "12px", marginBottom: "16px" }}>
        <button
          onClick={onBack}
          style={{
            background: "#1a1a1a", color: "#888", border: "1px solid #333",
            padding: "4px 10px", borderRadius: "4px", cursor: "pointer", fontSize: "12px",
          }}
        >
          ← Org Family Insights
        </button>
        <h2 style={{ margin: 0, fontSize: "15px", color: "#aaa" }}>{family}</h2>
        <span style={{ color: "#555", fontSize: "12px" }}>org-wide</span>
      </div>

      {loading && <div style={{ color: "#888", fontSize: "13px" }}>Loading…</div>}
      {error && <div style={{ color: "#e05555", fontSize: "13px" }}>Error: {error}</div>}

      {!loading && data && (
        <>
          <ShapleyBlock
            label="Device Family Behavior Explanation"
            score={shapleyScoreFromIfScore(data.worst_centroid_if_score)}
            features={data.worst_centroid_top_features}
            description={
              data.worst_centroid_if_score != null
                ? `Worst centroid IF score ${data.worst_centroid_if_score.toFixed(4)} across all sites — measures how distinctly this family's collective behavior differs from all other families at its most anomalous site.`
                : "No centroid IF score available — fewer than 3 qualifying families at all sites, or this family has fewer than 2 members at every site."
            }
          />
          <div style={{ fontSize: "12px", color: "#666", marginBottom: "12px" }}>
            {data.total_count} clients across all sites.{" "}
            <span style={{ color: "#e05555" }}>{data.if_outlier_count} flagged</span> by Isolation Forest.{" "}
            <span style={{ color: "#e05555" }}>{data.dbscan_outlier_count} flagged</span> by DBSCAN.{" "}
            <span style={{ color: "#e05555" }}>{data.markov_outlier_count} flagged</span> by Markov.
            {" "}Click column headers to sort. Click a row to open MAC drill-down.
          </div>

          {sortedRows.length === 0 ? (
            <div style={{ color: "#555", fontSize: "13px" }}>No clients found.</div>
          ) : (
            <div style={{ overflowX: "auto" }}>
              <table style={{ borderCollapse: "collapse", fontSize: "12px" }}>
                <thead>
                  <tr>
                    <SortTh col="site_name">Site</SortTh>
                    <SortTh col="mac">MAC</SortTh>
                    <SortTh col="health" style={{ minWidth: "90px" }}>Health</SortTh>
                    <SortTh col="if_score" style={{ minWidth: "120px" }}>IF Score</SortTh>
                    <th style={thStyle}>▲IF</th>
                    <th style={thStyle}>DBSCAN</th>
                    <SortTh col="markov_ratio" style={{ minWidth: "80px" }}>Markov</SortTh>
                    {EVENT_CATEGORIES.map(cat => (
                      <SortTh key={cat} col={cat}>{CATEGORY_LABELS[cat]}</SortTh>
                    ))}
                    <SortTh col="total_events">Total</SortTh>
                  </tr>
                </thead>
                <tbody>
                  {sortedRows.map((row, i) => {
                    const bar = scoreBar(row.if_score);
                    const rowBg = row.is_if_outlier ? "#1a1510" : "transparent";
                    return (
                      <tr
                        key={`${row.site_id}-${row.mac}`}
                        onClick={() => onMacSiteSelect(row.mac, row.site_id)}
                        style={{ cursor: "pointer", background: rowBg }}
                        onMouseEnter={e => e.currentTarget.style.background = "#1a2530"}
                        onMouseLeave={e => e.currentTarget.style.background = rowBg}
                      >
                        <td style={{ ...tdStyle, color: "#888", whiteSpace: "nowrap", fontSize: "11px" }}>
                          {row.site_name}
                        </td>
                        <td style={{ ...tdStyle, color: "#7ec8e3", fontFamily: "monospace", whiteSpace: "nowrap" }}>
                          {row.mac}
                          {row.random_mac && (
                            <span style={{ color: "#555", fontSize: "10px", marginLeft: "6px" }}>rnd</span>
                          )}
                        </td>
                        <td style={{ ...tdStyle, minWidth: "90px" }}>
                          {(() => {
                            const h = computeMacHealth(row.categories);
                            if (h === null) return <span style={{ color: "#444" }}>—</span>;
                            const color = healthColor(h);
                            const pct = Math.round(h * 100);
                            return (
                              <div style={{ display: "flex", alignItems: "center", gap: "5px" }}>
                                <div style={{ width: "40px", height: "6px", background: "#222", borderRadius: "2px", overflow: "hidden" }}>
                                  <div style={{ width: `${pct}%`, height: "100%", background: color, borderRadius: "2px" }} />
                                </div>
                                <span style={{ fontSize: "11px", color }}>{pct}%</span>
                              </div>
                            );
                          })()}
                        </td>
                        <td style={{ ...tdStyle, minWidth: "120px" }}>
                          {bar ? (
                            <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                              <div style={{ width: "60px", height: "8px", background: "#222", borderRadius: "2px", overflow: "hidden" }}>
                                <div style={{ width: `${Math.round(bar.fraction * 100)}%`, height: "100%", background: bar.color, borderRadius: "2px" }} />
                              </div>
                              <span style={{ color: "#888", fontSize: "11px" }}>{row.if_score.toFixed(3)}</span>
                            </div>
                          ) : (
                            <span style={{ color: "#555" }}>—</span>
                          )}
                        </td>
                        <td style={{ ...tdStyle, textAlign: "center" }}>
                          {row.is_if_outlier ? (
                            <span style={{
                              color: SEVERITY_COLOR.significant, fontSize: "10px",
                              background: SEVERITY_COLOR.significant + "22", padding: "1px 5px",
                              borderRadius: "3px", border: `1px solid ${SEVERITY_COLOR.significant}44`,
                            }}>▲</span>
                          ) : (
                            <span style={{ color: "#333", fontSize: "10px" }}>—</span>
                          )}
                        </td>
                        <td style={{ ...tdStyle, textAlign: "center" }}>
                          {row.is_dbscan_outlier ? (
                            <span style={{
                              color: SEVERITY_COLOR.significant, fontSize: "10px",
                              background: SEVERITY_COLOR.significant + "22", padding: "1px 5px",
                              borderRadius: "3px", border: `1px solid ${SEVERITY_COLOR.significant}44`,
                            }}>YES</span>
                          ) : (
                            <span style={{ color: "#444", fontSize: "10px" }}>—</span>
                          )}
                        </td>
                        <td style={{ ...tdStyle, textAlign: "center", minWidth: "80px" }}>
                          {row.is_markov_outlier ? (
                            <span
                              title={`${row.markov_anomalous_episodes}/${row.markov_scoreable_episodes} episodes anomalous`}
                              style={{
                                color: "#4ab0e8", fontSize: "10px",
                                background: "#0d2535", padding: "1px 5px",
                                borderRadius: "3px", border: "1px solid #2a6a8a",
                                whiteSpace: "nowrap",
                              }}
                            >
                              {row.markov_scoreable_episodes > 0
                                ? `${Math.round(row.markov_episode_anomaly_ratio * 100)}%`
                                : "▲"}
                            </span>
                          ) : row.markov_scoreable_episodes > 0 ? (
                            <span
                              title={`${row.markov_anomalous_episodes}/${row.markov_scoreable_episodes} episodes anomalous`}
                              style={{ color: "#2d7a4f", fontSize: "10px" }}
                            >OK</span>
                          ) : (
                            <span style={{ color: "#333", fontSize: "10px" }}>—</span>
                          )}
                        </td>
                        {EVENT_CATEGORIES.map(cat => (
                          <td key={cat} style={{ ...tdStyle, color: (row.categories[cat] || 0) > 0 ? "#aaa" : "#333", textAlign: "right" }}>
                            {(row.categories[cat] || 0) > 0 ? row.categories[cat] : "—"}
                          </td>
                        ))}
                        <td style={{ ...tdStyle, color: "#ccc", textAlign: "right", fontWeight: "500" }}>
                          {row.total_events}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}

          <div style={{ marginTop: "8px", fontSize: "11px", color: "#444" }}>
            ▲IF = Isolation Forest outlier within site peer group. DBSCAN = flagged site-wide. Markov = % of connection episodes with anomalous event sequences (hover for episode counts). Click a row to open MAC timeline.
          </div>
        </>
      )}
    </div>
  );
}
