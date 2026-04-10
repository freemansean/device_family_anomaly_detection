import { useState, useEffect } from "react";
import { apiFetch } from "../api";

const SEVERITY_COLOR = { significant: "#e05555", moderate: "#e0a835", minimal: "#4ea8c4" };
const SA_COLOR = "#d4a06a";
const SA_BG    = "#2a1f15";

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

const SERVICE_BUCKETS = [
  { svc: "auth", success: "AUTH_SUCCESS", failure: "AUTH_FAILURE" },
  { svc: "roam", success: "ROAM_SUCCESS", failure: "ROAM_FAILURE" },
  { svc: "dhcp", success: "DHCP_SUCCESS", failure: "DHCP_FAILURE" },
  { svc: "dns",  success: "DNS_SUCCESS",  failure: "DNS_FAILURE" },
  { svc: "arp",  success: "ARP_SUCCESS",  failure: "ARP_FAILURE" },
];
const SERVICE_HEALTH_THRESHOLD = 0.50;

function computeMacServiceAlarms(cats) {
  const out = [];
  for (const b of SERVICE_BUCKETS) {
    const s = cats[b.success] || 0;
    const f = cats[b.failure] || 0;
    const total = s + f;
    if (total === 0) continue;
    const health = s / total;
    if (health < SERVICE_HEALTH_THRESHOLD) {
      out.push({ svc: b.svc, health });
    }
  }
  return out;
}

function ServiceAlarmCards({ alarms }) {
  if (!alarms || alarms.length === 0) {
    return <span style={{ color: "#444", fontSize: "11px" }}>—</span>;
  }
  return (
    <span style={{ display: "flex", flexWrap: "wrap", gap: "3px" }}>
      {alarms.map((a) => (
        <span
          key={a.svc}
          title={`${a.svc.toUpperCase()} health ${Math.round(a.health * 100)}%`}
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
          {a.svc}
        </span>
      ))}
    </span>
  );
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
        <h2 style={{ margin: 0, fontSize: "15px", color: "#aaa" }}>
          {data?.family_kind === "service_account" && data?.service_account_label
            ? data.service_account_label
            : family}
        </h2>
        {data?.family_kind === "service_account" && (
          <span
            style={{ background: SA_BG, color: SA_COLOR, border: `1px solid ${SA_COLOR}55`, borderRadius: "3px", padding: "2px 7px", fontSize: "10px", fontWeight: "bold", letterSpacing: "0.05em" }}
            title="Service account: same username shared across multiple devices"
          >
            SVC ACCT
          </span>
        )}
        <span style={{ color: "#555", fontSize: "12px" }}>org-wide</span>
      </div>

      {data?.family_kind === "service_account" && data?.service_account_member_families?.length > 0 && (
        <div
          style={{
            background: SA_BG,
            border: `1px solid ${SA_COLOR}44`,
            borderLeft: `3px solid ${SA_COLOR}`,
            borderRadius: "4px",
            padding: "10px 12px",
            marginBottom: "14px",
            fontSize: "12px",
            color: "#bbb",
          }}
        >
          <div style={{ color: SA_COLOR, fontSize: "11px", fontWeight: "bold", letterSpacing: "0.06em", textTransform: "uppercase", marginBottom: "4px" }}>
            Service account · spans {data.service_account_member_families.length} device {data.service_account_member_families.length === 1 ? "family" : "families"}
          </div>
          <div style={{ color: "#999" }}>
            Username <span style={{ color: SA_COLOR, fontFamily: "monospace" }}>{data.service_account_label}</span>{" "}
            shared across: {data.service_account_member_families.join(", ")}
          </div>
        </div>
      )}

      {loading && <div style={{ color: "#888", fontSize: "13px" }}>Loading…</div>}
      {error && <div style={{ color: "#e05555", fontSize: "13px" }}>Error: {error}</div>}

      {!loading && data && (
        <>
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
                    {data.family_kind === "service_account" && (
                      <th style={thStyle}>Primary Family</th>
                    )}
                    <SortTh col="health" style={{ minWidth: "90px" }}>Health</SortTh>
                    <th style={{ ...thStyle, minWidth: "100px" }}>Service Alarm</th>
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
                          {row.last_username && (
                            <span style={{ color: SA_COLOR, fontSize: "10px", marginLeft: "6px", fontFamily: "monospace" }}
                              title={`username: ${row.last_username}`}>
                              {row.last_username}
                            </span>
                          )}
                        </td>
                        {data.family_kind === "service_account" && (
                          <td style={{ ...tdStyle, color: "#888", fontSize: "11px", whiteSpace: "nowrap" }}>
                            {row.primary_device_family || "—"}
                          </td>
                        )}
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
                        <td style={{ ...tdStyle, minWidth: "100px" }}>
                          <ServiceAlarmCards alarms={computeMacServiceAlarms(row.categories)} />
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
                              title={`Markov ${row.markov_reason || "anomaly"}: ${row.markov_anomalous_episodes}/${row.markov_scoreable_episodes} episodes anomalous`}
                              style={{
                                color: "#4ab0e8", fontSize: "10px",
                                background: "#0d2535", padding: "1px 5px",
                                borderRadius: "3px", border: "1px solid #2a6a8a",
                                whiteSpace: "nowrap",
                              }}
                            >
                              {row.markov_reason || "chain"}
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
            ▲IF = Isolation Forest outlier within site peer group. DBSCAN = flagged site-wide. Markov = anomaly (anomalous connection-chain transitions) or repeated (stuck failure loop) — hover for episode counts. Click a row to open MAC timeline.
          </div>
        </>
      )}
    </div>
  );
}
