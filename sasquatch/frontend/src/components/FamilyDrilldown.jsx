import { useState, useEffect } from "react";
import { apiFetch } from "../api";
import ColumnSelector, { loadVisibleFromStorage } from "./ColumnSelector";

const SEVERITY_COLOR = { significant: "#e05555", moderate: "#e0a835", minimal: "#4ea8c4" };
const SA_COLOR = "#d4a06a";
const SA_BG    = "#2a1f15";
const MFG_COLOR = "#5ab5c8";
const MFG_BG    = "#13272a";

const CATEGORY_LABELS = {
  DHCP_SUCCESS:   "DHCP ✓",
  DHCP_FAILURE:   "DHCP ✗",
  DNS_SUCCESS:    "DNS ✓",
  DNS_FAILURE:    "DNS ✗",
  AUTH_SUCCESS:   "Auth ✓",
  AUTH_FAILURE:   "Auth ✗",
  ROAM_SUCCESS:   "Roam ✓",
  ROAM_FAILURE:   "Roam ✗",
  DISASSOC_AP:     "Disassoc - AP",
  DISASSOC_CLIENT: "Disassoc - Client",
  ARP_SUCCESS:    "ARP ✓",
  ARP_FAILURE:    "ARP ✗",
  CAPTIVE_PORTAL: "Captive",
  SECURITY:       "Security",
  COLLABORATION:  "Collab",
  OTHER:          "Other",
};

const EVENT_CATEGORIES = Object.keys(CATEGORY_LABELS);

const COLUMN_DEFS = [
  { key: "mac",              label: "MAC", required: true },
  { key: "primary_family",   label: "Primary Family" },
  { key: "health",           label: "Health" },
  { key: "service_alarm",    label: "Service Alarm" },
  { key: "if_score",         label: "IF Score" },
  { key: "if_flag",          label: "▲IF" },
  { key: "dbscan",           label: "DBSCAN" },
  { key: "markov",           label: "Markov" },
  ...EVENT_CATEGORIES.map(c => ({ key: `cat_${c}`, label: CATEGORY_LABELS[c] })),
  { key: "total_events",     label: "Total" },
  { key: "model",            label: "Model" },
  { key: "os",               label: "OS" },
  { key: "manufacturer",     label: "Manufacturer" },
];

const DEFAULT_VISIBLE = {
  mac: true, primary_family: true,
  health: true, service_alarm: true, if_score: true, if_flag: true,
  dbscan: true, markov: true,
  cat_DHCP_SUCCESS: true, cat_DHCP_FAILURE: true,
  cat_DNS_SUCCESS: false, cat_DNS_FAILURE: false,
  cat_AUTH_SUCCESS: true, cat_AUTH_FAILURE: true,
  cat_ROAM_SUCCESS: true, cat_ROAM_FAILURE: true,
  cat_DISASSOC_AP: false,
  cat_DISASSOC_CLIENT: false,
  cat_ARP_SUCCESS: false, cat_ARP_FAILURE: false,
  cat_CAPTIVE_PORTAL: false, cat_SECURITY: false,
  cat_COLLABORATION: false, cat_OTHER: false,
  total_events: true,
  model: false, os: false, manufacturer: false,
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

// Per-MAC service alarms — services where success/(success+failure) < 0.50.
// Inactive services (no events in the bucket) are excluded. Returns a list of
// {svc, health} sorted by service order.
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

export default function FamilyDrilldown({ siteId, family, apiBase, onMacSelect, onBack, refreshToken, wlan }) {
  const [ifData, setIfData] = useState(null);
  const [ifLoading, setIfLoading] = useState(true);
  const [ifError, setIfError] = useState(null);

  const [eventData, setEventData] = useState(null);
  const [eventLoading, setEventLoading] = useState(true);
  const [eventError, setEventError] = useState(null);

  const [sortCol, setSortCol] = useState("if_score");
  const [sortDir, setSortDir] = useState("desc");
  const [visibleCols, setVisibleCols] = useState(() =>
    loadVisibleFromStorage("familyDrilldown.columns.v2", DEFAULT_VISIBLE)
  );

  useEffect(() => {
    setIfLoading(true);
    setIfError(null);
    apiFetch(`${apiBase}/api/v1/sites/${siteId}/families/${encodeURIComponent(family)}/if-outliers?wlan=${encodeURIComponent(wlan)}`)
      .then((r) => {
        if (!r.ok) return r.json().then((e) => Promise.reject(e.detail || r.statusText));
        return r.json();
      })
      .then((d) => { setIfData(d); setIfLoading(false); })
      .catch((e) => { setIfError(String(e)); setIfLoading(false); });
  }, [siteId, family, apiBase, refreshToken, wlan]);

  useEffect(() => {
    setEventLoading(true);
    setEventError(null);
    apiFetch(`${apiBase}/api/v1/sites/${siteId}/families/${encodeURIComponent(family)}/event-counts?wlan=${encodeURIComponent(wlan)}`)
      .then((r) => {
        if (!r.ok) return r.json().then((e) => Promise.reject(e.detail || r.statusText));
        return r.json();
      })
      .then((d) => { setEventData(d); setEventLoading(false); })
      .catch((e) => { setEventError(String(e)); setEventLoading(false); });
  }, [siteId, family, apiBase, refreshToken, wlan]);

  const handleSort = (col) => {
    if (sortCol === col) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortCol(col);
      setSortDir(col === "mac" || col === "health" ? "asc" : "desc");
    }
  };

  // Build merged rows indexed by MAC
  const mergedRows = (() => {
    if (!ifData) return [];
    const eventByMac = {};
    if (eventData) {
      for (const c of eventData.clients) eventByMac[c.mac] = c;
    }
    return ifData.outliers.map((client) => {
      const ev = eventByMac[client.mac] || {};
      return {
        mac: client.mac,
        random_mac: client.random_mac,
        if_score: client.if_score,
        is_if_outlier: client.is_if_outlier,
        is_dbscan_outlier: client.is_dbscan_outlier,
        is_markov_outlier: client.is_markov_outlier,
        markov_episode_anomaly_ratio: client.markov_episode_anomaly_ratio,
        markov_reason: client.markov_reason,
        event_count: client.event_count,
        categories: ev.categories || {},
        total_events: ev.total_events ?? client.event_count,
        meta: client.client_metadata || {},
        primary_device_family: client.primary_device_family,
        last_username: client.last_username,
        is_service_account_record: client.is_service_account_record,
      };
    });
  })();

  const sortedRows = [...mergedRows].sort((a, b) => {
    if (sortCol === "mac") {
      return sortDir === "asc" ? a.mac.localeCompare(b.mac) : b.mac.localeCompare(a.mac);
    }
    if (sortCol === "if_score") {
      const av = a.if_score ?? -999;
      const bv = b.if_score ?? -999;
      // More anomalous (lower score) = higher rank in desc
      return sortDir === "desc" ? av - bv : bv - av;
    }
    if (sortCol === "health") {
      const av = computeMacHealth(a.categories) ?? 2;
      const bv = computeMacHealth(b.categories) ?? 2;
      return sortDir === "asc" ? av - bv : bv - av;
    }
    if (sortCol === "total_events") {
      return sortDir === "asc" ? a.total_events - b.total_events : b.total_events - a.total_events;
    }
    // Event category column
    const av = a.categories[sortCol] || 0;
    const bv = b.categories[sortCol] || 0;
    return sortDir === "asc" ? av - bv : bv - av;
  });

  const loading = ifLoading || eventLoading;
  const error = ifError || eventError;

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
          ← Site WLAN Family Insights
        </button>
        <h2 style={{ margin: 0, fontSize: "15px", color: "#aaa" }}>
          {ifData?.family_kind === "service_account" && ifData?.service_account_label
            ? ifData.service_account_label
            : ifData?.family_kind === "mfg_rollup" && ifData?.mfg_rollup_label
            ? ifData.mfg_rollup_label
            : family}
        </h2>
        {ifData?.family_kind === "service_account" && (
          <span
            style={{ background: SA_BG, color: SA_COLOR, border: `1px solid ${SA_COLOR}55`, borderRadius: "3px", padding: "2px 7px", fontSize: "10px", fontWeight: "bold", letterSpacing: "0.05em" }}
            title="Service account: same username shared across multiple devices"
          >
            SVC ACCT
          </span>
        )}
        {ifData?.family_kind === "mfg_rollup" && (
          <span
            style={{ background: MFG_BG, color: MFG_COLOR, border: `1px solid ${MFG_COLOR}55`, borderRadius: "3px", padding: "2px 7px", fontSize: "10px", fontWeight: "bold", letterSpacing: "0.05em" }}
            title="Manufacturer rollup: aggregates every MAC of this manufacturer regardless of fingerprint depth"
          >
            MFG ROLLUP
          </span>
        )}
        <div style={{ flex: 1 }} />
        <ColumnSelector
          columns={COLUMN_DEFS}
          visible={visibleCols}
          onChange={setVisibleCols}
          storageKey="familyDrilldown.columns.v2"
        />
      </div>

      {ifData?.family_kind === "service_account" && ifData?.service_account_member_families?.length > 0 && (
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
            Service account · spans {ifData.service_account_member_families.length} device {ifData.service_account_member_families.length === 1 ? "family" : "families"}
          </div>
          <div style={{ color: "#999" }}>
            Username <span style={{ color: SA_COLOR, fontFamily: "monospace" }}>{ifData.service_account_label}</span>{" "}
            shared across this site as: {ifData.service_account_member_families.join(", ")}
          </div>
        </div>
      )}

      {ifData?.family_kind === "mfg_rollup" && ifData?.mfg_rollup_member_families?.length > 0 && (
        <div
          style={{
            background: MFG_BG,
            border: `1px solid ${MFG_COLOR}44`,
            borderLeft: `3px solid ${MFG_COLOR}`,
            borderRadius: "4px",
            padding: "10px 12px",
            marginBottom: "14px",
            fontSize: "12px",
            color: "#bbb",
          }}
        >
          <div style={{ color: MFG_COLOR, fontSize: "11px", fontWeight: "bold", letterSpacing: "0.06em", textTransform: "uppercase", marginBottom: "4px" }}>
            Manufacturer rollup · {ifData.mfg_rollup_member_families.length} per-fingerprint {ifData.mfg_rollup_member_families.length === 1 ? "family" : "families"}
          </div>
          <div style={{ color: "#999" }}>
            <span style={{ color: MFG_COLOR, fontFamily: "monospace" }}>{ifData.mfg_rollup_label}</span>{" "}
            aggregates at this site: {ifData.mfg_rollup_member_families.join(", ")}
          </div>
        </div>
      )}

      {loading && <div style={{ color: "#888" }}>Loading…</div>}
      {error && <div style={{ color: "#e05555" }}>Error: {error}</div>}

      {!loading && ifData && (
        <>
          <div style={{ fontSize: "12px", color: "#666", marginBottom: "12px" }}>
            Showing all {ifData.total_family_count} clients in this family.{" "}
            <span style={{ color: "#e05555" }}>{ifData.if_outlier_count} flagged</span> by Isolation Forest.
            Click column headers to sort.
          </div>

          {sortedRows.length === 0 ? (
            <div style={{ color: "#555", fontSize: "13px" }}>No clients found for this family.</div>
          ) : (
            <div style={{ overflowX: "auto" }}>
              <table style={{ borderCollapse: "collapse", fontSize: "12px" }}>
                <thead>
                  <tr>
                    {/* IF columns */}
                    {visibleCols.mac && <SortTh col="mac">MAC</SortTh>}
                    {visibleCols.primary_family && (ifData.family_kind === "service_account" || ifData.family_kind === "mfg_rollup") && (
                      <th style={thStyle}>Primary Family</th>
                    )}
                    {visibleCols.health && <SortTh col="health" style={{ minWidth: "90px" }}>Health</SortTh>}
                    {visibleCols.service_alarm && <th style={{ ...thStyle, minWidth: "100px" }}>Service Alarm</th>}
                    {visibleCols.if_score && <SortTh col="if_score" style={{ minWidth: "120px" }}>IF Score</SortTh>}
                    {visibleCols.if_flag && <th style={thStyle}>▲IF</th>}
                    {visibleCols.dbscan && <th style={thStyle}>DBSCAN</th>}
                    {visibleCols.markov && <th style={thStyle}>Markov</th>}
                    {/* Event category columns */}
                    {EVENT_CATEGORIES.map((cat) => (
                      visibleCols[`cat_${cat}`] && <SortTh key={cat} col={cat}>{CATEGORY_LABELS[cat]}</SortTh>
                    ))}
                    {visibleCols.total_events && <SortTh col="total_events">Total</SortTh>}
                    {/* Metadata */}
                    {visibleCols.model && <th style={thStyle}>Model</th>}
                    {visibleCols.os && <th style={thStyle}>OS</th>}
                    {visibleCols.manufacturer && <th style={thStyle}>Manufacturer</th>}
                  </tr>
                </thead>
                <tbody>
                  {sortedRows.map((row) => {
                    const bar = scoreBar(row.if_score);
                    const rowBg = row.is_if_outlier ? "#1a1510" : "transparent";
                    return (
                      <tr
                        key={row.mac}
                        onClick={() => onMacSelect(row.mac)}
                        style={{ cursor: "pointer", background: rowBg }}
                        onMouseEnter={(e) => e.currentTarget.style.background = "#1a2530"}
                        onMouseLeave={(e) => e.currentTarget.style.background = rowBg}
                      >
                        {visibleCols.mac && (
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
                        )}
                        {visibleCols.primary_family && (ifData.family_kind === "service_account" || ifData.family_kind === "mfg_rollup") && (
                          <td style={{ ...tdStyle, color: "#888", fontSize: "11px", whiteSpace: "nowrap" }}>
                            {row.primary_device_family || "—"}
                          </td>
                        )}
                        {visibleCols.health && (
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
                        )}
                        {visibleCols.service_alarm && (
                          <td style={{ ...tdStyle, minWidth: "100px" }}>
                            <ServiceAlarmCards alarms={computeMacServiceAlarms(row.categories)} />
                          </td>
                        )}
                        {visibleCols.if_score && (
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
                        )}
                        {visibleCols.if_flag && (
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
                        )}
                        {visibleCols.dbscan && (
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
                        )}
                        {visibleCols.markov && (
                          <td style={{ ...tdStyle, textAlign: "center" }}>
                            {row.is_markov_outlier ? (
                              <span style={{
                                color: "#4ab0e8", fontSize: "10px",
                                background: "#1a2a3a", padding: "1px 5px",
                                borderRadius: "3px", border: "1px solid #2a6a8a",
                              }}
                                title={`Markov ${row.markov_reason || "anomaly"}${row.markov_episode_anomaly_ratio != null ? ` — ${(row.markov_episode_anomaly_ratio * 100).toFixed(0)}% of episodes anomalous` : ""}`}
                              >
                                {row.markov_reason || "chain"}
                              </span>
                            ) : (
                              <span style={{ color: "#333", fontSize: "10px" }}>—</span>
                            )}
                          </td>
                        )}
                        {EVENT_CATEGORIES.map((cat) => (
                          visibleCols[`cat_${cat}`] && (
                            <td key={cat} style={{ ...tdStyle, color: (row.categories[cat] || 0) > 0 ? "#aaa" : "#333", textAlign: "right" }}>
                              {(row.categories[cat] || 0) > 0 ? row.categories[cat] : "—"}
                            </td>
                          )
                        ))}
                        {visibleCols.total_events && (
                          <td style={{ ...tdStyle, color: "#ccc", textAlign: "right", fontWeight: "500" }}>
                            {row.total_events}
                          </td>
                        )}
                        {visibleCols.model && <td style={{ ...tdStyle, color: "#999" }}>{row.meta.model || "—"}</td>}
                        {visibleCols.os && <td style={{ ...tdStyle, color: "#999" }}>{row.meta.os || "—"}</td>}
                        {visibleCols.manufacturer && <td style={{ ...tdStyle, color: "#999" }}>{row.meta.manufacturer || "—"}</td>}
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}

          <div style={{ marginTop: "8px", fontSize: "11px", color: "#444" }}>
            Click a row to open the MAC drill-down timeline. ▲ = Isolation Forest outlier. DBSCAN = flagged site-wide. Markov = anomaly (connection-chain transitions) or repeated (stuck failure loop).
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
