import { useState, useEffect } from "react";
import { apiFetch } from "../api";

const EVENT_COLOR = {
  DHCP_SUCCESS: "#2d7a4f",
  DHCP_FAILURE: "#c83232",
  DNS_SUCCESS: "#2d7a4f",
  DNS_FAILURE: "#c83232",
  AUTH_SUCCESS: "#3a7a3a",
  AUTH_FAILURE: "#c83232",
  ROAM_SUCCESS: "#4ea8c4",
  ROAM_FAILURE: "#e05555",
  DISASSOC: "#888",
  ARP: "#4a7a9b",
  CAPTIVE_PORTAL: "#9b4a7a",
  SECURITY: "#e05555",
  COLLABORATION: "#7a9b4a",
  OTHER: "#555",
};

// Domain axis definitions — map human-readable axes to the raw event types in the feature vector.
// The vector now stores per-event-type frequencies; we sum them here for display only.
const DOMAIN_AXES = [
  {
    label: "Auth / Roaming",
    healthy: [
      "CLIENT_AUTHENTICATED", "CLIENT_AUTH_ASSOCIATION", "CLIENT_AUTH_ASSOCIATION_11R",
      "CLIENT_AUTH_ASSOCIATION_OKC", "CLIENT_ASSOCIATION", "CLIENT_AUTH_REASSOCIATION",
      "CLIENT_AUTH_REASSOCIATION_11R", "CLIENT_AUTH_REASSOCIATION_OKC",
      "CLIENT_REASSOCIATION", "CLIENT_REASSOCIATION_PMKC",
    ],
    unhealthy: [
      "MARVIS_EVENT_CLIENT_AUTH_FAILURE", "MARVIS_EVENT_CLIENT_AUTH_DENIED",
      "MARVIS_EVENT_CLIENT_MAC_AUTH_FAILURE", "CLIENT_ASSOCIATION_FAILURE",
      "MARVIS_EVENT_CLIENT_FBT_FAILURE", "MARVIS_EVENT_CLIENT_AUTH_FAILURE_OKC",
      "MARVIS_EVENT_CLIENT_AUTH_FAILURE_11R", "MARVIS_EVENT_WLC_FT_KEY_NOT_FOUND",
    ],
  },
  {
    label: "DHCP",
    healthy: ["CLIENT_IP_ASSIGNED", "CLIENT_IPV6_ASSIGNED"],
    unhealthy: [
      "MARVIS_EVENT_CLIENT_DHCP_NAK", "MARVIS_EVENT_CLIENT_DHCPV6_NAK",
      "MARVIS_EVENT_CLIENT_DHCP_FAILURE", "MARVIS_EVENT_CLIENT_DHCPV6_FAILURE",
      "MARVIS_EVENT_CLIENT_DHCP_STUCK", "MARVIS_EVENT_CLIENT_DHCPV6_STUCK",
      "MARVIS_EVENT_CLIENT_FAILED_DHCP_INFORM",
    ],
  },
  {
    label: "DNS",
    healthy: ["CLIENT_DNS_OK"],
    unhealthy: ["MARVIS_DNS_FAILURE"],
  },
  {
    label: "ARP",
    healthy: ["CLIENT_GW_ARP_OK"],
    unhealthy: ["CLIENT_GW_ARP_FAILURE", "CLIENT_ARP_FAILURE", "CLIENT_EXCESSIVE_ARPING_GW"],
  },
];

function domainRatios(events, axis) {
  const total = events.length;
  if (total === 0) return { healthyRatio: 0, unhealthyRatio: 0 };
  const healthySet = new Set(axis.healthy);
  const unhealthySet = new Set(axis.unhealthy);
  let healthy = 0;
  let unhealthy = 0;
  for (const evt of events) {
    if (healthySet.has(evt.type)) healthy++;
    else if (unhealthySet.has(evt.type)) unhealthy++;
  }
  return { healthyRatio: healthy / total, unhealthyRatio: unhealthy / total };
}

function formatTs(ts) {
  return new Date(ts * 1000).toLocaleTimeString();
}

// Stacked bar: healthy (green) + unhealthy (red), 0–100% of total events.
// If both are zero the bar renders as empty — client was inactive in that domain.
function DomainHealthBar({ label, healthyRatio, unhealthyRatio }) {
  const totalActivity = healthyRatio + unhealthyRatio;
  const inactive = totalActivity < 0.001;
  const healthyPct = Math.min(healthyRatio * 100, 100);
  const unhealthyPct = Math.min(unhealthyRatio * 100, 100);
  const comboPct = Math.min((healthyRatio + unhealthyRatio) * 100, 100);

  return (
    <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "7px" }}>
      <span style={{ width: "120px", fontSize: "12px", color: "#888", textAlign: "right", flexShrink: 0 }}>
        {label}
      </span>
      <div style={{ flex: 1, position: "relative", height: "16px", background: "#1a1a1a", borderRadius: "3px", overflow: "hidden" }}>
        {/* Healthy portion */}
        <div style={{
          position: "absolute", left: 0, top: 0, height: "100%",
          width: `${healthyPct}%`,
          background: "#2d7a4f",
          borderRadius: "3px 0 0 3px",
          minWidth: healthyPct > 0 ? "2px" : 0,
        }} />
        {/* Unhealthy portion, stacked right of healthy */}
        <div style={{
          position: "absolute", left: `${healthyPct}%`, top: 0, height: "100%",
          width: `${unhealthyPct}%`,
          background: "#c83232",
          minWidth: unhealthyPct > 0 ? "2px" : 0,
        }} />
      </div>
      <div style={{ width: "150px", fontSize: "11px", flexShrink: 0, display: "flex", gap: "8px" }}>
        {inactive ? (
          <span style={{ color: "#444" }}>no activity</span>
        ) : (
          <>
            <span style={{ color: "#2d7a4f" }}>{healthyPct.toFixed(1)}% ok</span>
            {unhealthyPct > 0 && <span style={{ color: "#c83232" }}>{unhealthyPct.toFixed(1)}% fail</span>}
          </>
        )}
      </div>
    </div>
  );
}


export default function MacDrilldown({ siteId, mac, apiBase, onBack }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    setLoading(true);
    apiFetch(`${apiBase}/api/v1/sites/${siteId}/anomalies/${mac}`)
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((d) => { setData(d); setError(null); })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [siteId, mac, apiBase]);

  if (loading) return <div style={{ color: "#888" }}>Loading MAC data…</div>;
  if (error) return <div style={{ color: "#e05555" }}>Error: {error}</div>;
  if (!data) return null;

  const scores = data.anomaly_scores || {};
  const meta = data.client_metadata || {};
  const vector = data.feature_vector || {};
  const events = data.events || [];

  const isOutlier = scores.is_outlier;
  const severityColor = isOutlier ? "#e05555" : "#2d7a4f";

  return (
    <div>
      <div style={{ display: "flex", alignItems: "center", gap: "12px", marginBottom: "16px" }}>
        <button
          onClick={onBack}
          style={{ background: "#1a1a1a", border: "1px solid #333", color: "#888", padding: "5px 12px", borderRadius: "4px", cursor: "pointer" }}
        >
          ← Back
        </button>
        <h2 style={{ margin: 0, fontSize: "15px", color: "#ddd", fontFamily: "monospace" }}>{mac}</h2>
        <span style={{
          background: severityColor + "22",
          color: severityColor,
          padding: "2px 10px",
          borderRadius: "3px",
          fontSize: "12px",
          border: `1px solid ${severityColor}44`,
        }}>
          {isOutlier ? "ANOMALOUS" : "NORMAL"}
        </span>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px", marginBottom: "20px" }}>
        {/* Client metadata */}
        <div style={cardStyle}>
          <h3 style={cardTitleStyle}>Device Metadata</h3>
          {[
            ["Family",       meta.family],
            ["Model",        meta.model || "—"],
            ["OS",           meta.os || "—"],
            ["Manufacturer", meta.manufacturer || "—"],
            ["Last SSID",    meta.last_ssid || "—"],
            ["Last AP",      meta.last_ap || "—"],
            ["Random MAC",   meta.random_mac ? "Yes" : "No"],
          ].map(([label, value]) => (
            <div key={label} style={kvRow}>
              <span style={{ color: "#666" }}>{label}</span>
              <span style={{ color: "#ccc" }}>{value}</span>
            </div>
          ))}
        </div>

        {/* Anomaly scores */}
        <div style={cardStyle}>
          <h3 style={cardTitleStyle}>Anomaly Scores</h3>
          {[
            ["IF score",       scores.if_score != null ? scores.if_score.toFixed(4) : "N/A (too few peers)"],
            ["IF outlier",     scores.is_if_outlier ? "Yes" : "No"],
            ["DBSCAN label",   scores.dbscan_label],
            ["DBSCAN outlier", scores.is_dbscan_outlier ? "Yes" : "No"],
            ["is_outlier",     isOutlier ? "Yes" : "No"],
            ["Total events",   data.event_count],
            ["Median gap",     vector.median_inter_event_seconds != null ? `${vector.median_inter_event_seconds.toFixed(1)}s` : "—"],
            ["Gap CV",         vector.inter_event_cv != null ? vector.inter_event_cv.toFixed(3) : "—"],
          ].map(([label, value]) => (
            <div key={label} style={kvRow}>
              <span style={{ color: "#666" }}>{label}</span>
              <span style={{ color: String(value) === "Yes" ? "#e05555" : "#ccc" }}>{String(value)}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Domain health axes */}
      <div style={{ ...cardStyle, marginBottom: "20px" }}>
        <h3 style={cardTitleStyle}>Domain Health Axes</h3>
        <div style={{ fontSize: "11px", color: "#444", marginBottom: "10px" }}>
          Bars show share of total events that were healthy (green) or unhealthy (red).
          Empty bar = no activity in that domain (not a problem in itself).
        </div>
        {DOMAIN_AXES.map((axis) => {
          const { healthyRatio, unhealthyRatio } = domainRatios(events, axis);
          return (
            <DomainHealthBar
              key={axis.label}
              label={axis.label}
              healthyRatio={healthyRatio}
              unhealthyRatio={unhealthyRatio}
            />
          );
        })}

      </div>

      {/* 24hr event timeline */}
      <div style={cardStyle}>
        <h3 style={cardTitleStyle}>24hr Event Timeline ({events.length} events)</h3>
        <div style={{ maxHeight: "400px", overflowY: "auto", fontFamily: "monospace", fontSize: "12px" }}>
          {events.map((evt, i) => {
            const cat = evt.event_category || "OTHER";
            const color = EVENT_COLOR[cat] || "#555";
            return (
              <div key={i} style={{ display: "flex", gap: "10px", padding: "3px 0", borderBottom: "1px solid #111", alignItems: "flex-start" }}>
                <span style={{ color: "#555", flexShrink: 0, width: "80px" }}>{formatTs(evt.timestamp)}</span>
                <span style={{ color, flexShrink: 0, width: "320px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {evt.type}
                </span>
                <span style={{ color: "#444", fontSize: "11px" }}>
                  {evt.ap ? `AP:${evt.ap.slice(-4)} ` : ""}
                  {evt.ssid ? `SSID:${evt.ssid} ` : ""}
                  {evt.status_code !== undefined && evt.status_code !== 0 ? `status:${evt.status_code} ` : ""}
                  {evt.reason_code !== undefined && evt.reason_code !== 0 ? `reason:${evt.reason_code}` : ""}
                </span>
              </div>
            );
          })}
          {events.length === 0 && <div style={{ color: "#555" }}>No events in timeline.</div>}
        </div>
      </div>
    </div>
  );
}

const cardStyle = {
  background: "#161616",
  border: "1px solid #262626",
  borderRadius: "4px",
  padding: "14px",
};

const cardTitleStyle = {
  margin: "0 0 10px 0",
  fontSize: "13px",
  color: "#666",
  fontWeight: "normal",
  borderBottom: "1px solid #222",
  paddingBottom: "6px",
};

const kvRow = {
  display: "flex",
  justifyContent: "space-between",
  padding: "3px 0",
  borderBottom: "1px solid #1e1e1e",
  fontSize: "13px",
};
