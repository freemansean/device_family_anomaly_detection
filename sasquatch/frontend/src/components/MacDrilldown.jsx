import { useState, useEffect } from "react";

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

// Domain axis pairs — each rendered as a stacked healthy/unhealthy bar.
const DOMAIN_AXES = [
  { key: "auth_roam", label: "Auth / Roaming" },
  { key: "dhcp",      label: "DHCP" },
  { key: "dns",       label: "DNS" },
  { key: "arp",       label: "ARP" },
];

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

function RssiBar({ label, value, min, max, isPercent }) {
  const range = max - min;
  const pct = range === 0 ? 0 : Math.max(0, Math.min(100, ((value - min) / range) * 100));
  const color = value < -75 ? "#c83232" : value < -65 ? "#e0a835" : "#2d7a4f";
  return (
    <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "7px" }}>
      <span style={{ width: "120px", fontSize: "12px", color: "#888", textAlign: "right", flexShrink: 0 }}>{label}</span>
      <div style={{ flex: 1, position: "relative", height: "16px", background: "#1a1a1a", borderRadius: "3px", overflow: "hidden" }}>
        <div style={{ position: "absolute", left: 0, top: 0, height: "100%", width: `${pct}%`, background: color, borderRadius: "3px", minWidth: "2px" }} />
      </div>
      <span style={{ width: "150px", fontSize: "11px", color, flexShrink: 0 }}>
        {isPercent ? `${value >= 0 ? "+" : ""}${value.toFixed(1)} dBm/hr` : `${value.toFixed(1)} dBm`}
      </span>
    </div>
  );
}

export default function MacDrilldown({ siteId, mac, apiBase, onBack }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    setLoading(true);
    fetch(`${apiBase}/api/v1/sites/${siteId}/anomalies/${mac}`)
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

  const rssiMean = vector.rssi_mean ?? 0;
  const hasRssi = rssiMean !== 0;

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
        {DOMAIN_AXES.map(({ key, label }) => (
          <DomainHealthBar
            key={key}
            label={label}
            healthyRatio={vector[`${key}_healthy_ratio`] ?? 0}
            unhealthyRatio={vector[`${key}_unhealthy_ratio`] ?? 0}
          />
        ))}

        {hasRssi && (
          <>
            <div style={{ borderTop: "1px solid #222", margin: "10px 0 10px 0" }} />
            <div style={{ fontSize: "11px", color: "#444", marginBottom: "8px" }}>
              Signal quality (RSSI across all events, independent of type)
            </div>
            <RssiBar label="Mean RSSI"   value={rssiMean}              min={-90} max={-30} />
            <RssiBar label="10th pct"    value={vector.rssi_p10 ?? 0}  min={-90} max={-30} />
            <RssiBar label="Std dev"     value={-(vector.rssi_std ?? 0)} min={-30} max={0} />
            <RssiBar label="Trend"       value={vector.rssi_trend ?? 0} min={-20} max={20} isPercent />
          </>
        )}
        {!hasRssi && (
          <div style={{ color: "#444", fontSize: "12px", marginTop: "8px" }}>RSSI — no signal data in events</div>
        )}
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
                  {evt.rssi ? `rssi:${evt.rssi} ` : ""}
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
