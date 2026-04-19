import { useState, useEffect } from "react";
import { apiFetch } from "../api";

const SA_COLOR = "#d4a06a";
const SA_BG = "#2a1f15";
const MFG_COLOR = "#5ab5c8";
const MFG_BG = "#13272a";

const EVENT_COLOR = {
  DHCP_SUCCESS: "#2d7a4f",
  DHCP_FAILURE: "#c83232",
  DNS_SUCCESS: "#2d7a4f",
  DNS_FAILURE: "#c83232",
  AUTH_SUCCESS: "#3a7a3a",
  AUTH_FAILURE: "#c83232",
  ROAM_SUCCESS: "#4ea8c4",
  ROAM_FAILURE: "#e05555",
  DISASSOC_AP: "#a86464",
  DISASSOC_CLIENT: "#888",
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


export default function MacDrilldown({ siteId, mac, apiBase, onBack, wlan }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!siteId || !mac) return;
    setLoading(true);
    const qs = wlan ? `?wlan=${encodeURIComponent(wlan)}` : "";
    apiFetch(`${apiBase}/api/v1/sites/${siteId}/anomalies/${mac}${qs}`)
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((d) => { setData(d); setError(null); })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [siteId, mac, apiBase, wlan]);

  if (loading) return <div style={{ color: "#888" }}>Loading MAC data…</div>;
  if (error) return <div style={{ color: "#e05555" }}>Error: {error}</div>;
  if (!data) return null;

  const scores = data.anomaly_scores || {};
  const meta = data.client_metadata || {};
  const vector = data.feature_vector || {};
  const events = data.events || [];

  const isOutlier = scores.is_outlier;
  const severityColor = isOutlier ? "#e05555" : "#2d7a4f";

  const healthScore = data.health_score;
  const serviceAlarms = data.service_alarms || [];
  const serviceHealth = data.service_health || {};
  const healthPctStr = healthScore != null ? `${Math.round(healthScore * 100)}%` : "—";
  const healthColor =
    healthScore == null ? "#666"
    : healthScore >= 0.85 ? "#4caf7d"
    : healthScore >= 0.75 ? "#e0a835"
    : healthScore >= 0.55 ? "#e07835"
    : "#e05555";

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

        {/* Anomaly / Health scores */}
        <div style={cardStyle}>
          <h3 style={cardTitleStyle}>Anomaly / Health Scores</h3>
          {[
            ["IF score",       scores.if_score != null ? scores.if_score.toFixed(4) : "N/A (too few peers)"],
            ["Outlier compared to peers",     scores.is_if_outlier ? "Yes" : "No"],
            ["Outlier compared to site / wlan groups", scores.is_dbscan_outlier ? "Yes" : "No"],
            ["Device family is anomalous", scores.is_family_outlier ? "Yes" : "No"],
          ].map(([label, value]) => (
            <div key={label} style={kvRow}>
              <span style={{ color: "#666" }}>{label}</span>
              <span style={{ color: String(value) === "Yes" ? "#e05555" : "#ccc" }}>{String(value)}</span>
            </div>
          ))}
          {/* Markov reason — single row collapsing the anomaly/repeated signals
              with a sub-text giving the supporting detail. */}
          {(() => {
            const reason = scores.markov_reason;
            const labelText = reason === "repeated"
              ? "repeated"
              : reason === "anomaly"
                ? "anomaly"
                : "—";
            const labelColor = reason ? "#e05555" : "#444";
            let detail = null;
            if (reason === "repeated" && scores.stuck_loop_pair) {
              const pct = scores.stuck_loop_fraction != null
                ? `${(scores.stuck_loop_fraction * 100).toFixed(0)}%`
                : "";
              detail = `${scores.stuck_loop_pair}${pct ? ` @ ${pct}` : ""}`;
            } else if (reason === "anomaly" && scores.markov_scoreable_episodes != null) {
              const ratioPct = scores.markov_episode_anomaly_ratio != null
                ? `${(scores.markov_episode_anomaly_ratio * 100).toFixed(0)}%`
                : "";
              detail = `${scores.markov_anomalous_episodes}/${scores.markov_scoreable_episodes} episodes${ratioPct ? ` (${ratioPct})` : ""}`;
            }
            return (
              <div style={{ ...kvRow, alignItems: "flex-start" }}>
                <span style={{ color: "#666" }}>Markov reason</span>
                <span style={{ display: "flex", flexDirection: "column", alignItems: "flex-end" }}>
                  <span style={{ color: labelColor }}>{labelText}</span>
                  {detail && (
                    <span style={{ color: "#555", fontSize: "11px", marginTop: "2px" }}>
                      {detail}
                    </span>
                  )}
                </span>
              </div>
            );
          })()}
          {/* Health row — overall device health (success / total outcome-bearing events) */}
          <div style={kvRow}>
            <span style={{ color: "#666" }}>Health</span>
            {healthScore == null ? (
              <span style={{ color: "#444" }}>—</span>
            ) : (
              <span style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                <div style={{ width: "60px", height: "6px", background: "#222", borderRadius: "2px", overflow: "hidden" }}>
                  <div style={{
                    width: `${Math.round(healthScore * 100)}%`,
                    height: "100%",
                    background: healthColor,
                    borderRadius: "2px",
                  }} />
                </div>
                <span style={{ color: healthColor, fontSize: "12px", minWidth: "36px", textAlign: "right" }}>
                  {healthPctStr}
                </span>
              </span>
            )}
          </div>
          {/* Service Alarm row — cards for each service the MAC has below 50% health */}
          <div style={kvRow}>
            <span style={{ color: "#666" }}>Service Alarm</span>
            {serviceAlarms.length === 0 ? (
              <span style={{ color: "#444" }}>—</span>
            ) : (
              <span style={{ display: "flex", flexWrap: "wrap", gap: "4px", justifyContent: "flex-end" }}>
                {serviceAlarms.map((svc) => {
                  const sh = serviceHealth[svc];
                  const pct = sh != null && sh.health != null ? `${Math.round(sh.health * 100)}%` : "";
                  return (
                    <span
                      key={svc}
                      title={pct ? `${svc.toUpperCase()} health ${pct}` : svc.toUpperCase()}
                      style={{
                        background: "#e0555522",
                        color: "#e05555",
                        border: "1px solid #e0555544",
                        borderRadius: "3px",
                        padding: "2px 7px",
                        fontSize: "11px",
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
            )}
          </div>
        </div>
      </div>

      {/* Service-account family membership — shown only when this MAC is part of a username-based virtual family */}
      {scores.service_account && scores.service_account.family && (
        <div style={{
          background: SA_BG,
          border: `1px solid ${SA_COLOR}44`,
          borderLeft: `3px solid ${SA_COLOR}`,
          borderRadius: "4px",
          padding: "12px 14px",
          marginBottom: "20px",
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "8px" }}>
            <span style={{
              fontSize: "10px",
              color: SA_COLOR,
              textTransform: "uppercase",
              letterSpacing: "0.08em",
              fontWeight: 600,
              background: `${SA_COLOR}22`,
              border: `1px solid ${SA_COLOR}44`,
              padding: "2px 7px",
              borderRadius: "3px",
            }}>SVC ACCT</span>
            <span style={{ fontSize: "13px", color: "#ccc" }}>
              Also part of service account{" "}
              <span style={{ color: SA_COLOR, fontFamily: "monospace", fontWeight: 600 }}>
                {scores.service_account.family.replace(/\.service_account$/, "")}
              </span>
            </span>
          </div>
          <div style={{ fontSize: "11px", color: "#777", marginBottom: "10px" }}>
            This device shares its <code style={{ color: SA_COLOR }}>last_username</code> with ≥50 other MACs across the org.
            The username forms a virtual family that is scored independently of this device's primary family ({meta.family || "—"}).
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "6px 16px", fontSize: "12px" }}>
            {[
              ["Username", scores.service_account.last_username || "—"],
              ["SA family is anomalous", scores.service_account.is_family_outlier ? "Yes" : "No"],
              ["Outlier vs SA peers", scores.service_account.is_if_outlier ? "Yes" : "No"],
              ["SA IF score", scores.service_account.if_score != null ? scores.service_account.if_score.toFixed(4) : "N/A (too few peers)"],
              ["SA centroid distance", scores.service_account.centroid_dist_score != null ? scores.service_account.centroid_dist_score.toFixed(4) : "—"],
            ].map(([label, value]) => (
              <div key={label} style={{ display: "flex", justifyContent: "space-between", borderBottom: "1px solid #1e1e1e", padding: "3px 0" }}>
                <span style={{ color: "#666" }}>{label}</span>
                <span style={{ color: String(value) === "Yes" ? "#e05555" : "#ccc", fontFamily: label === "Username" ? "monospace" : undefined }}>
                  {String(value)}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Manufacturer-rollup family membership — shown when this MAC is part of a <mfg>-MFG virtual family */}
      {scores.mfg_rollup && scores.mfg_rollup.family && (
        <div style={{
          background: MFG_BG,
          border: `1px solid ${MFG_COLOR}44`,
          borderLeft: `3px solid ${MFG_COLOR}`,
          borderRadius: "4px",
          padding: "12px 14px",
          marginBottom: "20px",
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "8px" }}>
            <span style={{
              fontSize: "10px",
              color: MFG_COLOR,
              textTransform: "uppercase",
              letterSpacing: "0.08em",
              fontWeight: 600,
              background: `${MFG_COLOR}22`,
              border: `1px solid ${MFG_COLOR}44`,
              padding: "2px 7px",
              borderRadius: "3px",
            }}>MFG ROLLUP</span>
            <span style={{ fontSize: "13px", color: "#ccc" }}>
              Also part of manufacturer rollup{" "}
              <span style={{ color: MFG_COLOR, fontFamily: "monospace", fontWeight: 600 }}>
                {scores.mfg_rollup.family.replace(/-MFG$/, "")}
              </span>
            </span>
          </div>
          <div style={{ fontSize: "11px", color: "#777", marginBottom: "10px" }}>
            This device is folded into its manufacturer's rollup family — the cohort Centroid analysis measures against the healthy-family reference. Per-fingerprint families like <code style={{ color: MFG_COLOR }}>{meta.family || "—"}</code> drop out of Centroid entirely; the rollup carries the family-level signal instead.
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "6px 16px", fontSize: "12px" }}>
            {[
              ["Manufacturer", scores.mfg_rollup.resolved_manufacturer || "—"],
              ["Rollup family is anomalous", scores.mfg_rollup.is_family_outlier ? "Yes" : "No"],
              ["Rollup centroid distance", scores.mfg_rollup.centroid_dist_score != null ? scores.mfg_rollup.centroid_dist_score.toFixed(4) : "—"],
            ].map(([label, value]) => (
              <div key={label} style={{ display: "flex", justifyContent: "space-between", borderBottom: "1px solid #1e1e1e", padding: "3px 0" }}>
                <span style={{ color: "#666" }}>{label}</span>
                <span style={{ color: String(value) === "Yes" ? "#e05555" : "#ccc", fontFamily: label === "Manufacturer" ? "monospace" : undefined }}>
                  {String(value)}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

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
          {[...events].reverse().map((evt, i) => {
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
