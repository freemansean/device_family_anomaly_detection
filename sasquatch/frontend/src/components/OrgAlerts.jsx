import { useState, useEffect, useCallback } from "react";
import { apiFetch } from "../api";
import OrgFamilyDrilldown from "./OrgFamilyDrilldown";
import FamilyDrilldown from "./FamilyDrilldown";

// Format a duration in seconds into "Xd Yh Zm" or "Yh Zm" or "Zm"
function formatDuration(seconds) {
  if (!seconds || seconds < 60) return "<1m";
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

// Format an ISO8601 UTC string to local time HH:MM
function fmtTime(iso) {
  if (!iso) return "";
  return new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

const ALERT_COLOR = "#e05555";
const ALERT_BG    = "#2a1515";
const ANOMALY_COLOR = { significant: "#39e84e", moderate: "#2eb845", minimal: "#1a6b27" };
const HEALTH_COLOR  = "#e0a835";

function healthScoreColor(score) {
  if (score >= 0.85) return "#2d7a4f";
  if (score >= 0.75) return "#e0a835";
  if (score >= 0.55) return "#c87832";
  return "#e05555";
}

const PATTERN_LABELS = {
  dhcp_discard_loop: "DHCP Discard Loop",
  pmkid_stale: "Stale PMKID",
  gas_anqp_timeout: "GAS/ANQP Timeout",
  roam_failure: "Roam Failure",
  auth_failure_recovering: "Auth Failure (Recovering)",
  auth_failure_terminal: "Auth Failure (Terminal)",
  dns_failure: "DNS Failure",
  dhcp_failure: "DHCP Failure",
  behavioral_outlier: "Behavioral Outlier",
  family_behavioral_outlier: "Family-Wide Outlier",
};

function SectionHeader({ label, count, subtitle }) {
  return (
    <div style={{
      display: "flex",
      alignItems: "center",
      gap: "10px",
      marginBottom: "10px",
      marginTop: "20px",
      paddingBottom: "6px",
      borderBottom: `1px solid ${ALERT_COLOR}33`,
    }}>
      <span style={{
        background: ALERT_COLOR + "22",
        color: ALERT_COLOR,
        padding: "2px 10px",
        borderRadius: "3px",
        fontSize: "11px",
        fontWeight: "bold",
        letterSpacing: "0.08em",
        border: `1px solid ${ALERT_COLOR}44`,
      }}>
        {label}
      </span>
      <span style={{ color: "#444", fontSize: "11px" }}>{count} {count === 1 ? "family" : "families"}</span>
      {subtitle && <span style={{ color: "#333", fontSize: "11px" }}>· {subtitle}</span>}
    </div>
  );
}

function AlertCard({ finding, onFamilyClick }) {
  const sev = finding.severity;
  const hs = finding.health_score ?? null;

  const failureComponents = finding.health_components
    ? Object.entries(finding.health_components).filter(([, rate]) => rate > 0)
    : [];

  return (
    <div style={{
      border: `1px solid ${ALERT_COLOR}44`,
      borderLeft: `3px solid ${ALERT_COLOR}`,
      background: ALERT_BG,
      borderRadius: "4px",
      padding: "12px 14px",
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
        <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: "6px" }}>
          <span style={{
            background: ALERT_COLOR + "33",
            color: ALERT_COLOR,
            padding: "2px 8px",
            borderRadius: "3px",
            fontSize: "11px",
            fontWeight: "bold",
            border: `1px solid ${ALERT_COLOR}55`,
          }}>
            ALERT
          </span>
          <span style={{
            background: ANOMALY_COLOR[sev] + "33",
            color: ANOMALY_COLOR[sev],
            padding: "2px 8px",
            borderRadius: "3px",
            fontSize: "11px",
            border: `1px solid ${ANOMALY_COLOR[sev]}55`,
          }}>
            {sev}
          </span>
          <button
            onClick={onFamilyClick}
            style={{ fontWeight: "bold", fontSize: "14px", color: "#7ec8e3", background: "none", border: "none", cursor: "pointer", padding: 0, textDecoration: "underline", textDecorationColor: "#7ec8e344" }}
          >
            {finding.device_family}
          </button>
          <span style={{ color: "#666", fontSize: "12px" }}>
            {PATTERN_LABELS[finding.probable_pattern] || finding.probable_pattern}
          </span>
          {(finding.wlan && finding.wlan !== "__all__" ? finding.wlan : finding.predominant_wlan) && (
            <span style={{ background: "#1a2a1a", color: "#7aaa7a", border: "1px solid #3a6a3a", borderRadius: "3px", padding: "2px 7px", fontSize: "10px" }}>
              {finding.wlan !== "__all__" ? finding.wlan : finding.predominant_wlan}
            </span>
          )}
          {finding.is_family_outlier && (
            <span style={{ background: "#2a1a3a", color: "#b06ad4", border: "1px solid #6a3a8a", borderRadius: "3px", padding: "2px 7px", fontSize: "10px" }}>
              family-wide
            </span>
          )}
        </div>
        <div style={{ textAlign: "right", fontSize: "12px", marginLeft: "10px", flexShrink: 0 }}>
          <div style={{ whiteSpace: "nowrap" }}>
            <span style={{ color: ANOMALY_COLOR[sev], fontWeight: "bold" }}>
              {(finding.outlier_ratio * 100).toFixed(0)}%
            </span>
            <span style={{ color: "#555" }}> outlier</span>
            <span style={{ color: "#555", marginLeft: "8px" }}>
              {finding.affected_mac_count}/{finding.total_mac_count} devices
            </span>
          </div>
          {hs != null && (
            <div style={{ whiteSpace: "nowrap", marginTop: "3px" }}>
              <span style={{ color: "#555" }}>health </span>
              <span style={{ color: healthScoreColor(hs), fontWeight: "bold" }}>
                {(hs * 100).toFixed(0)}%
              </span>
            </div>
          )}
          {failureComponents.length > 0 && (
            <div style={{ marginTop: "3px", display: "flex", flexDirection: "column", alignItems: "flex-end", gap: "1px" }}>
              {failureComponents.map(([cat, rate]) => (
                <span key={cat} style={{ fontSize: "10px", color: rate > 0.1 ? HEALTH_COLOR : "#666", whiteSpace: "nowrap" }}>
                  {cat} {(rate * 100).toFixed(0)}% fail
                </span>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Site attribution (org-level findings) */}
      {finding.sites_affected?.length > 0 && (
        <div style={{ marginTop: "5px", fontSize: "11px", color: "#557799" }}>
          {finding.sites_affected.map(sa => sa.site_name || sa.site_id).join(" · ")}
        </div>
      )}

      {/* Top contributing features */}
      {finding.top_features?.length > 0 && (
        <div style={{ marginTop: "8px", display: "flex", gap: "6px", flexWrap: "wrap" }}>
          {finding.top_features.slice(0, 3).map((f, fi) => (
            <span
              key={fi}
              title={`Outlier mean: ${f.outlier_mean.toFixed(3)} vs baseline: ${f.baseline_mean.toFixed(3)}`}
              style={{ background: "#222", border: "1px solid #333", borderRadius: "3px", padding: "2px 7px", fontSize: "11px", color: "#999" }}
            >
              {f.feature} <span style={{ color: ANOMALY_COLOR[sev] }}>↑{Math.abs(f.outlier_mean - f.baseline_mean).toFixed(3)}</span>
            </span>
          ))}
        </div>
      )}

    </div>
  );
}

function SiteAlertGroup({ siteAlert, onFamilyClick }) {
  return (
    <div style={{
      border: `1px solid #3a2020`,
      borderRadius: "6px",
      padding: "12px 14px",
      background: "#161616",
      marginBottom: "8px",
    }}>
      <div style={{ marginBottom: "10px" }}>
        <span style={{ color: "#e0e0e0", fontSize: "13px", fontWeight: "bold" }}>{siteAlert.site_name}</span>
        <span style={{ color: "#444", fontSize: "10px", marginLeft: "8px", fontFamily: "monospace" }}>{siteAlert.site_id}</span>
        <span style={{ marginLeft: "10px", background: "#2a1515", color: ALERT_COLOR, padding: "1px 7px", borderRadius: "3px", fontSize: "10px" }}>
          {siteAlert.alerts.length} {siteAlert.alerts.length === 1 ? "ALERT" : "ALERTS"}
        </span>
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
        {siteAlert.alerts.map((alert, idx) => (
          <AlertCard
            key={`${siteAlert.site_id}-${idx}`}
            finding={alert}
            onFamilyClick={() => onFamilyClick(alert.device_family, siteAlert.site_id)}
          />
        ))}
      </div>
    </div>
  );
}

export default function OrgAlerts({ apiBase, onMacSiteSelect, refreshToken, wlan = "__all__" }) {
  const [data, setData]               = useState(null);
  const [loading, setLoading]         = useState(true);
  const [error, setError]             = useState(null);
  const [history, setHistory]         = useState(null);
  // selectedFamily: { family, siteId } — siteId null means org-wide drilldown
  const [selectedFamily, setSelectedFamily] = useState(null);

  const load = useCallback(() => {
    setLoading(true);
    Promise.all([
      apiFetch(`${apiBase}/api/v1/org/alerts?wlan=${encodeURIComponent(wlan)}`).then(r => r.json()),
      apiFetch(`${apiBase}/api/v1/org/alert-history?wlan=${encodeURIComponent(wlan)}&days=7&tz_offset=${new Date().getTimezoneOffset()}`).then(r => r.json()),
    ])
      .then(([alertData, histData]) => {
        setData(alertData);
        setHistory(histData);
        setError(null);
      })
      .catch(e => setError(e.message))
      .finally(() => setLoading(false));
  }, [apiBase, wlan]);

  useEffect(() => {
    load();
    const interval = setInterval(load, 30_000);
    return () => clearInterval(interval);
  }, [load, refreshToken]);

  if (selectedFamily) {
    if (selectedFamily.siteId) {
      return (
        <FamilyDrilldown
          siteId={selectedFamily.siteId}
          family={selectedFamily.family}
          apiBase={apiBase}
          onMacSelect={(mac) => onMacSiteSelect(mac, selectedFamily.siteId)}
          onBack={() => setSelectedFamily(null)}
          wlan={wlan}
        />
      );
    }
    return (
      <OrgFamilyDrilldown
        family={selectedFamily.family}
        apiBase={apiBase}
        onMacSiteSelect={onMacSiteSelect}
        onBack={() => setSelectedFamily(null)}
        wlan={wlan}
      />
    );
  }

  if (loading) return <div style={{ color: "#888" }}>Loading alerts…</div>;
  if (error)   return <div style={{ color: "#e05555" }}>Error: {error}</div>;

  const orgAlerts  = data?.org_alerts  ?? [];
  const siteAlerts = data?.site_alerts ?? [];
  const hasAnything = orgAlerts.length > 0 || siteAlerts.length > 0;

  if (!hasAnything) {
    return (
      <div style={{ color: "#2d7a4f", padding: "20px", fontSize: "13px" }}>
        No active alerts across the organization.
      </div>
    );
  }

  const totalSiteAlertFamilies = siteAlerts.reduce((sum, s) => sum + s.alerts.length, 0);

  return (
    <div>
      <div style={{ marginBottom: "4px" }}>
        <h2 style={{ fontSize: "15px", color: "#aaa", margin: 0 }}>
          Org Alerts
          {orgAlerts.length > 0 && (
            <span style={{ marginLeft: "10px", background: "#2a1515", color: ALERT_COLOR, padding: "2px 8px", borderRadius: "3px", fontSize: "11px" }}>
              {orgAlerts.length} org-wide
            </span>
          )}
          {totalSiteAlertFamilies > 0 && (
            <span style={{ marginLeft: "6px", background: "#2a1515", color: ALERT_COLOR, padding: "2px 8px", borderRadius: "3px", fontSize: "11px" }}>
              {totalSiteAlertFamilies} site-level
            </span>
          )}
        </h2>
      </div>

      {/* Org-wide alerts */}
      {orgAlerts.length > 0 && (
        <div>
          <SectionHeader
            label="ORG-WIDE ALERTS"
            count={orgAlerts.length}
            subtitle="device families anomalous and unhealthy across the organization"
          />
          <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
            {orgAlerts.map((finding, idx) => (
              <AlertCard
                key={`org-${idx}`}
                finding={finding}
                onFamilyClick={() => setSelectedFamily({ family: finding.device_family, siteId: null })}
              />
            ))}
          </div>
        </div>
      )}

      {/* Per-site alerts */}
      {siteAlerts.length > 0 && (
        <div>
          <div style={{
            display: "flex",
            alignItems: "center",
            gap: "10px",
            marginBottom: "10px",
            marginTop: "24px",
            paddingBottom: "6px",
            borderBottom: `1px solid ${ALERT_COLOR}33`,
          }}>
            <span style={{
              background: ALERT_COLOR + "22",
              color: ALERT_COLOR,
              padding: "2px 10px",
              borderRadius: "3px",
              fontSize: "11px",
              fontWeight: "bold",
              letterSpacing: "0.08em",
              border: `1px solid ${ALERT_COLOR}44`,
            }}>
              SITE ALERTS
            </span>
            <span style={{ color: "#444", fontSize: "11px" }}>
              {siteAlerts.length} {siteAlerts.length === 1 ? "site" : "sites"} · {totalSiteAlertFamilies} {totalSiteAlertFamilies === 1 ? "family" : "families"}
            </span>
            <span style={{ color: "#333", fontSize: "11px" }}>· device families anomalous and unhealthy at a specific site</span>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
            {siteAlerts.map(siteAlert => (
              <SiteAlertGroup
                key={siteAlert.site_id}
                siteAlert={siteAlert}
                onFamilyClick={(family, siteId) => setSelectedFamily({ family, siteId })}
              />
            ))}
          </div>
        </div>
      )}

      {/* 7-day alert history */}
      <AlertHistory history={history} />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Alert History
// ---------------------------------------------------------------------------

const HIST_COLOR = "#888";
const RESOLVED_COLOR = "#2d7a4f";

function AlertHistory({ history }) {
  const [expanded, setExpanded] = useState(true);

  const days = history?.days ?? [];
  if (days.length === 0) return null;

  // Flatten to count total unique sessions for the header badge
  const totalSessions = history?.total_sessions ?? 0;

  return (
    <div style={{ marginTop: "32px" }}>
      {/* Section header */}
      <div
        onClick={() => setExpanded(e => !e)}
        style={{
          display: "flex",
          alignItems: "center",
          gap: "10px",
          marginBottom: expanded ? "12px" : 0,
          paddingBottom: "6px",
          borderBottom: "1px solid #2a2a2a",
          cursor: "pointer",
          userSelect: "none",
        }}
      >
        <span style={{
          background: "#1e1e1e",
          color: HIST_COLOR,
          padding: "2px 10px",
          borderRadius: "3px",
          fontSize: "11px",
          fontWeight: "bold",
          letterSpacing: "0.08em",
          border: "1px solid #333",
        }}>
          7-DAY HISTORY
        </span>
        <span style={{ color: "#555", fontSize: "11px" }}>
          {totalSessions} {totalSessions === 1 ? "alarm session" : "alarm sessions"} in the past 7 days
        </span>
        <span style={{ color: "#444", fontSize: "11px", marginLeft: "auto" }}>
          {expanded ? "▲" : "▼"}
        </span>
      </div>

      {expanded && (
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          {days.map(day => (
            <DayGroup key={day.date} day={day} />
          ))}
        </div>
      )}
    </div>
  );
}

function DayGroup({ day }) {
  return (
    <div>
      {/* Day label */}
      <div style={{
        fontSize: "11px",
        color: "#666",
        fontWeight: "bold",
        letterSpacing: "0.06em",
        marginBottom: "6px",
        textTransform: "uppercase",
      }}>
        {day.label}
        <span style={{ color: "#444", fontWeight: "normal", marginLeft: "8px" }}>{day.date}</span>
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
        {day.alarms.map((alarm, idx) => (
          <HistoryRow key={idx} alarm={alarm} />
        ))}
      </div>
    </div>
  );
}

function HistoryRow({ alarm }) {
  const isActive    = alarm.status === "active";
  const accentColor = isActive ? ALERT_COLOR : RESOLVED_COLOR;
  const duration    = formatDuration(alarm.total_duration_seconds);
  const sev         = alarm.severity;

  // Time window: "10:22 – 11:47" or "10:22 – now"
  const timeStr = fmtTime(alarm.window_start) + " – " + (isActive ? "now" : fmtTime(alarm.window_end));

  // "started N days ago" annotation for multi-day sessions
  const sessionDay   = alarm.session_first_seen ? alarm.session_first_seen.slice(0, 10) : null;
  const windowDay    = alarm.window_start ? alarm.window_start.slice(0, 10) : null;
  const startedEarlier = sessionDay && windowDay && sessionDay < windowDay;

  const hs = alarm.health_score ?? null;
  const failureComponents = alarm.health_components
    ? Object.entries(alarm.health_components).filter(([, rate]) => rate > 0)
    : [];
  const wlanDisplay = alarm.wlan !== "__all__" ? alarm.wlan : alarm.predominant_wlan;

  return (
    <div style={{
      border: `1px solid ${accentColor}33`,
      borderLeft: `3px solid ${accentColor}`,
      background: isActive ? "#1a1010" : "#111",
      borderRadius: "4px",
      padding: "10px 12px",
      fontSize: "12px",
    }}>
      {/* Top row: status + family + site + time + duration */}
      <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: "8px" }}>
        {/* Status pip */}
        <span style={{ width: 7, height: 7, borderRadius: "50%", background: accentColor, flexShrink: 0 }} />

        {/* Family */}
        <span style={{ color: "#ccc", fontWeight: "bold", fontSize: "13px" }}>
          {alarm.family}
        </span>

        {/* Severity badge */}
        {sev && (
          <span style={{
            background: (ANOMALY_COLOR[sev] || "#888") + "22",
            color: ANOMALY_COLOR[sev] || "#888",
            border: `1px solid ${(ANOMALY_COLOR[sev] || "#888")}44`,
            borderRadius: "3px", padding: "1px 7px", fontSize: "10px",
          }}>
            {sev}
          </span>
        )}

        {/* Pattern */}
        {alarm.probable_pattern && (
          <span style={{ color: "#888", fontSize: "11px" }}>
            {PATTERN_LABELS[alarm.probable_pattern] || alarm.probable_pattern}
          </span>
        )}

        {/* WLAN badge */}
        {wlanDisplay && (
          <span style={{ background: "#1a2a1a", color: "#7aaa7a", border: "1px solid #3a6a3a", borderRadius: "3px", padding: "1px 6px", fontSize: "10px" }}>
            {wlanDisplay}
          </span>
        )}

        {/* Resolved / active badge */}
        {isActive ? (
          <span style={{ marginLeft: "auto", color: ALERT_COLOR, fontSize: "10px", fontWeight: "bold" }}>
            ACTIVE <span style={{ fontSize: "9px" }}>●</span>
          </span>
        ) : (
          <span style={{ marginLeft: "auto", color: RESOLVED_COLOR, fontSize: "10px", border: `1px solid ${RESOLVED_COLOR}55`, borderRadius: "3px", padding: "1px 6px" }}>
            resolved
          </span>
        )}
      </div>

      {/* Second row: site + time window + duration */}
      <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: "12px", marginTop: "6px" }}>
        <span style={{ color: "#7ec8e3", fontSize: "11px" }}>
          {alarm.site_name || alarm.site_id}
        </span>
        <span style={{ color: "#666", fontSize: "11px" }}>
          {timeStr}
        </span>
        <span style={{ color: isActive ? ALERT_COLOR : "#555", fontSize: "11px", fontWeight: isActive ? "bold" : "normal" }}>
          {duration}
        </span>
        {startedEarlier && (
          <span style={{ color: "#555", fontSize: "10px" }}>
            started {new Date(alarm.session_first_seen).toLocaleDateString([], { month: "short", day: "numeric" })}
          </span>
        )}
      </div>

      {/* Third row: device count + health score + failure breakdown */}
      {(alarm.affected_mac_count != null || hs != null) && (
        <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: "14px", marginTop: "6px" }}>
          {alarm.affected_mac_count != null && (
            <span style={{ fontSize: "11px" }}>
              <span style={{ color: "#555" }}>devices </span>
              <span style={{ color: sev ? (ANOMALY_COLOR[sev] || "#ccc") : "#ccc", fontWeight: "bold" }}>
                {alarm.affected_mac_count}
              </span>
              {alarm.total_mac_count != null && (
                <span style={{ color: "#444" }}>/{alarm.total_mac_count}</span>
              )}
              {alarm.outlier_ratio != null && (
                <span style={{ color: "#555" }}> ({(alarm.outlier_ratio * 100).toFixed(0)}%)</span>
              )}
            </span>
          )}
          {hs != null && (
            <span style={{ fontSize: "11px" }}>
              <span style={{ color: "#555" }}>health </span>
              <span style={{ color: healthScoreColor(hs), fontWeight: "bold" }}>
                {(hs * 100).toFixed(0)}%
              </span>
            </span>
          )}
          {failureComponents.map(([cat, rate]) => (
            <span key={cat} style={{ fontSize: "10px", color: rate > 0.1 ? HEALTH_COLOR : "#555" }}>
              {cat} {(rate * 100).toFixed(0)}% fail
            </span>
          ))}
        </div>
      )}

      {/* Top features */}
      {alarm.top_features?.length > 0 && (
        <div style={{ display: "flex", gap: "6px", flexWrap: "wrap", marginTop: "6px" }}>
          {alarm.top_features.map((f, fi) => (
            <span
              key={fi}
              title={`Outlier: ${f.outlier_mean?.toFixed(3)} vs baseline: ${f.baseline_mean?.toFixed(3)}`}
              style={{ background: "#1a1a1a", border: "1px solid #2a2a2a", borderRadius: "3px", padding: "2px 7px", fontSize: "10px", color: "#777" }}
            >
              {f.feature}
              {f.outlier_mean != null && f.baseline_mean != null && (
                <span style={{ color: sev ? (ANOMALY_COLOR[sev] || "#888") : "#888" }}>
                  {" "}↑{Math.abs(f.outlier_mean - f.baseline_mean).toFixed(3)}
                </span>
              )}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}
