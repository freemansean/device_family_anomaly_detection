import { useState, useEffect, useCallback } from "react";
import { apiFetch } from "../api";
import OrgFamilyDrilldown from "./OrgFamilyDrilldown";
import FamilyDrilldown from "./FamilyDrilldown";

const ALERT_COLOR = "#e05555";
const ALERT_BG    = "#2a1515";
const ANOMALY_COLOR = { significant: "#39e84e", moderate: "#2eb845", minimal: "#1a6b27" };
const ANOMALY_BG    = { significant: "#0d2a15", moderate: "#0b2210", minimal: "#09180a" };
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
  // selectedFamily: { family, siteId } — siteId null means org-wide drilldown
  const [selectedFamily, setSelectedFamily] = useState(null);

  const load = useCallback(() => {
    setLoading(true);
    apiFetch(`${apiBase}/api/v1/org/alerts?wlan=${encodeURIComponent(wlan)}`)
      .then(r => r.json())
      .then(d => { setData(d); setError(null); })
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
    </div>
  );
}
