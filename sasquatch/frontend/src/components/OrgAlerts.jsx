import { useState, useEffect, useCallback } from "react";
import { apiFetch } from "../api";
import OrgFamilyDrilldown from "./OrgFamilyDrilldown";
import FamilyDrilldown from "./FamilyDrilldown";

const ALERT_COLOR = "#e05555";
const ALERT_BG    = "#2a1515";
const ANOMALY_COLOR = { significant: "#39e84e", moderate: "#2eb845", minimal: "#1a6b27" };
const HEALTH_COLOR  = "#e0a835";
const SA_COLOR     = "#d4a06a";
const SA_BG        = "#2a1f15";
const MFG_COLOR    = "#5ab5c8";
const MFG_BG       = "#13272a";

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
          <button
            onClick={onFamilyClick}
            style={{ fontWeight: "bold", fontSize: "14px", color: "#7ec8e3", background: "none", border: "none", cursor: "pointer", padding: 0, textDecoration: "underline", textDecorationColor: "#7ec8e344" }}
          >
            {finding.family_kind === "service_account"
              ? finding.service_account_label
              : finding.family_kind === "mfg_rollup"
              ? finding.mfg_rollup_label
              : finding.device_family}
          </button>
          {finding.family_kind === "service_account" && (
            <span
              style={{ background: SA_BG, color: SA_COLOR, border: `1px solid ${SA_COLOR}55`, borderRadius: "3px", padding: "2px 7px", fontSize: "10px", fontWeight: "bold", letterSpacing: "0.05em" }}
              title={
                finding.service_account_member_families?.length
                  ? `Service account spanning: ${finding.service_account_member_families.join(", ")}`
                  : "Service account (shared username across multiple devices)"
              }
            >
              SVC ACCT{finding.service_account_member_families?.length ? ` · ${finding.service_account_member_families.length} families` : ""}
            </span>
          )}
          {finding.family_kind === "mfg_rollup" && (
            <span
              style={{ background: MFG_BG, color: MFG_COLOR, border: `1px solid ${MFG_COLOR}55`, borderRadius: "3px", padding: "2px 7px", fontSize: "10px", fontWeight: "bold", letterSpacing: "0.05em" }}
              title={
                finding.mfg_rollup_member_families?.length
                  ? `Manufacturer rollup — aggregates ${finding.mfg_rollup_member_families.length} per-fingerprint families: ${finding.mfg_rollup_member_families.join(", ")}`
                  : "Manufacturer rollup (aggregates every MAC of this manufacturer regardless of fingerprint depth)"
              }
            >
              MFG ROLLUP{finding.mfg_rollup_member_families?.length ? ` · ${finding.mfg_rollup_member_families.length} families` : ""}
            </span>
          )}
          <span style={{ color: "#666", fontSize: "12px" }}>
            {PATTERN_LABELS[finding.probable_pattern] || finding.probable_pattern}
          </span>
          {finding.wlan && (
            <span style={{ background: "#1a2a1a", color: "#7aaa7a", border: "1px solid #3a6a3a", borderRadius: "3px", padding: "2px 7px", fontSize: "10px" }}
              title={`WLAN: ${finding.wlan}`}>
              {finding.wlan}
            </span>
          )}
          {finding.is_family_outlier && (
            <span style={{ background: "#2a1a3a", color: "#b06ad4", border: "1px solid #6a3a8a", borderRadius: "3px", padding: "2px 7px", fontSize: "10px" }}
              title="Family cosine distance: whole family's collective behavior differs from other families">
              Family
            </span>
          )}
          {finding.is_family_dbscan_outlier && (
            <span style={{ background: "#1a2a1a", color: "#5ab86c", border: "1px solid #2a6a3a", borderRadius: "3px", padding: "2px 7px", fontSize: "10px" }}
              title={`DBSCAN: ${finding.dbscan_family_noise_ratio != null ? (finding.dbscan_family_noise_ratio * 100).toFixed(0) + "%" : ""} of family MACs are site-wide behavioral outliers`}>
              DBSCAN {finding.dbscan_family_noise_ratio != null ? `${(finding.dbscan_family_noise_ratio * 100).toFixed(0)}%` : ""}
            </span>
          )}
          {finding.is_family_markov_outlier && (
            <span style={{ background: "#1a2a3a", color: "#4ab0e8", border: "1px solid #2a6a8a", borderRadius: "3px", padding: "2px 7px", fontSize: "10px" }}
              title={`Markov ${finding.markov_family_reason || "anomaly"}: ${finding.markov_family_anomalous_count ?? ""}/${finding.markov_evaluatable_count ?? ""} clients flagged${finding.markov_family_anomaly_ratio != null ? ` (${(finding.markov_family_anomaly_ratio * 100).toFixed(0)}%)` : ""}`}>
              Markov {finding.markov_family_reason || "chain"}
            </span>
          )}
        </div>
        <div style={{ textAlign: "right", fontSize: "12px", marginLeft: "10px", flexShrink: 0 }}>
          <div style={{ whiteSpace: "nowrap" }}>
            <span style={{ color: "#ccc", fontWeight: "bold" }}>
              {finding.affected_mac_count}/{finding.total_mac_count}
            </span>
            <span style={{ color: "#555" }}> devices</span>
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

      {/* Worst-health MACs */}
      {finding.worst_health_macs?.length > 0 && (
        <div style={{ marginTop: "8px" }}>
          <div style={{ color: "#555", fontSize: "10px", marginBottom: "4px" }}>Worst-health devices</div>
          <div style={{ display: "flex", flexDirection: "column", gap: "3px" }}>
            {finding.worst_health_macs.map(({ mac, health_score, health_components }) => {
              const worstCat = Object.entries(health_components || {}).sort(([, a], [, b]) => b - a)[0];
              return (
                <div key={mac} style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                  <span style={{ fontFamily: "monospace", fontSize: "11px", color: "#7ec8e3" }}>{mac}</span>
                  <span style={{ color: healthScoreColor(health_score), fontSize: "11px", fontWeight: "bold" }}>
                    {(health_score * 100).toFixed(0)}%
                  </span>
                  {worstCat && (
                    <span style={{ color: "#666", fontSize: "10px" }}>
                      {worstCat[0]} {(worstCat[1] * 100).toFixed(0)}% fail
                    </span>
                  )}
                </div>
              );
            })}
          </div>
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
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(480px, 1fr))", gap: "8px" }}>
        {siteAlert.alerts.map((alert, idx) => (
          <AlertCard
            key={`${siteAlert.site_id}-${idx}`}
            finding={alert}
            onFamilyClick={() => onFamilyClick(alert.device_family, siteAlert.site_id, alert.wlan)}
          />
        ))}
      </div>
    </div>
  );
}

export default function OrgAlerts({ apiBase, onMacSiteSelect, refreshToken, wlan, detectionInProgress }) {
  const [data, setData]               = useState(null);
  const [loading, setLoading]         = useState(true);
  const [error, setError]             = useState(null);
  // Site Alerts section is collapsed by default. State is kept in this component
  // so 30s auto-refreshes preserve the user's expanded/collapsed choice.
  const [siteAlertsExpanded, setSiteAlertsExpanded] = useState(false);
  // selectedFamily: { family, siteId } — siteId null means org-wide drilldown
  const [selectedFamily, setSelectedFamily] = useState(null);

  const load = useCallback(() => {
    setLoading(true);
    apiFetch(`${apiBase}/api/v1/org/alerts-full`)
      .then(r => r.json())
      .then(alertData => {
        setData(alertData);
        setError(null);
      })
      .catch(e => setError(e.message))
      .finally(() => setLoading(false));
  }, [apiBase]);

  useEffect(() => {
    load();
  }, [load, refreshToken]);

  if (selectedFamily) {
    // Each alert carries its own wlan — use that for drilldown so the
    // per-finding details match the row the user clicked. Fall back to the
    // app-level wlan prop if the alert somehow lacks one.
    const drilldownWlan = selectedFamily.wlan || wlan;
    if (selectedFamily.siteId) {
      return (
        <FamilyDrilldown
          siteId={selectedFamily.siteId}
          family={selectedFamily.family}
          apiBase={apiBase}
          onMacSelect={(mac) => onMacSiteSelect(mac, selectedFamily.siteId)}
          onBack={() => setSelectedFamily(null)}
          wlan={drilldownWlan}
        />
      );
    }
    return (
      <OrgFamilyDrilldown
        family={selectedFamily.family}
        apiBase={apiBase}
        onMacSiteSelect={onMacSiteSelect}
        onBack={() => setSelectedFamily(null)}
        wlan={drilldownWlan}
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
      {detectionInProgress && (
        <div style={{ background: "#0d2a38", border: "1px solid #2d5a8a", borderRadius: "4px", padding: "6px 12px", marginBottom: "10px", fontSize: "11px", color: "#7ec8e3" }}>
          Detection in progress… results will refresh automatically.
        </div>
      )}
      <div style={{ marginBottom: "4px" }}>
        <h2 style={{ fontSize: "15px", color: "#aaa", margin: 0 }}>
          Full Alert Summary
          <span style={{ marginLeft: "10px", color: "#555", fontSize: "11px", fontWeight: "normal" }}>
            aggregated across all WLANs
          </span>
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

      {orgAlerts.length === 0 && (
        <div style={{
          background: "#12241a",
          border: "1px solid #2d7a4f",
          borderLeft: "3px solid #2d7a4f",
          color: "#7dd49c",
          borderRadius: "4px",
          padding: "10px 14px",
          marginTop: "10px",
          marginBottom: "6px",
          fontSize: "13px",
          fontWeight: "bold",
        }}>
          No Org Alarms active
        </div>
      )}

      {/* Org-wide alerts */}
      {orgAlerts.length > 0 && (
        <div>
          <SectionHeader
            label="ORG-WIDE ALERTS"
            count={orgAlerts.length}
            subtitle="device families anomalous and unhealthy across the organization"
          />
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(480px, 1fr))", gap: "10px" }}>
            {orgAlerts.map((finding, idx) => (
              <AlertCard
                key={`org-${idx}`}
                finding={finding}
                onFamilyClick={() => setSelectedFamily({ family: finding.device_family, siteId: null, wlan: finding.wlan })}
              />
            ))}
          </div>
        </div>
      )}

      {/* Per-site alerts */}
      {siteAlerts.length > 0 && (
        <div>
          <div
            onClick={() => setSiteAlertsExpanded(e => !e)}
            style={{
              display: "flex",
              alignItems: "center",
              gap: "10px",
              marginBottom: siteAlertsExpanded ? "10px" : 0,
              marginTop: "24px",
              paddingBottom: "6px",
              borderBottom: `1px solid ${ALERT_COLOR}33`,
              cursor: "pointer",
              userSelect: "none",
            }}
          >
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
              SITE ALERTS ({totalSiteAlertFamilies})
            </span>
            <span style={{ color: "#444", fontSize: "11px" }}>
              {siteAlerts.length} {siteAlerts.length === 1 ? "site" : "sites"} · {totalSiteAlertFamilies} {totalSiteAlertFamilies === 1 ? "family" : "families"}
            </span>
            <span style={{ color: "#333", fontSize: "11px" }}>· device families anomalous and unhealthy at a specific site</span>
            <span style={{ color: "#444", fontSize: "11px", marginLeft: "auto" }}>
              {siteAlertsExpanded ? "▲" : "▼"}
            </span>
          </div>
          {siteAlertsExpanded && (
            <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
              {siteAlerts.map(siteAlert => (
                <SiteAlertGroup
                  key={siteAlert.site_id}
                  siteAlert={siteAlert}
                  onFamilyClick={(family, siteId, alertWlan) => setSelectedFamily({ family, siteId, wlan: alertWlan })}
                />
              ))}
            </div>
          )}
        </div>
      )}

    </div>
  );
}
