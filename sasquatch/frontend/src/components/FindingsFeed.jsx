import { useState, useEffect, useCallback } from "react";
import { apiFetch } from "../api";
import FamilyDrilldown from "./FamilyDrilldown";

// Anomaly severity — green spectrum (anomalies alone are not actionable alerts)
const ANOMALY_COLOR = { significant: "#39e84e", moderate: "#2eb845", minimal: "#1a6b27" };
const ANOMALY_BG    = { significant: "#0d2a15", moderate: "#0b2210", minimal: "#09180a" };

// Alert state — anomalous AND unhealthy (dual-gate)
const ALERT_COLOR = "#e05555";
const ALERT_BG    = "#2a1515";

// Health state — unhealthy, not (yet) anomalous
const HEALTH_COLOR = "#e0a835";
const HEALTH_BG    = "#2a2015";

// Service-account virtual family
const SA_COLOR = "#d4a06a";
const SA_BG    = "#2a1f15";

// Default — overridden at runtime by general-config endpoint
const HEALTH_THRESHOLD_DEFAULT = 0.80;

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

function SectionHeader({ label, color, count, subtitle }) {
  return (
    <div style={{
      display: "flex",
      alignItems: "center",
      gap: "10px",
      marginBottom: "8px",
      marginTop: "18px",
      paddingBottom: "6px",
      borderBottom: `1px solid ${color}33`,
    }}>
      <span style={{
        background: color + "22",
        color: color,
        padding: "2px 10px",
        borderRadius: "3px",
        fontSize: "11px",
        fontWeight: "bold",
        letterSpacing: "0.08em",
        border: `1px solid ${color}44`,
      }}>
        {label}
      </span>
      <span style={{ color: "#444", fontSize: "11px" }}>{count} {count === 1 ? "family" : "families"}</span>
      {subtitle && <span style={{ color: "#333", fontSize: "11px" }}>· {subtitle}</span>}
    </div>
  );
}

// Dedicated alert card for the top-of-page SITE ALERTS section. Mirrors the
// shape of OrgAlerts.jsx's AlertCard so a site alert and an org alert look
// the same. Cross-references the separately-fetched site /health endpoint
// for health_score / components, since per-site finding records don't carry
// those fields directly.
function SiteAlertCard({ finding, healthData, onMacSelect, onFamilyClick }) {
  const sev = finding.severity;
  const hs  = healthData?.health_score ?? null;
  const components = healthData?.components ?? null;

  const failureComponents = components
    ? Object.entries(components).filter(([, rate]) => rate > 0)
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
            {finding.family_kind === "service_account" && finding.service_account_label
              ? finding.service_account_label
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
          <span style={{ color: "#666", fontSize: "12px" }}>
            {PATTERN_LABELS[finding.probable_pattern] || finding.probable_pattern}
          </span>
          {finding.wlan && (
            <span style={{ background: "#1a2a1a", color: "#7aaa7a", border: "1px solid #3a6a3a", borderRadius: "3px", padding: "2px 7px", fontSize: "10px" }}>
              {finding.wlan}
            </span>
          )}
          {finding.is_family_outlier && (
            <span style={{ background: "#2a1a3a", color: "#b06ad4", border: "1px solid #6a3a8a", borderRadius: "3px", padding: "2px 7px", fontSize: "10px" }}
              title="Centroid IF/distance: whole family's collective behavior differs from healthy reference">
              Centroid
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

      {/* Worst-health MACs — clickable since we're at site scope */}
      {finding.worst_health_macs?.length > 0 && (
        <div style={{ marginTop: "10px" }}>
          <div style={{ color: "#555", fontSize: "11px", marginBottom: "5px" }}>Worst-health devices</div>
          <div style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
            {finding.worst_health_macs.map(({ mac, health_score, health_components }) => {
              const worstCat = Object.entries(health_components || {}).sort(([, a], [, b]) => b - a)[0];
              return (
                <div key={mac} style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                  <button
                    onClick={() => onMacSelect(mac)}
                    style={{ background: "#1a1a2e", border: "1px solid #2a2a5e", color: "#7ec8e3", borderRadius: "3px", padding: "3px 10px", cursor: "pointer", fontSize: "12px", fontFamily: "monospace" }}
                  >
                    {mac}
                  </button>
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

function AnomalyFindingCard({ finding, healthData, onFamilyClick, healthThreshold }) {
  const sev        = finding.severity;
  const hs         = healthData?.health_score ?? null;
  const components = healthData?.components ?? null;
  const isUnhealthy = hs != null && hs < healthThreshold;
  const cardColor  = ANOMALY_COLOR[sev];
  const cardBg     = ANOMALY_BG[sev];

  // Failure reasons: only categories with > 0% failure rate
  const failureReasons = components
    ? Object.entries(components).filter(([, rate]) => rate > 0)
    : [];

  return (
    <div style={{
      border: `1px solid ${cardColor}44`,
      borderLeft: `3px solid ${cardColor}`,
      background: cardBg,
      borderRadius: "4px",
      padding: "12px 14px",
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
        <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: "6px" }}>
          <span style={{
            background: ANOMALY_COLOR[sev] + "33",
            color: ANOMALY_COLOR[sev],
            padding: "2px 8px",
            borderRadius: "3px",
            fontSize: "11px",
            fontWeight: "bold",
            border: `1px solid ${ANOMALY_COLOR[sev]}55`,
          }}>
            {sev}
          </span>
          <button
            onClick={onFamilyClick}
            style={{ fontWeight: "bold", fontSize: "14px", color: "#7ec8e3", background: "none", border: "none", cursor: "pointer", padding: 0, textDecoration: "underline", textDecorationColor: "#7ec8e344" }}
          >
            {finding.family_kind === "service_account" && finding.service_account_label
              ? finding.service_account_label
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
          <span style={{ color: "#666", fontSize: "12px" }}>
            {PATTERN_LABELS[finding.probable_pattern] || finding.probable_pattern}
          </span>
          {finding.wlan && (
            <span style={{ background: "#1a2a1a", color: "#7aaa7a", border: "1px solid #3a6a3a", borderRadius: "3px", padding: "2px 7px", fontSize: "10px" }}>
              {finding.wlan}
            </span>
          )}
          {finding.is_family_outlier && (
            <span style={{ background: "#2a1a3a", color: "#b06ad4", border: "1px solid #6a3a8a", borderRadius: "3px", padding: "2px 7px", fontSize: "10px" }}
              title="Centroid IF/distance: whole family's collective behavior differs from other families at this site">
              Centroid
            </span>
          )}
          {finding.is_family_dbscan_outlier && (
            <span style={{ background: "#1a2a1a", color: "#5ab86c", border: "1px solid #2a6a3a", borderRadius: "3px", padding: "2px 7px", fontSize: "10px" }}
              title={`DBSCAN: ${(finding.dbscan_family_noise_ratio * 100).toFixed(0)}% of family MACs are site-wide behavioral outliers`}>
              DBSCAN family
            </span>
          )}
          {finding.is_family_markov_outlier && (
            <span
              style={{ background: "#1a2a3a", color: "#4ab0e8", border: "1px solid #2a6a8a", borderRadius: "3px", padding: "2px 7px", fontSize: "10px" }}
              title={`Markov ${finding.markov_family_reason || "anomaly"}: ${finding.markov_family_anomalous_count}/${finding.markov_evaluatable_count} clients flagged${finding.markov_family_anomaly_ratio != null ? ` (${(finding.markov_family_anomaly_ratio * 100).toFixed(0)}%)` : ""}`}
            >
              Markov {finding.markov_family_reason || "chain"}
            </span>
          )}
          {isUnhealthy && (
            <span style={{ background: HEALTH_BG, color: HEALTH_COLOR, border: `1px solid ${HEALTH_COLOR}55`, borderRadius: "3px", padding: "2px 7px", fontSize: "10px" }}>
              unhealthy {(hs * 100).toFixed(0)}%
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
          {failureReasons.length > 0 && (
            <div style={{ marginTop: "3px", display: "flex", flexDirection: "column", alignItems: "flex-end", gap: "1px" }}>
              {failureReasons.map(([cat, rate]) => (
                <span key={cat} style={{ fontSize: "10px", color: rate > 0.1 ? HEALTH_COLOR : "#666", whiteSpace: "nowrap" }}>
                  {cat} {(rate * 100).toFixed(0)}% fail
                </span>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Top contributing features */}
      {finding.top_features?.length > 0 && (
        <div style={{ marginTop: "8px", display: "flex", gap: "6px", flexWrap: "wrap" }}>
          {finding.top_features.slice(0, 3).map((f, fi) => (
            <span
              key={fi}
              title={`Outlier mean: ${f.outlier_mean.toFixed(3)} vs baseline: ${f.baseline_mean.toFixed(3)}`}
              style={{ background: "#222", border: "1px solid #333", borderRadius: "3px", padding: "2px 7px", fontSize: "11px", color: "#999" }}
            >
              {f.feature} <span style={{ color: ANOMALY_COLOR[sev] }}>↑{(Math.abs(f.outlier_mean - f.baseline_mean)).toFixed(3)}</span>
            </span>
          ))}
        </div>
      )}

    </div>
  );
}

function HealthOnlyCard({ family, data }) {
  const hs = data.health_score;
  const hsColor = healthScoreColor(hs);
  return (
    <div style={{
      border: `1px solid ${HEALTH_COLOR}44`,
      borderLeft: `3px solid ${HEALTH_COLOR}`,
      background: HEALTH_BG,
      borderRadius: "4px",
      padding: "12px 14px",
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <span style={{ fontWeight: "bold", fontSize: "14px", color: "#ddd" }}>{family}</span>
          <span style={{ color: "#555", fontSize: "12px" }}>{data.mac_count || 0} devices · {(data.total_events || 0).toLocaleString()} events</span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <span style={{ fontSize: "11px", color: "#555" }}>health</span>
          <span style={{ fontSize: "13px", fontWeight: "bold", color: hsColor }}>
            {(hs * 100).toFixed(0)}%
          </span>
        </div>
      </div>
      {data.components && (
        <div style={{ marginTop: "8px", display: "flex", gap: "8px", flexWrap: "wrap" }}>
          {Object.entries(data.components).map(([cat, rate]) => (
            <span key={cat} style={{ fontSize: "10px", color: rate > 0.1 ? HEALTH_COLOR : "#444" }}>
              {cat} {(rate * 100).toFixed(0)}% fail
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

export default function FindingsFeed({ siteId, apiBase, onMacSelect, refreshToken, wlan, detectionInProgress }) {
  const [findings, setFindings] = useState([]);
  const [health, setHealth]     = useState({});
  const [healthThreshold, setHealthThreshold] = useState(HEALTH_THRESHOLD_DEFAULT);
  const [alarmMinFamilySize, setAlarmMinFamilySize] = useState(1);
  const [loading, setLoading]   = useState(true);
  const [error, setError]       = useState(null);
  const [selectedFamily, setSelectedFamily] = useState(null);

  useEffect(() => {
    // Both anomaly_health_score_threshold and alarm_min_family_size live under
    // general config — they gate alarm generation, not detection itself.
    apiFetch(`${apiBase}/api/v1/general-config`).then(r => r.json())
      .then(cfg => {
        if (cfg.anomaly_health_score_threshold != null) setHealthThreshold(cfg.anomaly_health_score_threshold);
        if (cfg.alarm_min_family_size != null) setAlarmMinFamilySize(cfg.alarm_min_family_size);
      })
      .catch(() => {});
  }, [apiBase]);

  const load = useCallback(() => {
    Promise.all([
      apiFetch(`${apiBase}/api/v1/sites/${siteId}/findings?wlan=${encodeURIComponent(wlan)}`).then(r => r.json()),
      apiFetch(`${apiBase}/api/v1/sites/${siteId}/health?wlan=${encodeURIComponent(wlan)}`).then(r => r.json()),
    ])
      .then(([findingsData, healthData]) => {
        setFindings(findingsData.findings || []);
        setHealth(healthData.health || {});
        setError(null);
      })
      .catch(e => setError(e.message))
      .finally(() => setLoading(false));
  }, [siteId, apiBase, wlan]);

  useEffect(() => {
    load();
    const interval = setInterval(load, 30_000);
    return () => clearInterval(interval);
  }, [load, refreshToken]);

  if (selectedFamily) {
    return (
      <FamilyDrilldown
        siteId={siteId}
        family={selectedFamily}
        apiBase={apiBase}
        onMacSelect={onMacSelect}
        onBack={() => setSelectedFamily(null)}
        wlan={wlan}
      />
    );
  }

  if (loading) return <div style={{ color: "#888" }}>Loading findings…</div>;
  if (error)   return <div style={{ color: "#e05555" }}>Error: {error}</div>;

  // Cross-reference findings against the separately-fetched health data by device_family.
  // Per-site findings may not have health_score embedded — health endpoint is authoritative.
  const familyHealth      = (family) => health[family] ?? null;
  const familyHealthScore = (family) => health[family]?.health_score ?? 1.0;
  const familyServiceAlarms = (family) => health[family]?.service_alarms ?? [];

  // Split findings into alerts (matches backend site-alert gate in get_org_alerts)
  // and the rest. Alerts float to the top as dedicated SITE ALERTS cards; remaining
  // findings render in the unified flat list below. Within each bucket, sort by
  // severity then outlier_ratio.
  //
  // Site-alert gate mirrors routes.py:get_org_alerts:
  //   (health_score < threshold OR service_alarms non-empty)
  //   AND total_mac_count >= alarm_min_family_size
  // No is_family_outlier requirement — any finding in the list is already anomalous
  // (centroid, DBSCAN, or Markov). Gating only on centroid would drop Markov-driven
  // alerts that the backend flags at org level.
  const SEVERITY_RANK = { significant: 0, moderate: 1, minimal: 2 };
  const sortFindings = (arr) => [...arr].sort((a, b) => {
    const aSev = SEVERITY_RANK[a.severity] ?? 99;
    const bSev = SEVERITY_RANK[b.severity] ?? 99;
    if (aSev !== bSev) return aSev - bSev;
    return (b.outlier_ratio ?? 0) - (a.outlier_ratio ?? 0);
  });
  const isAlertFinding = (f) => {
    const unhealthy =
      familyHealthScore(f.device_family) < healthThreshold
      || familyServiceAlarms(f.device_family).length > 0;
    const meetsFloor = (f.total_mac_count ?? 0) >= alarmMinFamilySize;
    return unhealthy && meetsFloor;
  };
  const alertFindings    = sortFindings(findings.filter(isAlertFinding));
  const sortedFindings   = sortFindings(findings.filter(f => !isAlertFinding(f)));

  // GENERAL HEALTH: unhealthy families NOT triggering any anomaly finding
  const findingFamilies = new Set(findings.map(f => f.device_family));
  const healthOnlyFamilies = Object.entries(health)
    .filter(([fam, data]) => data.health_score < healthThreshold && !findingFamilies.has(fam))
    .sort(([, a], [, b]) => a.health_score - b.health_score);

  const hasAnything = alertFindings.length > 0 || sortedFindings.length > 0 || healthOnlyFamilies.length > 0;

  if (!hasAnything) {
    return <div style={{ color: "#2d7a4f", padding: "20px" }}>No anomalies detected. All device families behaving normally.</div>;
  }

  return (
    <div>
      {detectionInProgress && (
        <div style={{ background: "#0d2a38", border: "1px solid #2d5a8a", borderRadius: "4px", padding: "6px 12px", marginBottom: "10px", fontSize: "11px", color: "#7ec8e3" }}>
          Detection in progress… results will refresh automatically.
        </div>
      )}
      <h2 style={{ fontSize: "15px", color: "#aaa", marginBottom: "4px" }}>
        Anomaly Findings — {findings.length} active
        {alertFindings.length > 0 && (
          <span style={{ marginLeft: "10px", background: ALERT_BG, color: ALERT_COLOR, padding: "2px 8px", borderRadius: "3px", fontSize: "11px" }}>
            {alertFindings.length} {alertFindings.length === 1 ? "alert" : "alerts"}
          </span>
        )}
      </h2>

      {/* SITE ALERTS — dual-gate (is_family_outlier + unhealthy) lifted to the top */}
      {alertFindings.length > 0 && (
        <div>
          <SectionHeader
            label="SITE ALERTS"
            color={ALERT_COLOR}
            count={alertFindings.length}
            subtitle="device families anomalous and unhealthy at this site"
          />
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(480px, 1fr))", gap: "10px" }}>
            {alertFindings.map((finding, idx) => (
              <SiteAlertCard
                key={`alert-${idx}`}
                finding={finding}
                healthData={familyHealth(finding.device_family)}
                onMacSelect={onMacSelect}
                onFamilyClick={() => setSelectedFamily(finding.device_family)}
              />
            ))}
          </div>
        </div>
      )}

      {sortedFindings.length > 0 && (
        <div>
          <SectionHeader
            label="SITE ANOMALIES"
            color={ANOMALY_COLOR.moderate}
            count={sortedFindings.length}
            subtitle="device families behaving unusually but not unhealthy"
          />
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(480px, 1fr))", gap: "10px" }}>
            {sortedFindings.map((finding, idx) => (
              <AnomalyFindingCard
                key={`f-${idx}`}
                finding={finding}
                healthData={familyHealth(finding.device_family)}
                onFamilyClick={() => setSelectedFamily(finding.device_family)}
                healthThreshold={healthThreshold}
              />
            ))}
          </div>
        </div>
      )}

      {/* GENERAL HEALTH — unhealthy families not triggering a behavioral anomaly */}
      {healthOnlyFamilies.length > 0 && (
        <div>
          <SectionHeader label="GENERAL HEALTH" color={HEALTH_COLOR} count={healthOnlyFamilies.length} />
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(480px, 1fr))", gap: "10px" }}>
            {healthOnlyFamilies.map(([fam, data]) => (
              <HealthOnlyCard key={fam} family={fam} data={data} />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
