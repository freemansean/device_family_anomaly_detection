import { useState, useEffect, useCallback } from "react";
import { apiFetch } from "../api";
import OrgFamilyDrilldown from "./OrgFamilyDrilldown";

// Anomaly severity — green spectrum (anomalies alone are not actionable alerts)
const ANOMALY_COLOR = { significant: "#39e84e", moderate: "#2eb845", minimal: "#1a6b27" };
const ANOMALY_BG    = { significant: "#0d2a15", moderate: "#0b2210", minimal: "#09180a" };

// Alert state — anomalous AND unhealthy (dual-gate)
const ALERT_COLOR = "#e05555";
const ALERT_BG    = "#2a1515";

// Health state — unhealthy, not anomalous
const HEALTH_COLOR = "#e0a835";
const HEALTH_BG    = "#2a2015";

// Default — overridden at runtime by anomaly-config endpoint
const HEALTH_THRESHOLD_DEFAULT = 0.75;

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

function healthScoreColor(score) {
  if (score >= 0.85) return "#2d7a4f";
  if (score >= 0.75) return "#e0a835";
  if (score >= 0.55) return "#c87832";
  return "#e05555";
}

function SectionHeader({ label, color, count }) {
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
    </div>
  );
}

function AnomalyFindingCard({ finding, healthComponents, isAlert, onFamilyClick, healthThreshold }) {
  const sev        = finding.severity;
  // Org findings carry health_score on the finding object; components come from family-insights
  const hs         = finding.health_score ?? null;
  const isUnhealthy = hs != null && hs < healthThreshold;
  const cardColor  = isAlert ? ALERT_COLOR : ANOMALY_COLOR[sev];
  const cardBg     = isAlert ? ALERT_BG    : ANOMALY_BG[sev];

  const failureReasons = healthComponents
    ? Object.entries(healthComponents).filter(([, rate]) => rate > 0)
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
          {isAlert && (
            <span style={{ background: ALERT_COLOR + "33", color: ALERT_COLOR, padding: "2px 8px", borderRadius: "3px", fontSize: "11px", fontWeight: "bold", border: `1px solid ${ALERT_COLOR}55` }}>
              ALERT
            </span>
          )}
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
            {finding.device_family}
          </button>
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
              title="Centroid IF/distance: whole family's collective behavior differs from other families">
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
              title={`Markov: ${finding.markov_family_anomalous_count}/${finding.markov_evaluatable_count} clients have anomalous event chain patterns`}>
              Markov {finding.markov_family_anomaly_ratio != null ? `${(finding.markov_family_anomaly_ratio * 100).toFixed(0)}%` : ""}
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

      {/* Site attribution */}
      <div style={{ marginTop: "5px", fontSize: "11px", color: "#557799" }}>
        {finding.sites_affected?.length > 1
          ? finding.sites_affected.map(sa => sa.site_name || sa.site_id).join(" · ")
          : (finding.sites_affected?.[0]?.site_name || finding.sites_affected?.[0]?.site_id || "")}
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
          <span style={{ color: "#555", fontSize: "12px" }}>
            {data.client_count != null ? `${data.client_count} devices` : ""}
            {data.site_count != null ? ` · ${data.site_count} sites` : ""}
          </span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <span style={{ fontSize: "11px", color: "#555" }}>health</span>
          <span style={{ fontSize: "13px", fontWeight: "bold", color: hsColor }}>
            {(hs * 100).toFixed(0)}%
          </span>
        </div>
      </div>
      {data.health_components && (
        <div style={{ marginTop: "8px", display: "flex", gap: "8px", flexWrap: "wrap" }}>
          {Object.entries(data.health_components).map(([cat, rate]) => (
            <span key={cat} style={{ fontSize: "10px", color: rate > 0.1 ? HEALTH_COLOR : "#444" }}>
              {cat} {(rate * 100).toFixed(0)}% fail
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

export default function OrgFindingsFeed({ apiBase, onMacSiteSelect, refreshToken, wlan }) {
  const [findings, setFindings]         = useState([]);
  const [familyInsights, setInsights]   = useState({});
  const [healthThreshold, setHealthThreshold] = useState(HEALTH_THRESHOLD_DEFAULT);
  const [loading, setLoading]           = useState(true);
  const [error, setError]               = useState(null);
  const [selectedFamily, setSelectedFamily] = useState(null);

  useEffect(() => {
    apiFetch(`${apiBase}/api/v1/anomaly-config`).then(r => r.json())
      .then(cfg => { if (cfg.anomaly_health_score_threshold != null) setHealthThreshold(cfg.anomaly_health_score_threshold); })
      .catch(() => {});
  }, [apiBase]);

  const load = useCallback(() => {
    Promise.all([
      apiFetch(`${apiBase}/api/v1/org/findings?wlan=${encodeURIComponent(wlan)}`).then(r => r.json()),
      apiFetch(`${apiBase}/api/v1/org/family-insights?wlan=${encodeURIComponent(wlan)}`).then(r => r.json()),
    ])
      .then(([findingsData, insightsData]) => {
        setFindings(findingsData.findings || []);
        setInsights(insightsData.families || {});
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
    return (
      <OrgFamilyDrilldown
        family={selectedFamily}
        apiBase={apiBase}
        onMacSiteSelect={onMacSiteSelect}
        onBack={() => setSelectedFamily(null)}
        wlan={wlan}
      />
    );
  }

  if (loading) return <div style={{ color: "#888" }}>Loading findings…</div>;
  if (error)   return <div style={{ color: "#e05555" }}>Error: {error}</div>;

  // Partition findings into 4 detector classes (priority order to avoid duplication)
  // IF Centroid: whole-family centroid flagged by IF/cosine-distance
  const ifCentroidFindings = findings.filter(f => f.is_family_outlier);
  // DBSCAN: family noise ratio above threshold, not already in IF Centroid
  const dbscanFindings     = findings.filter(f => f.is_family_dbscan_outlier && !f.is_family_outlier);
  // Markov: family event-chain anomaly ratio above threshold, not already in IF or DBSCAN
  const markovFindings     = findings.filter(f => f.is_family_markov_outlier && !f.is_family_outlier && !f.is_family_dbscan_outlier);
  // Catch-all for findings driven by per-MAC IF without a family-level flag (fold into IF section)
  const ifDeviceFindings   = findings.filter(f => !f.is_family_outlier && !f.is_family_dbscan_outlier && !f.is_family_markov_outlier);
  const ifSectionFindings  = [...ifCentroidFindings, ...ifDeviceFindings];

  // GENERAL HEALTH: unhealthy families from org insights NOT in any anomaly finding
  const findingFamilies = new Set(findings.map(f => f.device_family));
  const healthOnlyFamilies = Object.entries(familyInsights)
    .filter(([fam, data]) =>
      data.health_score != null &&
      data.health_score < healthThreshold &&
      !findingFamilies.has(fam)
    )
    .sort(([, a], [, b]) => a.health_score - b.health_score);

  const hasAnything = ifSectionFindings.length > 0 || dbscanFindings.length > 0 || markovFindings.length > 0 || healthOnlyFamilies.length > 0;

  if (!hasAnything) {
    return <div style={{ color: "#2d7a4f", padding: "20px" }}>No anomalies detected across the organization.</div>;
  }

  const IF_COLOR     = "#b06ad4";
  const DBSCAN_COLOR = "#5ab86c";
  const MARKOV_COLOR = "#4ab0e8";

  function renderFindingCards(list, prefix) {
    return list.map((finding, idx) => (
      <AnomalyFindingCard
        key={`${prefix}-${idx}`}
        finding={finding}
        healthComponents={familyInsights[finding.device_family]?.health_components ?? null}
        isAlert={(finding.health_score ?? 1.0) < healthThreshold}
        healthThreshold={healthThreshold}
        onFamilyClick={() => setSelectedFamily(finding.device_family)}
      />
    ));
  }

  return (
    <div>
      <h2 style={{ fontSize: "15px", color: "#aaa", marginBottom: "4px" }}>
        Org Anomaly Findings — {findings.length} active
      </h2>

      {/* IF CENTROID — whole-family centroid outlier (+ per-device IF catch-all) */}
      {ifSectionFindings.length > 0 && (
        <div>
          <SectionHeader label="CENTROID" color={IF_COLOR} count={ifSectionFindings.length} />
          <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
            {renderFindingCards(ifSectionFindings, "if")}
          </div>
        </div>
      )}

      {/* DBSCAN — % of device family are site-wide behavioral outliers */}
      {dbscanFindings.length > 0 && (
        <div>
          <SectionHeader label="DBSCAN" color={DBSCAN_COLOR} count={dbscanFindings.length} />
          <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
            {renderFindingCards(dbscanFindings, "dbscan")}
          </div>
        </div>
      )}

      {/* MARKOV — % of device family have anomalous event-chain patterns */}
      {markovFindings.length > 0 && (
        <div>
          <SectionHeader label="MARKOV" color={MARKOV_COLOR} count={markovFindings.length} />
          <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
            {renderFindingCards(markovFindings, "markov")}
          </div>
        </div>
      )}

      {/* GENERAL HEALTH — unhealthy families not triggering a behavioral anomaly */}
      {healthOnlyFamilies.length > 0 && (
        <div>
          <SectionHeader label="GENERAL HEALTH" color={HEALTH_COLOR} count={healthOnlyFamilies.length} />
          <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
            {healthOnlyFamilies.map(([fam, data]) => (
              <HealthOnlyCard key={fam} family={fam} data={data} />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
