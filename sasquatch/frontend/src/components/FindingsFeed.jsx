import { useState, useEffect, useCallback } from "react";
import { apiFetch } from "../api";

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

// Default — overridden at runtime by anomaly-config endpoint
const HEALTH_THRESHOLD_DEFAULT = 0.75;

function shapleyScoreFromCentroidDist(dist) {
  // Cosine distance on L2-normalized unit vectors ranges 0 (identical) to 2 (opposite).
  // In practice healthy families sit near 0 and flagged families exceed ~0.35.
  // Map linearly to 0–100 with 0 dist → 0 and 1.0 dist → 100.
  if (dist == null) return null;
  return Math.max(0, Math.min(100, Math.round(dist * 100)));
}

function shapleyColor(score) {
  if (score >= 60) return ANOMALY_COLOR.significant;
  if (score >= 35) return ANOMALY_COLOR.moderate;
  return ANOMALY_COLOR.minimal;
}

function healthScoreColor(score) {
  if (score >= 0.85) return "#2d7a4f";
  if (score >= 0.75) return "#e0a835";
  if (score >= 0.55) return "#c87832";
  return "#e05555";
}

function ShapleyBlock({ label, score, features, description }) {
  const color = score != null ? shapleyColor(score) : "#666";
  return (
    <div style={{
      background: "#0e0e0e",
      border: `1px solid ${color}33`,
      borderLeft: `3px solid ${color}`,
      borderRadius: "3px",
      padding: "10px 12px",
      marginBottom: "10px",
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: "12px", marginBottom: "6px" }}>
        <span style={{ fontSize: "11px", color: "#666", fontWeight: "normal", textTransform: "uppercase", letterSpacing: "0.06em" }}>
          {label}
        </span>
        {score != null && (
          <div style={{ display: "flex", alignItems: "center", gap: "8px", flex: 1 }}>
            <div style={{ flex: 1, height: "6px", background: "#1a1a1a", borderRadius: "3px", overflow: "hidden" }}>
              <div style={{ width: `${score}%`, height: "100%", background: color, borderRadius: "3px", transition: "width 0.4s ease" }} />
            </div>
            <span style={{ fontSize: "13px", fontWeight: "bold", color, minWidth: "36px", textAlign: "right" }}>
              {score}<span style={{ fontSize: "10px", color: "#555" }}>/100</span>
            </span>
          </div>
        )}
        {score == null && (
          <span style={{ fontSize: "11px", color: "#444" }}>score unavailable</span>
        )}
      </div>
      {description && (
        <div style={{ fontSize: "11px", color: "#555", marginBottom: features?.length > 0 ? "6px" : 0 }}>
          {description}
        </div>
      )}
      {features?.length > 0 && (
        <div style={{ display: "flex", flexDirection: "column", gap: "3px" }}>
          {features.slice(0, 4).map((f, i) => {
            const delta = Math.abs(f.outlier_mean - f.baseline_mean);
            const barWidth = Math.min(delta * 400, 100);
            return (
              <div key={i} style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <span style={{ fontSize: "10px", color: "#777", width: "220px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flexShrink: 0 }}
                  title={f.feature}>
                  {f.feature}
                </span>
                <div style={{ flex: 1, height: "5px", background: "#1a1a1a", borderRadius: "2px", overflow: "hidden" }}>
                  <div style={{ width: `${barWidth}%`, height: "100%", background: color + "99", borderRadius: "2px" }} />
                </div>
                <span style={{ fontSize: "10px", color: color, minWidth: "42px", textAlign: "right" }}>
                  +{delta.toFixed(3)}
                </span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
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

function AnomalyFindingCard({ finding, healthData, isAlert, expanded, onToggle, onMacSelect, healthThreshold }) {
  const sev        = finding.severity;
  const hs         = healthData?.health_score ?? null;
  const components = healthData?.components ?? null;
  const isUnhealthy = hs != null && hs < healthThreshold;
  const cardColor  = isAlert ? ALERT_COLOR : ANOMALY_COLOR[sev];
  const cardBg     = isAlert ? ALERT_BG    : ANOMALY_BG[sev];

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
          <span style={{ fontWeight: "bold", fontSize: "14px", color: "#ddd" }}>
            {finding.family_kind === "service_account" && finding.service_account_label
              ? finding.service_account_label
              : finding.device_family}
          </span>
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

      <div style={{ marginTop: "10px" }}>
        <ShapleyBlock
          label="Device Family Behavior Explanation"
          score={shapleyScoreFromCentroidDist(finding.centroid_dist_score)}
          features={finding.top_features}
          description={
            finding.centroid_dist_score != null
              ? `Cosine distance from healthy reference ${finding.centroid_dist_score.toFixed(4)} — measures how far this family's collective behavior sits from the healthy-family centroid.`
              : finding.is_family_outlier
                ? "This family's collective behavior is flagged as anomalous relative to the healthy-family reference."
                : "Anomaly driven by individual device deviations within the family."
          }
        />
      </div>

      {isAlert && finding.worst_health_macs?.length > 0 ? (
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
      ) : (
        <>
          <button
            onClick={onToggle}
            style={{ background: "transparent", border: "none", color: "#555", cursor: "pointer", padding: "6px 0 0 0", fontSize: "12px" }}
          >
            {expanded ? "▲ Hide affected MACs" : `▼ Show ${finding.example_macs?.length || 0} example MACs`}
          </button>

          {expanded && finding.example_macs?.length > 0 && (
            <div style={{ marginTop: "6px", display: "flex", gap: "6px", flexWrap: "wrap" }}>
              {finding.example_macs.map((mac) => (
                <button
                  key={mac}
                  onClick={() => onMacSelect(mac)}
                  style={{ background: "#1a1a2e", border: "1px solid #2a2a5e", color: "#7ec8e3", borderRadius: "3px", padding: "3px 10px", cursor: "pointer", fontSize: "12px", fontFamily: "monospace" }}
                >
                  {mac}
                </button>
              ))}
            </div>
          )}
        </>
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
  const [loading, setLoading]   = useState(true);
  const [error, setError]       = useState(null);
  const [expanded, setExpanded] = useState({});

  useEffect(() => {
    apiFetch(`${apiBase}/api/v1/anomaly-config`).then(r => r.json())
      .then(cfg => { if (cfg.anomaly_health_score_threshold != null) setHealthThreshold(cfg.anomaly_health_score_threshold); })
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

  if (loading) return <div style={{ color: "#888" }}>Loading findings…</div>;
  if (error)   return <div style={{ color: "#e05555" }}>Error: {error}</div>;

  // Cross-reference findings against the separately-fetched health data by device_family.
  // Per-site findings may not have health_score embedded — health endpoint is authoritative.
  const familyHealth      = (family) => health[family] ?? null;
  const familyHealthScore = (family) => health[family]?.health_score ?? 1.0;

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

  // GENERAL HEALTH: unhealthy families NOT triggering any anomaly finding
  const findingFamilies = new Set(findings.map(f => f.device_family));
  const healthOnlyFamilies = Object.entries(health)
    .filter(([fam, data]) => data.health_score < healthThreshold && !findingFamilies.has(fam))
    .sort(([, a], [, b]) => a.health_score - b.health_score);

  const hasAnything = ifSectionFindings.length > 0 || dbscanFindings.length > 0 || markovFindings.length > 0 || healthOnlyFamilies.length > 0;

  if (!hasAnything) {
    return <div style={{ color: "#2d7a4f", padding: "20px" }}>No anomalies detected. All device families behaving normally.</div>;
  }

  function toggleExpand(idx) {
    setExpanded(prev => ({ ...prev, [idx]: !prev[idx] }));
  }

  const IF_COLOR     = "#b06ad4";
  const DBSCAN_COLOR = "#5ab86c";
  const MARKOV_COLOR = "#4ab0e8";

  function renderFindingCards(list, prefix) {
    return list.map((finding, idx) => (
      <AnomalyFindingCard
        key={`${prefix}-${idx}`}
        finding={finding}
        healthData={familyHealth(finding.device_family)}
        isAlert={familyHealthScore(finding.device_family) < healthThreshold}
        expanded={expanded[`${prefix}-${idx}`]}
        onToggle={() => toggleExpand(`${prefix}-${idx}`)}
        onMacSelect={onMacSelect}
        healthThreshold={healthThreshold}
      />
    ));
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
