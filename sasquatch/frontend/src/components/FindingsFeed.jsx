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

// Families below this health score are considered unhealthy
const HEALTH_THRESHOLD = 0.75;

function shapleyScoreFromIfScore(ifScore) {
  if (ifScore == null) return null;
  return Math.max(0, Math.min(100, Math.round((0.5 - ifScore) / 1.0 * 100)));
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

function AnomalyFindingCard({ finding, healthData, isAlert, expanded, onToggle, onMacSelect }) {
  const sev        = finding.severity;
  const hs         = healthData?.health_score ?? null;
  const components = healthData?.components ?? null;
  const isUnhealthy = hs != null && hs < HEALTH_THRESHOLD;
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
            {finding.device_family}
          </span>
          <span style={{ color: "#666", fontSize: "12px" }}>
            {PATTERN_LABELS[finding.probable_pattern] || finding.probable_pattern}
          </span>
          {finding.is_family_outlier && (
            <span style={{ background: "#2a1a3a", color: "#b06ad4", border: "1px solid #6a3a8a", borderRadius: "3px", padding: "2px 7px", fontSize: "10px" }}>
              family-wide
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
          score={shapleyScoreFromIfScore(finding.centroid_if_score)}
          features={finding.top_features}
          description={
            finding.centroid_if_score != null
              ? `Family centroid IF score ${finding.centroid_if_score.toFixed(4)} — measures how distinctly this family's collective behavior differs from all other families at this site.`
              : finding.is_family_outlier
                ? "This family's collective behavior is flagged as anomalous relative to other families."
                : "Anomaly driven by individual device deviations within the family."
          }
        />
      </div>

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

export default function FindingsFeed({ siteId, apiBase, onMacSelect, refreshToken, wlan = "__all__" }) {
  const [findings, setFindings] = useState([]);
  const [health, setHealth]     = useState({});
  const [loading, setLoading]   = useState(true);
  const [error, setError]       = useState(null);
  const [expanded, setExpanded] = useState({});

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

  // Partition findings: ALERT (anomalous + unhealthy) vs ANOMALOUS (anomalous, healthy)
  const alertFindings     = findings.filter(f => familyHealthScore(f.device_family) < HEALTH_THRESHOLD);
  const anomalousFindings = findings.filter(f => familyHealthScore(f.device_family) >= HEALTH_THRESHOLD);

  // HEALTH section: unhealthy families NOT in any anomaly finding
  const findingFamilies = new Set(findings.map(f => f.device_family));
  const healthOnlyFamilies = Object.entries(health)
    .filter(([fam, data]) => data.health_score < HEALTH_THRESHOLD && !findingFamilies.has(fam))
    .sort(([, a], [, b]) => a.health_score - b.health_score);

  const hasAnything = alertFindings.length > 0 || healthOnlyFamilies.length > 0 || anomalousFindings.length > 0;

  if (!hasAnything) {
    return <div style={{ color: "#2d7a4f", padding: "20px" }}>No anomalies detected. All device families behaving normally.</div>;
  }

  function toggleExpand(idx) {
    setExpanded(prev => ({ ...prev, [idx]: !prev[idx] }));
  }

  return (
    <div>
      <h2 style={{ fontSize: "15px", color: "#aaa", marginBottom: "4px" }}>
        Anomaly Findings — {findings.length} active
      </h2>

      {/* ALERT section */}
      {alertFindings.length > 0 && (
        <div>
          <SectionHeader label="ALERT" color={ALERT_COLOR} count={alertFindings.length} />
          <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
            {alertFindings.map((finding, idx) => (
              <AnomalyFindingCard
                key={`alert-${idx}`}
                finding={finding}
                healthData={familyHealth(finding.device_family)}
                isAlert={true}
                expanded={expanded[`alert-${idx}`]}
                onToggle={() => toggleExpand(`alert-${idx}`)}
                onMacSelect={onMacSelect}
              />
            ))}
          </div>
        </div>
      )}

      {/* HEALTH section — unhealthy families with no anomaly finding */}
      {healthOnlyFamilies.length > 0 && (
        <div>
          <SectionHeader label="HEALTH" color={HEALTH_COLOR} count={healthOnlyFamilies.length} />
          <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
            {healthOnlyFamilies.map(([fam, data]) => (
              <HealthOnlyCard key={fam} family={fam} data={data} />
            ))}
          </div>
        </div>
      )}

      {/* ANOMALOUS section — anomalous but no health issue */}
      {anomalousFindings.length > 0 && (
        <div>
          <SectionHeader label="ANOMALOUS" color={ANOMALY_COLOR.significant} count={anomalousFindings.length} />
          <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
            {anomalousFindings.map((finding, idx) => (
              <AnomalyFindingCard
                key={`anom-${idx}`}
                finding={finding}
                healthData={familyHealth(finding.device_family)}
                isAlert={false}
                expanded={expanded[`anom-${idx}`]}
                onToggle={() => toggleExpand(`anom-${idx}`)}
                onMacSelect={onMacSelect}
              />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
