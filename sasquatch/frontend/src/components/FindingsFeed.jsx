import { useState, useEffect, useCallback } from "react";
import { apiFetch } from "../api";

const SEVERITY_COLOR = { significant: "#e05555", moderate: "#e0a835", minimal: "#4ea8c4" };
const SEVERITY_BG = { significant: "#2a1515", moderate: "#2a2015", minimal: "#152030" };

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

export default function FindingsFeed({ siteId, apiBase, onMacSelect }) {
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [expanded, setExpanded] = useState({});

  const load = useCallback(() => {
    apiFetch(`${apiBase}/api/v1/sites/${siteId}/findings`)
      .then((r) => r.json())
      .then((data) => {
        setFindings(data.findings || []);
        setError(null);
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [siteId, apiBase]);

  useEffect(() => {
    load();
    const interval = setInterval(load, 30_000);
    return () => clearInterval(interval);
  }, [load]);

  if (loading) return <div style={{ color: "#888" }}>Loading findings…</div>;
  if (error) return <div style={{ color: "#e05555" }}>Error: {error}</div>;
  if (findings.length === 0) {
    return <div style={{ color: "#2d7a4f", padding: "20px" }}>No anomalies detected. All device families behaving normally.</div>;
  }

  function toggleExpand(idx) {
    setExpanded((prev) => ({ ...prev, [idx]: !prev[idx] }));
  }

  return (
    <div>
      <h2 style={{ fontSize: "15px", color: "#aaa", marginBottom: "12px" }}>
        Anomaly Findings — {findings.length} active
      </h2>
      <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
        {findings.map((finding, idx) => {
          const sev = finding.severity;
          const isExpanded = expanded[idx];
          return (
            <div
              key={idx}
              style={{
                border: `1px solid ${SEVERITY_COLOR[sev]}44`,
                borderLeft: `3px solid ${SEVERITY_COLOR[sev]}`,
                background: SEVERITY_BG[sev],
                borderRadius: "4px",
                padding: "12px 14px",
              }}
            >
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                <div>
                  <span style={{
                    background: SEVERITY_COLOR[sev] + "33",
                    color: SEVERITY_COLOR[sev],
                    padding: "2px 8px",
                    borderRadius: "3px",
                    fontSize: "11px",
                    fontWeight: "bold",
                    marginRight: "10px",
                    border: `1px solid ${SEVERITY_COLOR[sev]}55`,
                  }}>
                    {sev}
                  </span>
                  <span style={{ fontWeight: "bold", fontSize: "14px", color: "#ddd" }}>
                    {finding.device_family}
                  </span>
                  <span style={{ color: "#666", fontSize: "12px", marginLeft: "10px" }}>
                    {PATTERN_LABELS[finding.probable_pattern] || finding.probable_pattern}
                  </span>
                  {finding.is_family_outlier && (
                    <span style={{
                      background: "#2a1a3a",
                      color: "#b06ad4",
                      border: "1px solid #6a3a8a",
                      borderRadius: "3px",
                      padding: "2px 7px",
                      fontSize: "10px",
                      marginLeft: "8px",
                    }}>
                      family-wide
                    </span>
                  )}
                </div>
                <div style={{ textAlign: "right", fontSize: "12px" }}>
                  <span style={{ color: SEVERITY_COLOR[sev], fontWeight: "bold" }}>
                    {(finding.outlier_ratio * 100).toFixed(0)}%
                  </span>
                  <span style={{ color: "#555" }}> outlier</span>
                  <span style={{ color: "#555", marginLeft: "8px" }}>
                    {finding.affected_mac_count}/{finding.total_mac_count} devices
                  </span>
                </div>
              </div>

              {/* Top contributing features */}
              {finding.top_features?.length > 0 && (
                <div style={{ marginTop: "8px", display: "flex", gap: "6px", flexWrap: "wrap" }}>
                  {finding.top_features.slice(0, 3).map((f, fi) => (
                    <span
                      key={fi}
                      title={`Outlier mean: ${f.outlier_mean.toFixed(3)} vs baseline: ${f.baseline_mean.toFixed(3)}`}
                      style={{
                        background: "#222",
                        border: "1px solid #333",
                        borderRadius: "3px",
                        padding: "2px 7px",
                        fontSize: "11px",
                        color: "#999",
                      }}
                    >
                      {f.feature} <span style={{ color: SEVERITY_COLOR[sev] }}>↑{(Math.abs(f.outlier_mean - f.baseline_mean)).toFixed(3)}</span>
                    </span>
                  ))}
                </div>
              )}

              {/* Expand/collapse example MACs */}
              <button
                onClick={() => toggleExpand(idx)}
                style={{
                  background: "transparent",
                  border: "none",
                  color: "#555",
                  cursor: "pointer",
                  padding: "6px 0 0 0",
                  fontSize: "12px",
                }}
              >
                {isExpanded ? "▲ Hide affected MACs" : `▼ Show ${finding.example_macs?.length || 0} example MACs`}
              </button>

              {isExpanded && finding.example_macs?.length > 0 && (
                <div style={{ marginTop: "6px", display: "flex", gap: "6px", flexWrap: "wrap" }}>
                  {finding.example_macs.map((mac) => (
                    <button
                      key={mac}
                      onClick={() => onMacSelect(mac)}
                      style={{
                        background: "#1a1a2e",
                        border: "1px solid #2a2a5e",
                        color: "#7ec8e3",
                        borderRadius: "3px",
                        padding: "3px 10px",
                        cursor: "pointer",
                        fontSize: "12px",
                        fontFamily: "monospace",
                      }}
                    >
                      {mac}
                    </button>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
