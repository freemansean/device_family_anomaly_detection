import { useState, useEffect } from "react";
import { apiFetch } from "../api";
import OrgClusterViz from "./OrgClusterViz";
import OrgFamilyInsights from "./OrgFamilyInsights";
import OrgFindingsFeed from "./OrgFindingsFeed";

const SEVERITY_BORDER = {
  significant: "#3a2020",
  moderate:    "#3a2f10",
  ok:          "#1a3a2a",
  none:        "#2a2a2a",
};

function SiteCard({ site, onClick }) {
  const { site_name, site_id, has_data, critical_count, warning_count, info_count, event_count } = site;

  const severity = !has_data ? "none" : critical_count > 0 ? "significant" : warning_count > 0 ? "moderate" : "ok";
  const statusColor = { none: "#555", significant: "#e05555", moderate: "#e0a835", ok: "#2d7a4f" }[severity];
  const statusText  = { none: "No data", significant: "Significant", moderate: "Moderate", ok: "OK" }[severity];

  const [hovered, setHovered] = useState(false);

  return (
    <div
      onClick={onClick}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        background: "#161616",
        border: `1px solid ${hovered ? "#555" : SEVERITY_BORDER[severity]}`,
        borderRadius: "6px",
        padding: "12px 14px",
        cursor: "pointer",
        transition: "border-color 0.15s",
      }}
    >
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "8px" }}>
        <div>
          <div style={{ color: "#e0e0e0", fontSize: "13px" }}>{site_name}</div>
          <div style={{ color: "#444", fontSize: "10px", marginTop: "2px", fontFamily: "monospace" }}>{site_id}</div>
        </div>
        <span style={{ color: statusColor, fontSize: "11px", display: "flex", alignItems: "center", gap: "4px", whiteSpace: "nowrap" }}>
          <span style={{ fontSize: "8px" }}>●</span>{statusText}
        </span>
      </div>

      {has_data ? (
        <div style={{ display: "flex", gap: "5px", flexWrap: "wrap", alignItems: "center" }}>
          {critical_count > 0 && (
            <span style={{ background: "#2a1515", color: "#e05555", padding: "1px 6px", borderRadius: "3px", fontSize: "10px" }}>
              {critical_count} SIGNIFICANT
            </span>
          )}
          {warning_count > 0 && (
            <span style={{ background: "#2a1f10", color: "#e0a835", padding: "1px 6px", borderRadius: "3px", fontSize: "10px" }}>
              {warning_count} MODERATE
            </span>
          )}
          {info_count > 0 && (
            <span style={{ background: "#1a2a3a", color: "#7ec8e3", padding: "1px 6px", borderRadius: "3px", fontSize: "10px" }}>
              {info_count} MINIMAL
            </span>
          )}
          {critical_count === 0 && warning_count === 0 && info_count === 0 && (
            <span style={{ color: "#2d7a4f", fontSize: "10px" }}>No findings</span>
          )}
          <span style={{ color: "#444", fontSize: "10px", marginLeft: "auto" }}>
            {event_count.toLocaleString()} events
          </span>
        </div>
      ) : (
        <div style={{ color: "#333", fontSize: "10px" }}>No event data — run Full Discovery</div>
      )}
    </div>
  );
}

export default function OrgOverview({ apiBase, onSiteSelect, onMacSiteSelect, refreshToken, wlan = "__all__", onLoaded }) {
  const [summary, setSummary]       = useState(null);
  const [loading, setLoading]       = useState(true);
  const [error, setError]           = useState(null);
  const [activeView, setActiveView] = useState("overview");

  useEffect(() => {
    setLoading(true);
    setError(null);
    apiFetch(`${apiBase}/api/v1/org/summary?wlan=${encodeURIComponent(wlan)}`)
      .then(r => r.json())
      .then(data => { setSummary(data); setError(null); })
      .catch(e => { setError(e.message); })
      .finally(() => { setLoading(false); onLoaded?.(); });
  }, [apiBase, refreshToken, wlan]);

  const sites = summary?.sites || [];
  const sitesWithData     = sites.filter(s => s.has_data).length;
  const totalSignificant  = sites.reduce((n, s) => n + (s.critical_count || 0), 0);
  const totalModerate     = sites.reduce((n, s) => n + (s.warning_count  || 0), 0);

  return (
    <div>
      {/* View toggle */}
      <div style={{ display: "flex", gap: "8px", marginBottom: "18px" }}>
        {["overview", "insights", "findings"].map(view => {
          const label = view === "overview" ? "Org Overview" : view === "insights" ? "Org Family Insights" : "Findings";
          const active = activeView === view;
          return (
            <button
              key={view}
              onClick={() => setActiveView(view)}
              style={{
                padding: "5px 14px",
                fontSize: "12px",
                borderRadius: "4px",
                border: active ? "1px solid #7ec8e3" : "1px solid #333",
                background: active ? "#0d2a38" : "#161616",
                color: active ? "#7ec8e3" : "#666",
                cursor: "pointer",
                transition: "all 0.15s",
              }}
            >
              {label}
            </button>
          );
        })}
      </div>

      {activeView === "overview" && (
        <div>
          {/* Header */}
          <div style={{ marginBottom: "16px", display: "flex", alignItems: "center", gap: "14px", flexWrap: "wrap" }}>
            <h2 style={{ margin: 0, fontSize: "15px", color: "#7ec8e3" }}>Org Overview</h2>
            {loading
              ? <span style={{ color: "#555", fontSize: "12px" }}>Loading…</span>
              : <span style={{ color: "#555", fontSize: "12px" }}>{sites.length} sites</span>
            }
            {sitesWithData > 0 && (
              <span style={{ color: "#555", fontSize: "12px" }}>{sitesWithData} with data</span>
            )}
            {totalSignificant > 0 && (
              <span style={{ background: "#2a1515", color: "#e05555", padding: "2px 8px", borderRadius: "3px", fontSize: "11px" }}>
                {totalSignificant} SIGNIFICANT
              </span>
            )}
            {totalModerate > 0 && (
              <span style={{ background: "#2a1f10", color: "#e0a835", padding: "2px 8px", borderRadius: "3px", fontSize: "11px" }}>
                {totalModerate} MODERATE
              </span>
            )}
            {!loading && !error && (
              <span style={{ color: "#444", fontSize: "11px", marginLeft: "auto" }}>Click a site to inspect</span>
            )}
          </div>

          {error && (
            <div style={{ color: "#e05555", marginBottom: "16px" }}>Error loading org summary: {error}</div>
          )}

          {/* Two-column layout: PCA chart + site cards */}
          <div style={{ display: "flex", gap: "28px", alignItems: "flex-start" }}>
            <div style={{ flexShrink: 0 }}>
              <OrgClusterViz apiBase={apiBase} onMacSiteSelect={onMacSiteSelect} refreshToken={refreshToken} wlan={wlan} />
            </div>
            <div style={{ flex: 1, minWidth: 0 }}>
              {!loading && sites.length === 0 && !error && (
                <div style={{ color: "#555", padding: "24px 0" }}>
                  No sites found. Check that MIST_ORG_ID is configured.
                </div>
              )}
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(240px, 1fr))", gap: "8px" }}>
                {sites.map(site => (
                  <SiteCard key={site.site_id} site={site} onClick={() => onSiteSelect(site.site_id)} />
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {activeView === "insights" && (
        <OrgFamilyInsights apiBase={apiBase} refreshToken={refreshToken} onMacSiteSelect={onMacSiteSelect} wlan={wlan} />
      )}

      {activeView === "findings" && (
        <OrgFindingsFeed apiBase={apiBase} onMacSiteSelect={onMacSiteSelect} refreshToken={refreshToken} wlan={wlan} />
      )}
    </div>
  );
}
