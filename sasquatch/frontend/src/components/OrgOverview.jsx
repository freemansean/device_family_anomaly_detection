import { useState, useEffect } from "react";
import { apiFetch } from "../api";
import OrgFamilyInsights from "./OrgFamilyInsights";
import OrgFindingsFeed from "./OrgFindingsFeed";
import OrgAlerts from "./OrgAlerts";

// Site card border reflects the dual-gate alert state, not raw anomaly severity
const SEVERITY_BORDER = {
  alert:     "#3a2020",  // dark red — anomalous + unhealthy
  anomalous: "#1a3a20",  // dark green — anomalies only, no health issue
  ok:        "#1a2a1a",  // very dark green — healthy, no anomalies
  none:      "#2a2a2a",  // dark gray — no data
};

// Anomaly severity colors — green spectrum (anomalies alone are not alerts)
const ANOMALY_COLOR = { significant: "#39e84e", moderate: "#2eb845", minimal: "#1a6b27" };
const ANOMALY_BG    = { significant: "#0d2a15", moderate: "#0b2210", minimal: "#09180a" };

function SiteCard({ site, onClick }) {
  const { site_name, site_id, has_data, alert_count = 0, impacted_family_count = 0, event_count } = site;

  const severity = !has_data
    ? "none"
    : alert_count > 0
    ? "alert"
    : impacted_family_count > 0
    ? "anomalous"
    : "ok";

  const statusColor = {
    none:      "#555",
    alert:     "#e05555",
    anomalous: "#39e84e",
    ok:        "#2d7a4f",
  }[severity];

  const statusText = {
    none:      "No data",
    alert:     "Alert",
    anomalous: "Anomalous",
    ok:        "OK",
  }[severity];

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
          {alert_count > 0 && (
            <span style={{ background: "#2a1515", color: "#e05555", padding: "1px 6px", borderRadius: "3px", fontSize: "10px" }}>
              {alert_count} ALERT
            </span>
          )}
          {impacted_family_count > 0 ? (
            <span
              title="Device families flagged by DBSCAN, centroid, or Markov detectors"
              style={{ background: ANOMALY_BG.moderate, color: ANOMALY_COLOR.moderate, padding: "1px 6px", borderRadius: "3px", fontSize: "10px" }}
            >
              {impacted_family_count} {impacted_family_count === 1 ? "FAMILY" : "FAMILIES"} IMPACTED
            </span>
          ) : (
            <span style={{ color: "#2d7a4f", fontSize: "10px" }}>No impacted families</span>
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

export default function OrgOverview({ apiBase, onSiteSelect, onMacSiteSelect, refreshToken, wlan, onLoaded, detectionInProgress }) {
  const [summary, setSummary]       = useState(null);
  const [loading, setLoading]       = useState(true);
  const [error, setError]           = useState(null);
  const [activeView, setActiveView] = useState("full-alerts");

  useEffect(() => {
    // /org/summary requires a WLAN. When none is selected (e.g. on first
    // paint before the auto-select effect resolves) skip the fetch — the
    // Full Alert Summary tab uses its own cross-WLAN endpoint and does not
    // depend on this summary payload.
    if (!wlan) {
      setLoading(false);
      setSummary(null);
      onLoaded?.();
      return;
    }
    setLoading(true);
    setError(null);
    apiFetch(`${apiBase}/api/v1/org/summary?wlan=${encodeURIComponent(wlan)}`)
      .then(r => r.json())
      .then(data => { setSummary(data); setError(null); })
      .catch(e => { setError(e.message); })
      .finally(() => { setLoading(false); onLoaded?.(); });
  }, [apiBase, refreshToken, wlan]);

  const MAX_SITE_CARDS    = 20;
  const allSites          = (summary?.sites || []).slice().sort((a, b) => {
    const aAlerts = a.alert_count || 0;
    const bAlerts = b.alert_count || 0;
    if (bAlerts !== aAlerts) return bAlerts - aAlerts;
    return (b.event_count || 0) - (a.event_count || 0);
  });
  const sites             = allSites.slice(0, MAX_SITE_CARDS);
  const hiddenSiteCount   = Math.max(0, allSites.length - sites.length);
  const sitesWithData     = allSites.filter(s => s.has_data).length;
  const orgFindingCount   = summary?.org_finding_count ?? 0;

  return (
    <div>
      {/* View toggle. "full-alerts" aggregates across every WLAN in the
          retention window and is the default landing tab. The other three
          tabs are WLAN-scoped and reflect the selection in the WLAN dropdown. */}
      <div style={{ display: "flex", gap: "8px", marginBottom: "18px", flexWrap: "wrap" }}>
        {["full-alerts", "overview", "insights", "findings"].map(view => {
          const label =
            view === "full-alerts" ? "Full Alert Summary" :
            view === "overview"    ? "Org WLAN Overview" :
            view === "insights"    ? "Org WLAN Family Insights" :
                                     "Org WLAN Findings";
          const active = activeView === view;
          const isAlertTab = view === "full-alerts";
          const activeColor  = isAlertTab ? "#e05555" : "#7ec8e3";
          const activeBg     = isAlertTab ? "#2a1515" : "#0d2a38";
          return (
            <button
              key={view}
              onClick={() => setActiveView(view)}
              style={{
                padding: "5px 14px",
                fontSize: "12px",
                borderRadius: "4px",
                border: active ? `1px solid ${activeColor}` : "1px solid #333",
                background: active ? activeBg : "#161616",
                color: active ? activeColor : "#666",
                cursor: "pointer",
                transition: "all 0.15s",
              }}
            >
              {label}
            </button>
          );
        })}
      </div>

      {activeView === "full-alerts" && (
        <OrgAlerts apiBase={apiBase} onMacSiteSelect={onMacSiteSelect} refreshToken={refreshToken} wlan={wlan} detectionInProgress={detectionInProgress} />
      )}

      {activeView === "overview" && (
        <div>
          {/* Header — counts from org-wide findings, not per-site aggregates */}
          <div style={{ marginBottom: "16px", display: "flex", alignItems: "center", gap: "14px", flexWrap: "wrap" }}>
            <h2 style={{ margin: 0, fontSize: "15px", color: "#7ec8e3" }}>Org Overview</h2>
            {loading
              ? <span style={{ color: "#555", fontSize: "12px" }}>Loading…</span>
              : <span style={{ color: "#555", fontSize: "12px" }}>{allSites.length} sites</span>
            }
            {sitesWithData > 0 && (
              <span style={{ color: "#555", fontSize: "12px" }}>{sitesWithData} with data</span>
            )}
            {!loading && !error && orgFindingCount === 0 && sitesWithData > 0 && (
              <span style={{ color: "#444", fontSize: "11px" }}>No org-wide findings yet — run Full Discovery to start org analysis</span>
            )}
            {!loading && !error && (
              <span style={{ color: "#444", fontSize: "11px", marginLeft: "auto" }}>Click a site to inspect</span>
            )}
          </div>

          {error && (
            <div style={{ color: "#e05555", marginBottom: "16px" }}>Error loading org summary: {error}</div>
          )}

          <div>
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
            {hiddenSiteCount > 0 && (
              <div style={{ color: "#555", fontSize: "11px", marginTop: "12px", textAlign: "center", fontStyle: "italic" }}>
                Showing top {sites.length} of {allSites.length} sites (ranked by alerts, then event volume). Use the Site dropdown above to jump to the {hiddenSiteCount} site{hiddenSiteCount === 1 ? "" : "s"} not listed.
              </div>
            )}
          </div>
        </div>
      )}

      {activeView === "insights" && (
        <OrgFamilyInsights apiBase={apiBase} refreshToken={refreshToken} onMacSiteSelect={onMacSiteSelect} wlan={wlan} />
      )}

      {activeView === "findings" && (
        <OrgFindingsFeed apiBase={apiBase} onMacSiteSelect={onMacSiteSelect} refreshToken={refreshToken} wlan={wlan} detectionInProgress={detectionInProgress} />
      )}
    </div>
  );
}
