import { useState, useEffect, useCallback } from "react";
import { apiFetch } from "../api";
import { familyColor } from "./familyColors";
import OrgFamilyDrilldown from "./OrgFamilyDrilldown";
import OrgClusterViz from "./OrgClusterViz";

const CATEGORIES = [
  "DHCP_SUCCESS", "DHCP_FAILURE", "DNS_SUCCESS", "DNS_FAILURE",
  "AUTH_SUCCESS", "AUTH_FAILURE", "ROAM_SUCCESS", "ROAM_FAILURE",
  "DISASSOC", "ARP_SUCCESS", "ARP_FAILURE", "CAPTIVE_PORTAL", "SECURITY", "COLLABORATION", "OTHER",
];

const SEVERITY_COLOR = { significant: "#e05555", moderate: "#e0a835", minimal: "#4ea8c4" };
const SEVERITY_RANK  = { significant: 3, moderate: 2, minimal: 1 };

function healthScoreColor(score) {
  if (score == null) return "#444";
  if (score >= 0.85) return "#2d7a4f";
  if (score >= 0.75) return "#e0a835";
  if (score >= 0.55) return "#c87832";
  return "#e05555";
}

function healthBarColor(score) {
  if (score == null) return "#333";
  if (score >= 0.85) return "#2d9e5f";
  if (score >= 0.75) return "#e0a835";
  if (score >= 0.55) return "#c87832";
  return "#e05555";
}

function ratioColor(ratio) {
  if (ratio <= 0) return "#1a2d1a";
  if (ratio < 0.3) {
    const t = ratio / 0.3;
    return `rgb(${Math.round(45 + t * 155)}, ${Math.round(122 - t * 50)}, ${Math.round(79 - t * 79)})`;
  }
  const t = Math.min((ratio - 0.3) / 0.7, 1);
  return `rgb(200, ${Math.round(168 - t * 118)}, ${Math.round(32 - t * 32)})`;
}

function successColor(ratio) {
  if (ratio <= 0) return "#111";
  const t = Math.min(ratio / 0.4, 1);
  return `rgb(${Math.round(18 + t * 12)}, ${Math.round(44 + t * 116)}, ${Math.round(18 + t * 12)})`;
}

const thStyle = {
  padding: "6px 8px",
  borderBottom: "1px solid #333",
  color: "#666",
  textAlign: "left",
  fontWeight: "normal",
  background: "#161616",
};

const tdStyle = {
  padding: "5px 8px",
  borderBottom: "1px solid #1e1e1e",
};

function SortIndicator({ active, dir }) {
  if (!active) return <span style={{ color: "#333", marginLeft: "3px", fontSize: "9px" }}>⇅</span>;
  return <span style={{ color: "#7ec8e3", marginLeft: "3px", fontSize: "9px" }}>{dir === "asc" ? "▲" : "▼"}</span>;
}

export default function OrgFamilyInsights({ apiBase, refreshToken, onMacSiteSelect, wlan }) {
  const [data, setData]               = useState(null);
  const [loading, setLoading]         = useState(true);
  const [error, setError]             = useState(null);
  const [selectedFamily, setSelectedFamily] = useState(null);
  const [sortKey, setSortKey]         = useState("anomaly");
  const [sortDir, setSortDir]         = useState("desc");

  const load = useCallback(() => {
    setLoading(true);
    apiFetch(`${apiBase}/api/v1/org/family-insights?wlan=${encodeURIComponent(wlan)}`)
      .then(r => r.json())
      .then(d => { setData(d); setError(null); setLoading(false); })
      .catch(e => { setError(e.message); setLoading(false); });
  }, [apiBase, refreshToken, wlan]);

  useEffect(() => {
    load();
    const interval = setInterval(load, 60_000);
    return () => clearInterval(interval);
  }, [load]);

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

  if (loading && !data) return <div style={{ color: "#888", fontSize: "13px", padding: "8px 0" }}>Loading org insights…</div>;
  if (error)            return <div style={{ color: "#e05555", fontSize: "13px" }}>Error loading org family insights: {error}</div>;
  if (!data)            return null;

  const { families, sites_with_data, total_sites } = data;

  const HIDDEN_FAMILIES    = new Set(["Unknown", "IoT (Unknown)"]);
  const MIN_DISPLAY_EVENTS = 20;

  const allFamilies = Object.keys(families).filter(f => !HIDDEN_FAMILIES.has(f));
  const display     = allFamilies.filter(f => (families[f].total_events ?? 0) >= MIN_DISPLAY_EVENTS);
  const other       = allFamilies.filter(f => (families[f].total_events ?? 0) < MIN_DISPLAY_EVENTS);

  const handleSort = (key) => {
    setSortKey(prev => {
      if (prev === key) { setSortDir(d => d === "asc" ? "desc" : "asc"); return key; }
      setSortDir(key === "family" ? "asc" : "desc");
      return key;
    });
  };

  // IF sort rank: family outlier > ok
  const ifRank = (f) => families[f].is_family_outlier_any_site ? 1 : 0;
  // Anomaly sort rank combines all three classifiers for the default sort
  const anomalyRank = (f) => {
    if (families[f].is_family_outlier_any_site) return 10;
    const dbRank = SEVERITY_RANK[families[f].worst_dbscan_severity] ?? 0;
    const mRank  = families[f].is_family_markov_outlier_any_site ? 1 : 0;
    return dbRank * 2 + mRank;
  };

  const sortedDisplay = [...display].sort((a, b) => {
    let va, vb;
    if (sortKey === "family") {
      va = a.toLowerCase(); vb = b.toLowerCase();
    } else if (sortKey === "anomaly") {
      va = anomalyRank(a); vb = anomalyRank(b);
    } else if (sortKey === "dbscan") {
      va = SEVERITY_RANK[families[a].worst_dbscan_severity] ?? 0;
      vb = SEVERITY_RANK[families[b].worst_dbscan_severity] ?? 0;
    } else if (sortKey === "markov") {
      va = families[a].worst_markov_ratio ?? 0;
      vb = families[b].worst_markov_ratio ?? 0;
    } else if (sortKey === "health") {
      va = families[a].health_score ?? -1; vb = families[b].health_score ?? -1;
    } else if (sortKey === "events") {
      va = families[a].total_events ?? 0; vb = families[b].total_events ?? 0;
    } else if (sortKey === "sites") {
      va = families[a].site_count ?? 0; vb = families[b].site_count ?? 0;
    } else {
      // category column — sort by raw event count
      va = families[a].categories?.[sortKey]?.count ?? 0;
      vb = families[b].categories?.[sortKey]?.count ?? 0;
    }
    if (va < vb) return sortDir === "asc" ? -1 : 1;
    if (va > vb) return sortDir === "asc" ? 1 : -1;
    // tiebreak: total_events desc
    return (families[b].total_events ?? 0) - (families[a].total_events ?? 0);
  });

  // Aggregate "All Other" row
  const otherCounts = {};
  let otherTotal = 0;
  for (const f of other) {
    for (const cat of CATEGORIES) {
      otherCounts[cat] = (otherCounts[cat] ?? 0) + (families[f].categories?.[cat]?.count ?? 0);
    }
    otherTotal += families[f].total_events ?? 0;
  }

  if (display.length === 0 && other.length === 0) {
    return (
      <div style={{ marginTop: "28px" }}>
        <h3 style={{ margin: "0 0 8px 0", fontSize: "14px", color: "#7ec8e3" }}>Org Family Insights</h3>
        <div style={{ color: "#555", fontSize: "13px" }}>No event data across sites — run Full Discovery to populate.</div>
      </div>
    );
  }

  return (
    <div style={{ marginTop: "28px" }}>
      <div style={{ display: "flex", alignItems: "baseline", gap: "12px", marginBottom: "10px", flexWrap: "wrap" }}>
        <h3 style={{ margin: 0, fontSize: "14px", color: "#7ec8e3" }}>Org Family Insights</h3>
        <span style={{ color: "#555", fontSize: "12px" }}>
          {display.length} device families · {sites_with_data}/{total_sites} sites with data
        </span>
      </div>

      <div style={{ display: "flex", gap: "28px", alignItems: "flex-start" }}>
      <div style={{ overflowX: "auto", flex: "1 1 auto", minWidth: 0 }}>
        <table style={{ borderCollapse: "collapse", fontSize: "12px" }}>
          <thead>
            <tr>
              <th
                style={{ ...thStyle, cursor: "pointer", userSelect: "none" }}
                onClick={() => handleSort("family")}
              >
                Device Family<SortIndicator active={sortKey === "family"} dir={sortDir} />
              </th>
              <th
                style={{ ...thStyle, whiteSpace: "nowrap", cursor: "pointer", userSelect: "none" }}
                title="Isolation Forest centroid detection — flags the whole family as behaving differently from all other families (any site)."
                onClick={() => handleSort("anomaly")}
              >
                IF<SortIndicator active={sortKey === "anomaly"} dir={sortDir} />
              </th>
              <th
                style={{ ...thStyle, whiteSpace: "nowrap", cursor: "pointer", userSelect: "none" }}
                title="DBSCAN — worst fraction of individual MACs flagged as site-wide behavioral outliers across all sites."
                onClick={() => handleSort("dbscan")}
              >
                DB<SortIndicator active={sortKey === "dbscan"} dir={sortDir} />
              </th>
              <th
                style={{ ...thStyle, whiteSpace: "nowrap", cursor: "pointer", userSelect: "none" }}
                title="Markov Chain episode analysis — flags families where clients show anomalous event chain patterns."
                onClick={() => handleSort("markov")}
              >
                Markov<SortIndicator active={sortKey === "markov"} dir={sortDir} />
              </th>
              <th
                style={{ ...thStyle, whiteSpace: "nowrap", minWidth: "90px", cursor: "pointer", userSelect: "none" }}
                title="Family health score — volume-weighted failure rate across AUTH, ROAM, DHCP, DNS, ARP org-wide. 1.0 = no failures."
                onClick={() => handleSort("health")}
              >
                Health<SortIndicator active={sortKey === "health"} dir={sortDir} />
              </th>
              <th
                style={{ ...thStyle, whiteSpace: "nowrap", color: "#444", cursor: "pointer", userSelect: "none" }}
                onClick={() => handleSort("events")}
              >
                Events<SortIndicator active={sortKey === "events"} dir={sortDir} />
              </th>
              <th
                style={{ ...thStyle, whiteSpace: "nowrap", color: "#444", cursor: "pointer", userSelect: "none" }}
                onClick={() => handleSort("sites")}
              >
                Sites<SortIndicator active={sortKey === "sites"} dir={sortDir} />
              </th>
              {CATEGORIES.map(c => (
                <th
                  key={c}
                  style={{
                    ...thStyle,
                    writingMode: "vertical-rl",
                    transform: "rotate(180deg)",
                    padding: "4px 2px",
                    fontSize: "10px",
                    cursor: "pointer",
                    userSelect: "none",
                    color: sortKey === c ? "#7ec8e3" : undefined,
                  }}
                  onClick={() => handleSort(c)}
                >
                  {c}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {sortedDisplay.map(family => {
              const fdata     = families[family];
              const isFamOut  = fdata.is_family_outlier_any_site;
              const siteCount = fdata.site_count ?? 0;
              const sitesTotal = total_sites;
              const color     = familyColor(family);
              const outlierSites = fdata.outlier_sites ?? [];

              // Build tooltip for anomaly badge
              const anomalyTip = outlierSites.length > 0
                ? `Anomalous at: ${[...new Set(outlierSites)].join(", ")}`
                : isFamOut ? "Flagged as family outlier at one or more sites" : "";

              return (
                <tr key={family}>
                  {/* Family name — clickable to drill down */}
                  <td
                    style={{ ...tdStyle, whiteSpace: "nowrap", cursor: "pointer" }}
                    onClick={() => setSelectedFamily(family)}
                  >
                    <span style={{
                      display: "inline-block", width: 8, height: 8,
                      borderRadius: "50%", background: color,
                      marginRight: "6px", verticalAlign: "middle",
                    }} />
                    <span style={{ color: (fdata.worst_dbscan_severity || isFamOut || fdata.is_family_markov_outlier_any_site) ? "#e0e0e0" : "#ccc", textDecoration: "underline", textDecorationColor: "#444" }}>{family}</span>
                    {fdata.client_count > 0 && (
                      <span style={{ color: "#444", fontSize: "11px", marginLeft: "6px" }}>
                        ({fdata.client_count})
                      </span>
                    )}
                  </td>

                  {/* IF: Centroid Isolation Forest — whole-family outlier any site */}
                  <td style={{ ...tdStyle, textAlign: "center" }}>
                    {isFamOut ? (
                      <span
                        title={anomalyTip}
                        style={{
                          background: "#2a1a3a", color: "#b06ad4",
                          border: "1px solid #6a3a8a", borderRadius: "3px",
                          padding: "1px 6px", fontSize: "10px", fontWeight: "bold", cursor: "default",
                        }}
                      >
                        family
                      </span>
                    ) : (
                      <span style={{ color: "#2d7a4f", fontSize: "10px" }}>OK</span>
                    )}
                  </td>

                  {/* DB: DBSCAN — worst severity across sites */}
                  {(() => {
                    const dbSev = fdata.worst_dbscan_severity;
                    return (
                      <td style={{ ...tdStyle, textAlign: "center" }}>
                        {dbSev ? (
                          <span
                            title={anomalyTip}
                            style={{
                              background: SEVERITY_COLOR[dbSev] + "33",
                              color: SEVERITY_COLOR[dbSev],
                              border: `1px solid ${SEVERITY_COLOR[dbSev]}55`,
                              borderRadius: "3px", padding: "1px 6px",
                              fontSize: "10px", fontWeight: "bold", cursor: "default",
                            }}
                          >
                            {dbSev}
                            {fdata.dbscan_outlier_site_count > 0 && (
                              <span style={{ opacity: 0.7, marginLeft: "4px" }}>
                                ({fdata.dbscan_outlier_site_count})
                              </span>
                            )}
                          </span>
                        ) : (
                          <span style={{ color: "#2d7a4f", fontSize: "10px" }}>OK</span>
                        )}
                      </td>
                    );
                  })()}

                  {/* Markov: chain episode anomaly any site */}
                  {(() => {
                    const isMarkov = fdata.is_family_markov_outlier_any_site;
                    const mRatio   = fdata.worst_markov_ratio;
                    return (
                      <td style={{ ...tdStyle, textAlign: "center" }}>
                        {isMarkov ? (
                          <span style={{
                            background: "#1a2a3a", color: "#4ab0e8",
                            border: "1px solid #2a6a8a", borderRadius: "3px",
                            padding: "1px 6px", fontSize: "10px", fontWeight: "bold", whiteSpace: "nowrap",
                          }}>
                            {mRatio != null ? `${(mRatio * 100).toFixed(0)}%` : "chain"}
                          </span>
                        ) : (
                          <span style={{ color: "#2d7a4f", fontSize: "10px" }}>OK</span>
                        )}
                      </td>
                    );
                  })()}

                  {/* Health score */}
                  {(() => {
                    const score = fdata.health_score;
                    const components = fdata.health_components ?? {};
                    const tip = score != null
                      ? `Health: ${(score * 100).toFixed(0)}%\n` +
                        Object.entries(components)
                          .map(([k, v]) => `  ${k}: ${(v * 100).toFixed(1)}% failure`)
                          .join("\n")
                      : "Health score not yet computed";
                    return (
                      <td style={{ ...tdStyle, minWidth: "90px" }} title={tip}>
                        {score != null ? (
                          <div style={{ display: "flex", alignItems: "center", gap: "5px" }}>
                            <div style={{ flex: 1, height: "5px", background: "#1a1a1a", borderRadius: "3px", overflow: "hidden" }}>
                              <div style={{ width: `${(score * 100).toFixed(0)}%`, height: "100%", background: healthBarColor(score), borderRadius: "3px" }} />
                            </div>
                            <span style={{ fontSize: "11px", fontWeight: "bold", color: healthScoreColor(score), minWidth: "28px", textAlign: "right" }}>
                              {(score * 100).toFixed(0)}%
                            </span>
                          </div>
                        ) : (
                          <span style={{ color: "#333", fontSize: "10px" }}>—</span>
                        )}
                      </td>
                    );
                  })()}

                  {/* Event count */}
                  <td style={{ ...tdStyle, textAlign: "right", color: "#555", fontSize: "11px", fontVariantNumeric: "tabular-nums" }}>
                    {fdata.total_events > 999
                      ? `${(fdata.total_events / 1000).toFixed(1)}k`
                      : fdata.total_events}
                  </td>

                  {/* Site count */}
                  <td style={{ ...tdStyle, textAlign: "center", color: "#555", fontSize: "11px" }}>
                    {siteCount}/{sitesTotal}
                  </td>

                  {/* Category cells */}
                  {CATEGORIES.map(cat => {
                    const cell    = fdata.categories?.[cat];
                    const ratio   = cell?.ratio ?? 0;
                    const count   = cell?.count ?? 0;
                    const isFail  = cat.includes("FAILURE") || cat === "SECURITY";
                    const isSucc  = cat.includes("SUCCESS");
                    const bg      = isFail  ? ratioColor(ratio)
                                  : isSucc  ? successColor(ratio)
                                  : ratio > 0 ? "#1a2d1a" : "#111";
                    const textCol = isFail && ratio > 0.1 ? "#fff"
                                  : isSucc && ratio > 0.15 ? "#fff"
                                  : "#555";
                    return (
                      <td
                        key={cat}
                        title={`${family} / ${cat}: ${count.toLocaleString()} events (${(ratio * 100).toFixed(1)}% of family events org-wide)`}
                        style={{ ...tdStyle, background: bg, textAlign: "center", minWidth: "28px" }}
                      >
                        {count > 0 && (
                          <span style={{ fontSize: "10px", color: textCol }}>
                            {count > 999 ? `${(count / 1000).toFixed(1)}k` : count}
                          </span>
                        )}
                      </td>
                    );
                  })}
                </tr>
              );
            })}

            {/* All Other Devices row */}
            {other.length > 0 && (
              <tr style={{ borderTop: "1px solid #2a2a2a" }}>
                <td style={{ ...tdStyle, whiteSpace: "nowrap", color: "#555", fontStyle: "italic" }}>
                  <span style={{
                    display: "inline-block", width: 8, height: 8,
                    borderRadius: "50%", background: "#444",
                    marginRight: "6px", verticalAlign: "middle",
                  }} />
                  All Other Devices
                  <span style={{ color: "#333", fontSize: "11px", marginLeft: "6px" }}>
                    ({other.length} types)
                  </span>
                </td>
                <td style={{ ...tdStyle, textAlign: "center" }}>
                  <span style={{ color: "#333", fontSize: "10px" }}>—</span>
                </td>
                <td style={{ ...tdStyle, textAlign: "center" }}>
                  <span style={{ color: "#333", fontSize: "10px" }}>—</span>
                </td>
                <td style={{ ...tdStyle, textAlign: "center" }}>
                  <span style={{ color: "#333", fontSize: "10px" }}>—</span>
                </td>
                <td style={tdStyle} />
                <td style={{ ...tdStyle, textAlign: "right", color: "#444", fontSize: "11px" }}>
                  {otherTotal > 999 ? `${(otherTotal / 1000).toFixed(1)}k` : otherTotal}
                </td>
                <td style={{ ...tdStyle }} />
                {CATEGORIES.map(cat => {
                  const count = otherCounts[cat] ?? 0;
                  const ratio = otherTotal > 0 ? count / otherTotal : 0;
                  const isFail = cat.includes("FAILURE") || cat === "SECURITY";
                  const isSucc = cat.includes("SUCCESS");
                  const bg     = isFail ? ratioColor(ratio) : isSucc ? successColor(ratio) : count > 0 ? "#1a2d1a" : "#111";
                  const textCol = isFail && ratio > 0.1 ? "#fff" : isSucc && ratio > 0.15 ? "#fff" : "#555";
                  return (
                    <td
                      key={cat}
                      title={`All Other / ${cat}: ${count.toLocaleString()} events`}
                      style={{ ...tdStyle, background: bg, textAlign: "center", minWidth: "28px" }}
                    >
                      {count > 0 && (
                        <span style={{ fontSize: "10px", color: textCol }}>
                          {count > 999 ? `${(count / 1000).toFixed(1)}k` : count}
                        </span>
                      )}
                    </td>
                  );
                })}
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <div style={{ flex: "0 0 600px", width: "600px" }}>
        <OrgClusterViz apiBase={apiBase} onMacSiteSelect={onMacSiteSelect} refreshToken={refreshToken} wlan={wlan} />
      </div>
      </div>

      <div style={{ marginTop: "8px", fontSize: "11px", color: "#444" }}>
        Cell ratios are % of that family's org-wide event pool.
        {" "}<span style={{ color: "#b06ad4" }}>IF: family</span> = device class flagged as a centroid outlier org-wide (cross-site population).
        {" "}<span style={{ fontWeight: "bold", color: "#666" }}>DB:</span> <span style={{ color: "#e0a835" }}>moderate</span> / <span style={{ color: "#e05555" }}>significant</span> = org-wide DBSCAN severity (badge = sites with outlier MACs).
        {" "}<span style={{ color: "#4ab0e8" }}>Markov %</span> = org-wide ratio of clients with anomalous chain patterns.
        {" "}Health = volume-weighted failure rate org-wide (hover for per-category breakdown).
        {" "}Hover cells for exact counts.
      </div>
    </div>
  );
}
