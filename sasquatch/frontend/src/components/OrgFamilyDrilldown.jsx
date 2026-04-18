import { useState, useEffect } from "react";
import { apiFetch } from "../api";
import ColumnSelector, { loadVisibleFromStorage } from "./ColumnSelector";

const SEVERITY_COLOR = { significant: "#e05555", moderate: "#e0a835", minimal: "#4ea8c4" };
const SA_COLOR = "#d4a06a";
const SA_BG    = "#2a1f15";

const CATEGORY_LABELS = {
  DHCP_SUCCESS:   "DHCP ✓",
  DHCP_FAILURE:   "DHCP ✗",
  DNS_SUCCESS:    "DNS ✓",
  DNS_FAILURE:    "DNS ✗",
  AUTH_SUCCESS:   "Auth ✓",
  AUTH_FAILURE:   "Auth ✗",
  ROAM_SUCCESS:   "Roam ✓",
  ROAM_FAILURE:   "Roam ✗",
  DISASSOC_AP:     "Disassoc - AP",
  DISASSOC_CLIENT: "Disassoc - Client",
  ARP_SUCCESS:    "ARP ✓",
  ARP_FAILURE:    "ARP ✗",
  CAPTIVE_PORTAL: "Captive",
  SECURITY:       "Security",
  COLLABORATION:  "Collab",
  OTHER:          "Other",
};

const CSV_CATEGORY_LABELS = {
  DHCP_SUCCESS:   "DHCP Success",
  DHCP_FAILURE:   "DHCP Fail",
  DNS_SUCCESS:    "DNS Success",
  DNS_FAILURE:    "DNS Fail",
  AUTH_SUCCESS:   "Auth Success",
  AUTH_FAILURE:   "Auth Fail",
  ROAM_SUCCESS:   "Roam Success",
  ROAM_FAILURE:   "Roam Fail",
  DISASSOC_AP:     "Disassoc - AP",
  DISASSOC_CLIENT: "Disassoc - Client",
  ARP_SUCCESS:    "ARP Success",
  ARP_FAILURE:    "ARP Fail",
  CAPTIVE_PORTAL: "Captive",
  SECURITY:       "Security",
  COLLABORATION:  "Collab",
  OTHER:          "Other",
};

const EVENT_CATEGORIES = Object.keys(CATEGORY_LABELS);

const COLUMN_DEFS = [
  { key: "site",             label: "Site" },
  { key: "wlan",             label: "WLAN" },
  { key: "device_family",    label: "Device Family" },
  { key: "mac",              label: "MAC", required: true },
  { key: "primary_family",   label: "Primary Family" },
  { key: "health",           label: "Health" },
  { key: "service_alarm",    label: "Service Alarm" },
  { key: "if_score",         label: "IF Score" },
  { key: "if_flag",          label: "▲IF" },
  { key: "dbscan",           label: "DBSCAN" },
  { key: "markov",           label: "Markov" },
  ...EVENT_CATEGORIES.map(c => ({ key: `cat_${c}`, label: CATEGORY_LABELS[c] })),
  { key: "total_events",     label: "Total" },
  { key: "model",            label: "Model" },
  { key: "os",               label: "OS" },
  { key: "manufacturer",     label: "Manufacturer" },
];

const DEFAULT_VISIBLE = {
  site: true, wlan: true, device_family: true, mac: true, primary_family: true,
  health: true, service_alarm: true, if_score: true, if_flag: true,
  dbscan: true, markov: true,
  cat_DHCP_SUCCESS: true, cat_DHCP_FAILURE: true,
  cat_DNS_SUCCESS: true, cat_DNS_FAILURE: true,
  cat_AUTH_SUCCESS: true, cat_AUTH_FAILURE: true,
  cat_ROAM_SUCCESS: true, cat_ROAM_FAILURE: true,
  cat_DISASSOC_AP: true,
  cat_DISASSOC_CLIENT: true,
  cat_ARP_SUCCESS: true, cat_ARP_FAILURE: true,
  cat_CAPTIVE_PORTAL: false, cat_SECURITY: false,
  cat_COLLABORATION: false, cat_OTHER: false,
  total_events: true,
  model: false, os: false, manufacturer: false,
};

function escapeCsvField(value) {
  const str = value == null ? "" : String(value);
  if (str.includes(",") || str.includes('"') || str.includes("\n")) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

function downloadDrilldownCsv(rows, family, extra) {
  const cols = [
    "Site",
    ...(extra?.includeWlan ? ["WLAN"] : []),
    ...(extra?.includeDeviceFamily ? ["Device Family"] : []),
    "MAC",
    ...(extra?.includePrimaryFamily ? ["Primary Family"] : []),
    "Health %",
    "Service Alarms",
    "IF Score",
    "IF Outlier",
    "DBSCAN Outlier",
    "Markov Outlier",
    "Markov Reason",
    ...EVENT_CATEGORIES.map(c => CSV_CATEGORY_LABELS[c]),
    "Total Events",
    "Model",
    "OS",
    "Manufacturer",
  ];

  const csvRows = [cols.map(escapeCsvField).join(",")];
  for (const row of rows) {
    const h = computeMacHealth(row.categories);
    const alarms = computeMacServiceAlarms(row.categories);
    const meta = row.client_metadata || {};
    const vals = [
      row.site_name || "",
      ...(extra?.includeWlan ? [row.wlan || ""] : []),
      ...(extra?.includeDeviceFamily ? [row.device_family || ""] : []),
      row.mac,
      ...(extra?.includePrimaryFamily ? [row.primary_device_family || ""] : []),
      h != null ? Math.round(h * 100) : "",
      alarms.map(a => a.svc).join("; ") || "",
      row.if_score != null ? row.if_score.toFixed(4) : "",
      row.is_if_outlier ? "Yes" : "No",
      row.is_dbscan_outlier ? "Yes" : "No",
      row.is_markov_outlier ? "Yes" : "No",
      row.markov_reason || "",
      ...EVENT_CATEGORIES.map(c => row.categories[c] || 0),
      row.total_events ?? 0,
      meta.model || "",
      meta.os || "",
      meta.manufacturer || "",
    ];
    csvRows.push(vals.map(escapeCsvField).join(","));
  }

  const blob = new Blob([csvRows.join("\n")], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  const safeName = (family || "drilldown").replace(/[^a-zA-Z0-9._-]/g, "_");
  a.download = `${safeName}_clients.csv`;
  a.click();
  URL.revokeObjectURL(url);
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

function scoreBar(ifScore) {
  if (ifScore === null || ifScore === undefined) return null;
  const clamped = Math.max(-0.5, Math.min(0.5, ifScore));
  const anomalyFraction = (0.5 - clamped) / 1.0;
  const red = Math.round(80 + anomalyFraction * 145);
  const green = Math.round(180 - anomalyFraction * 155);
  return { fraction: anomalyFraction, color: `rgb(${red}, ${green}, 50)` };
}

function computeMacHealth(cats) {
  const success = (cats.DHCP_SUCCESS || 0) + (cats.DNS_SUCCESS || 0) +
                  (cats.AUTH_SUCCESS || 0) + (cats.ROAM_SUCCESS || 0) + (cats.ARP_SUCCESS || 0);
  const failure = (cats.DHCP_FAILURE || 0) + (cats.DNS_FAILURE || 0) +
                  (cats.AUTH_FAILURE || 0) + (cats.ROAM_FAILURE || 0) + (cats.ARP_FAILURE || 0);
  const total = success + failure;
  if (total === 0) return null;
  return 1.0 - (failure / total);
}

const SERVICE_BUCKETS = [
  { svc: "auth", success: "AUTH_SUCCESS", failure: "AUTH_FAILURE" },
  { svc: "roam", success: "ROAM_SUCCESS", failure: "ROAM_FAILURE" },
  { svc: "dhcp", success: "DHCP_SUCCESS", failure: "DHCP_FAILURE" },
  { svc: "dns",  success: "DNS_SUCCESS",  failure: "DNS_FAILURE" },
  { svc: "arp",  success: "ARP_SUCCESS",  failure: "ARP_FAILURE" },
];
const SERVICE_HEALTH_THRESHOLD = 0.50;

function computeMacServiceAlarms(cats) {
  const out = [];
  for (const b of SERVICE_BUCKETS) {
    const s = cats[b.success] || 0;
    const f = cats[b.failure] || 0;
    const total = s + f;
    if (total === 0) continue;
    const health = s / total;
    if (health < SERVICE_HEALTH_THRESHOLD) {
      out.push({ svc: b.svc, health });
    }
  }
  return out;
}

function ServiceAlarmCards({ alarms }) {
  if (!alarms || alarms.length === 0) {
    return <span style={{ color: "#444", fontSize: "11px" }}>—</span>;
  }
  return (
    <span style={{ display: "flex", flexWrap: "wrap", gap: "3px" }}>
      {alarms.map((a) => (
        <span
          key={a.svc}
          title={`${a.svc.toUpperCase()} health ${Math.round(a.health * 100)}%`}
          style={{
            background: "#e0555522",
            color: "#e05555",
            border: "1px solid #e0555544",
            borderRadius: "3px",
            padding: "1px 5px",
            fontSize: "10px",
            textTransform: "uppercase",
            letterSpacing: "0.04em",
            fontWeight: 600,
          }}
        >
          {a.svc}
        </span>
      ))}
    </span>
  );
}

function healthColor(score) {
  if (score >= 0.85) return "#4caf7d";
  if (score >= 0.75) return "#e0a835";
  if (score >= 0.55) return "#e07835";
  return "#e05555";
}

const PAGE_SIZE = 500;

export default function OrgFamilyDrilldown({ family, apiBase, onMacSiteSelect, onBack, wlan, allWlans, searchQuery, macSearchQuery }) {
  const [data, setData]       = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState(null);
  const [page, setPage]       = useState(1);
  const [exporting, setExporting] = useState(false);

  const [sortCol, setSortCol] = useState("if_score");
  const [sortDir, setSortDir] = useState("asc");
  const [filterText, setFilterText] = useState("");
  const [filterTags, setFilterTags] = useState([]);
  const [scope, setScope] = useState("site");
  const [visibleCols, setVisibleCols] = useState(() =>
    loadVisibleFromStorage("orgFamilyDrilldown.columns.v3", DEFAULT_VISIBLE)
  );

  useEffect(() => {
    setLoading(true);
    setError(null);
    const sortParams = `&sort=${encodeURIComponent(sortCol)}&sort_dir=${encodeURIComponent(sortDir)}`;
    let url;
    if (macSearchQuery) {
      url = `${apiBase}/api/v1/org/clients/search-drilldown?mac_prefix=${encodeURIComponent(macSearchQuery)}&page=${page}&page_size=${PAGE_SIZE}${sortParams}&scope=${scope}`;
    } else if (searchQuery) {
      url = `${apiBase}/api/v1/org/families/search-drilldown?q=${encodeURIComponent(searchQuery)}&page=${page}&page_size=${PAGE_SIZE}${sortParams}&scope=${scope}`;
    } else if (allWlans) {
      url = `${apiBase}/api/v1/org/families/${encodeURIComponent(family)}/drilldown-all-wlans?page=${page}&page_size=${PAGE_SIZE}${sortParams}`;
    } else {
      url = `${apiBase}/api/v1/org/families/${encodeURIComponent(family)}/drilldown?wlan=${encodeURIComponent(wlan)}&page=${page}&page_size=${PAGE_SIZE}${sortParams}`;
    }
    apiFetch(url)
      .then(r => {
        if (!r.ok) return r.json().then(e => Promise.reject(e.detail || r.statusText));
        return r.json();
      })
      .then(d => { setData(d); setLoading(false); })
      .catch(e => { setError(String(e)); setLoading(false); });
  }, [family, apiBase, wlan, allWlans, searchQuery, macSearchQuery, page, sortCol, sortDir, scope]);

  // Reset to page 1 when the query/family/scope changes
  useEffect(() => { setPage(1); }, [family, wlan, allWlans, searchQuery, macSearchQuery, scope]);

  const handleExportCsv = async () => {
    if (!data || exporting) return;
    setExporting(true);
    try {
      // Build the base URL (without pagination) then fetch all pages
      let baseUrl;
      if (macSearchQuery) {
        baseUrl = `${apiBase}/api/v1/org/clients/search-drilldown?mac_prefix=${encodeURIComponent(macSearchQuery)}&scope=${scope}`;
      } else if (searchQuery) {
        baseUrl = `${apiBase}/api/v1/org/families/search-drilldown?q=${encodeURIComponent(searchQuery)}&scope=${scope}`;
      } else if (allWlans) {
        baseUrl = `${apiBase}/api/v1/org/families/${encodeURIComponent(family)}/drilldown-all-wlans?`;
      } else {
        baseUrl = `${apiBase}/api/v1/org/families/${encodeURIComponent(family)}/drilldown?wlan=${encodeURIComponent(wlan)}`;
      }
      const sep = baseUrl.includes("?") ? "&" : "?";
      const sortParams = `&sort=${encodeURIComponent(sortCol)}&sort_dir=${encodeURIComponent(sortDir)}`;
      const totalPages = data.total_pages || 1;
      let allRows = [];
      for (let p = 1; p <= totalPages; p++) {
        const url = `${baseUrl}${sep}page=${p}&page_size=${PAGE_SIZE}${sortParams}`;
        const r = await apiFetch(url);
        if (!r.ok) break;
        const d = await r.json();
        allRows = allRows.concat(d.rows || []);
      }
      // Apply client-side filter tags
      const filtered = filterTags.length > 0
        ? allRows.filter((row) => {
            const alarms = computeMacServiceAlarms(row.categories);
            const alarmStr = alarms.map(a => a.svc).join(" ");
            const haystack = [
              row.mac, row.site_name, row.wlan || "", row.device_family || "",
              row.last_username || "", alarmStr, alarms.length > 0 ? "alarm" : "",
            ].join(" ").toLowerCase();
            return filterTags.every(tag => haystack.includes(tag.toLowerCase()));
          })
        : allRows;
      const csvName = macSearchQuery ? `mac_${macSearchQuery}` : family;
      downloadDrilldownCsv(filtered, csvName, {
        includeWlan: !!allWlans || !!searchQuery || !!macSearchQuery,
        includeDeviceFamily: !!searchQuery || !!macSearchQuery,
        includePrimaryFamily: data?.family_kind === "service_account",
      });
    } finally {
      setExporting(false);
    }
  };

  const handleSort = (col) => {
    if (sortCol === col) {
      setSortDir(d => d === "asc" ? "desc" : "asc");
    } else {
      setSortCol(col);
      setSortDir(col === "mac" || col === "site_name" || col === "wlan" || col === "device_family" || col === "health" ? "asc" : "desc");
    }
    setPage(1);
  };

  const filteredRows = data ? data.rows.filter((row) => {
    if (filterTags.length === 0) return true;
    const alarms = computeMacServiceAlarms(row.categories);
    const alarmStr = alarms.map(a => a.svc).join(" ");
    const haystack = [
      row.mac,
      row.site_name,
      row.wlan || "",
      row.device_family || "",
      row.last_username || "",
      alarmStr,
      alarms.length > 0 ? "alarm" : "",
    ].join(" ").toLowerCase();
    return filterTags.every(tag => haystack.includes(tag.toLowerCase()));
  }) : [];

  // Sorting is handled server-side; filteredRows preserves the API order.
  const sortedRows = filteredRows;

  const SortTh = ({ col, children, style = {} }) => (
    <th style={{ ...thStyle, ...style }}>
      <button
        onClick={() => handleSort(col)}
        style={{
          background: "none", border: "none", padding: 0, cursor: "pointer",
          color: sortCol === col ? "#7ec8e3" : "#666",
          fontSize: "12px", fontWeight: "normal",
          display: "flex", alignItems: "center", gap: "2px", whiteSpace: "nowrap",
        }}
      >
        {children}
        <span style={{ fontSize: "9px", opacity: sortCol === col ? 1 : 0.3 }}>
          {sortCol === col ? (sortDir === "asc" ? "▲" : "▼") : "⇅"}
        </span>
      </button>
    </th>
  );

  return (
    <div>
      <div style={{ display: "flex", alignItems: "center", gap: "12px", marginBottom: "16px" }}>
        <button
          onClick={onBack}
          style={{
            background: "#1a1a1a", color: "#888", border: "1px solid #333",
            padding: "4px 10px", borderRadius: "4px", cursor: "pointer", fontSize: "12px",
          }}
        >
          ← {allWlans ? "Back" : "Org Family Insights"}
        </button>
        <h2 style={{ margin: 0, fontSize: "15px", color: "#aaa" }}>
          {macSearchQuery
            ? <>MAC prefix: <span style={{ fontFamily: "monospace", color: "#7ec8e3" }}>{macSearchQuery}</span></>
            : searchQuery
              ? <>{`"${searchQuery}"`}</>
              : data?.family_kind === "service_account" && data?.service_account_label
                ? data.service_account_label
                : family}
        </h2>
        {(searchQuery || macSearchQuery) && data?.matched_families && (
          <span style={{ color: "#666", fontSize: "12px" }}>
            {data.matched_families.length} {data.matched_families.length === 1 ? "family" : "families"} matched
          </span>
        )}
        {data?.family_kind === "service_account" && (
          <span
            style={{ background: SA_BG, color: SA_COLOR, border: `1px solid ${SA_COLOR}55`, borderRadius: "3px", padding: "2px 7px", fontSize: "10px", fontWeight: "bold", letterSpacing: "0.05em" }}
            title="Service account: same username shared across multiple devices"
          >
            SVC ACCT
          </span>
        )}
        <span style={{ color: "#555", fontSize: "12px" }}>{allWlans || searchQuery || macSearchQuery ? "org-wide · all WLANs" : "org-wide"}</span>
        <div style={{ flex: 1 }} />
        <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: "6px" }}>
          <div style={{ display: "flex", gap: "6px", alignItems: "center" }}>
            {(searchQuery || macSearchQuery) && (
              <div
                title="Toggle between site-local and org-wide scoring for IF, DBSCAN, and Centroid flags. Markov is always site-WLAN scoped regardless."
                style={{
                  display: "inline-flex", alignItems: "center",
                  background: "#1a1a1a", border: "1px solid #333",
                  borderRadius: "4px", padding: "2px", gap: "2px",
                }}
              >
                <span style={{ color: "#666", fontSize: "11px", padding: "0 6px" }}>
                  IF/DBSCAN/Centroid:
                </span>
                {["site", "org"].map((s) => (
                  <button
                    key={s}
                    onClick={() => setScope(s)}
                    style={{
                      background: scope === s ? "#0d2535" : "transparent",
                      color: scope === s ? "#7ec8e3" : "#888",
                      border: scope === s ? "1px solid #2a6a8a" : "1px solid transparent",
                      padding: "2px 8px", borderRadius: "3px",
                      cursor: "pointer", fontSize: "11px",
                      textTransform: "capitalize",
                    }}
                  >
                    {s}
                  </button>
                ))}
              </div>
            )}
            {sortedRows.length > 0 && (
              <button
                onClick={handleExportCsv}
                disabled={exporting}
                style={{
                  background: "#1a1a1a", color: exporting ? "#555" : "#7ec8e3",
                  border: `1px solid ${exporting ? "#333" : "#2a6a8a"}`,
                  padding: "4px 10px", borderRadius: "4px",
                  cursor: exporting ? "wait" : "pointer", fontSize: "12px",
                }}
                title="Download all filtered data as CSV (fetches all pages)"
              >
                {exporting ? "Exporting…" : "Export CSV"}
              </button>
            )}
            <ColumnSelector
              columns={COLUMN_DEFS}
              visible={visibleCols}
              onChange={setVisibleCols}
              storageKey="orgFamilyDrilldown.columns.v3"
            />
          </div>
          {data?.total_pages > 1 && (
            <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
              <button
                onClick={() => setPage(1)}
                disabled={page <= 1 || loading}
                style={{
                  background: "#1a1a1a", color: page <= 1 ? "#444" : "#7ec8e3",
                  border: "1px solid #333", padding: "3px 6px", borderRadius: "4px",
                  cursor: page <= 1 ? "default" : "pointer", fontSize: "11px",
                }}
              >
                ««
              </button>
              <button
                onClick={() => setPage(p => Math.max(1, p - 1))}
                disabled={page <= 1 || loading}
                style={{
                  background: "#1a1a1a", color: page <= 1 ? "#444" : "#7ec8e3",
                  border: "1px solid #333", padding: "3px 8px", borderRadius: "4px",
                  cursor: page <= 1 ? "default" : "pointer", fontSize: "11px",
                }}
              >
                ← Prev
              </button>
              <span style={{ fontSize: "11px", color: "#888" }}>
                Page {data.page} of {data.total_pages}
              </span>
              <button
                onClick={() => setPage(p => Math.min(data.total_pages, p + 1))}
                disabled={page >= data.total_pages || loading}
                style={{
                  background: "#1a1a1a", color: page >= data.total_pages ? "#444" : "#7ec8e3",
                  border: "1px solid #333", padding: "3px 8px", borderRadius: "4px",
                  cursor: page >= data.total_pages ? "default" : "pointer", fontSize: "11px",
                }}
              >
                Next →
              </button>
              <button
                onClick={() => setPage(data.total_pages)}
                disabled={page >= data.total_pages || loading}
                style={{
                  background: "#1a1a1a", color: page >= data.total_pages ? "#444" : "#7ec8e3",
                  border: "1px solid #333", padding: "3px 6px", borderRadius: "4px",
                  cursor: page >= data.total_pages ? "default" : "pointer", fontSize: "11px",
                }}
              >
                »»
              </button>
            </div>
          )}
        </div>
      </div>

      {data?.family_kind === "service_account" && data?.service_account_member_families?.length > 0 && (
        <div
          style={{
            background: SA_BG,
            border: `1px solid ${SA_COLOR}44`,
            borderLeft: `3px solid ${SA_COLOR}`,
            borderRadius: "4px",
            padding: "10px 12px",
            marginBottom: "14px",
            fontSize: "12px",
            color: "#bbb",
          }}
        >
          <div style={{ color: SA_COLOR, fontSize: "11px", fontWeight: "bold", letterSpacing: "0.06em", textTransform: "uppercase", marginBottom: "4px" }}>
            Service account · spans {data.service_account_member_families.length} device {data.service_account_member_families.length === 1 ? "family" : "families"}
          </div>
          <div style={{ color: "#999" }}>
            Username <span style={{ color: SA_COLOR, fontFamily: "monospace" }}>{data.service_account_label}</span>{" "}
            shared across: {data.service_account_member_families.join(", ")}
          </div>
        </div>
      )}

      {loading && <div style={{ color: "#888", fontSize: "13px" }}>Loading…</div>}
      {error && <div style={{ color: "#e05555", fontSize: "13px" }}>Error: {error}</div>}

      {!loading && data && (
        <>
          <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "12px", flexWrap: "wrap" }}>
            <input
              type="text"
              value={filterText}
              onChange={e => setFilterText(e.target.value)}
              onKeyDown={e => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  const val = filterText.trim();
                  if (val && !filterTags.includes(val)) {
                    setFilterTags(prev => [...prev, val]);
                  }
                  setFilterText("");
                }
              }}
              placeholder={filterTags.length > 0 ? "Add another filter…" : "Filter: mac, site, family, alarm…"}
              style={{
                background: "#1a1a1a",
                color: "#ccc",
                border: "1px solid #333",
                borderRadius: "4px",
                padding: "5px 10px",
                fontSize: "12px",
                width: "260px",
                outline: "none",
              }}
              onFocus={e => e.target.style.borderColor = "#7ec8e3"}
              onBlur={e => e.target.style.borderColor = "#333"}
            />
            {filterTags.map((tag, i) => (
              <span
                key={i}
                style={{
                  display: "inline-flex", alignItems: "center", gap: "4px",
                  background: "#0d2535", color: "#7ec8e3", border: "1px solid #2a6a8a",
                  borderRadius: "3px", padding: "2px 8px", fontSize: "11px",
                }}
              >
                {tag}
                <span
                  onClick={() => setFilterTags(prev => prev.filter((_, j) => j !== i))}
                  style={{ cursor: "pointer", color: "#5a8a9a", fontSize: "13px", lineHeight: 1, marginLeft: "2px" }}
                  title="Remove filter"
                >
                  ×
                </span>
              </span>
            ))}
            <div style={{ fontSize: "12px", color: "#666" }}>
              {data.total_count} clients across all sites.{" "}
              <span style={{ color: "#e05555" }}>{data.if_outlier_count} flagged</span> by Isolation Forest
              {data.counts_scope === "page" && <span style={{ color: "#555" }}> (this page)</span>}.{" "}
              <span style={{ color: "#e05555" }}>{data.dbscan_outlier_count} flagged</span> by DBSCAN
              {data.counts_scope === "page" && <span style={{ color: "#555" }}> (this page)</span>}.{" "}
              <span style={{ color: "#e05555" }}>{data.markov_outlier_count} flagged</span> by Markov.
              {filterTags.length > 0 && (
                <span style={{ color: "#7ec8e3" }}>{" "}· {sortedRows.length} shown</span>
              )}
            </div>
          </div>

          {sortedRows.length === 0 ? (
            <div style={{ color: "#555", fontSize: "13px" }}>No clients found.</div>
          ) : (
            <div style={{ overflowX: "auto" }}>
              <table style={{ borderCollapse: "collapse", fontSize: "12px" }}>
                <thead>
                  <tr>
                    {visibleCols.site && <SortTh col="site_name">Site</SortTh>}
                    {visibleCols.wlan && allWlans && <SortTh col="wlan">WLAN</SortTh>}
                    {visibleCols.device_family && (searchQuery || macSearchQuery) && <SortTh col="device_family">Device Family</SortTh>}
                    {visibleCols.mac && <SortTh col="mac">MAC</SortTh>}
                    {visibleCols.primary_family && data.family_kind === "service_account" && (
                      <th style={thStyle}>Primary Family</th>
                    )}
                    {visibleCols.health && <SortTh col="health" style={{ minWidth: "90px" }}>Health</SortTh>}
                    {visibleCols.service_alarm && <th style={{ ...thStyle, minWidth: "100px" }}>Service Alarm</th>}
                    {visibleCols.if_score && <SortTh col="if_score" style={{ minWidth: "120px" }}>IF Score</SortTh>}
                    {visibleCols.if_flag && <th style={thStyle}>▲IF</th>}
                    {visibleCols.dbscan && <th style={thStyle}>DBSCAN</th>}
                    {visibleCols.markov && <SortTh col="markov_ratio" style={{ minWidth: "80px" }}>Markov</SortTh>}
                    {EVENT_CATEGORIES.map(cat => (
                      visibleCols[`cat_${cat}`] && <SortTh key={cat} col={cat}>{CATEGORY_LABELS[cat]}</SortTh>
                    ))}
                    {visibleCols.total_events && <SortTh col="total_events">Total</SortTh>}
                    {/* Metadata */}
                    {visibleCols.model && <th style={thStyle}>Model</th>}
                    {visibleCols.os && <th style={thStyle}>OS</th>}
                    {visibleCols.manufacturer && <th style={thStyle}>Manufacturer</th>}
                  </tr>
                </thead>
                <tbody>
                  {sortedRows.map((row, i) => {
                    const bar = scoreBar(row.if_score);
                    const rowBg = row.is_if_outlier ? "#1a1510" : "transparent";
                    return (
                      <tr
                        key={`${row.site_id}-${row.wlan || ""}-${row.mac}`}
                        onClick={() => onMacSiteSelect(row.mac, row.site_id)}
                        style={{ cursor: "pointer", background: rowBg }}
                        onMouseEnter={e => e.currentTarget.style.background = "#1a2530"}
                        onMouseLeave={e => e.currentTarget.style.background = rowBg}
                      >
                        {visibleCols.site && (
                          <td style={{ ...tdStyle, color: "#888", whiteSpace: "nowrap", fontSize: "11px" }}>
                            {row.site_name}
                          </td>
                        )}
                        {visibleCols.wlan && allWlans && (
                          <td style={{ ...tdStyle, whiteSpace: "nowrap", fontSize: "11px" }}>
                            <span style={{ background: "#1a2a1a", color: "#4caf7d", border: "1px solid #2d4a2d", borderRadius: "3px", padding: "1px 5px", fontSize: "10px" }}>{row.wlan}</span>
                          </td>
                        )}
                        {visibleCols.device_family && (searchQuery || macSearchQuery) && (
                          <td style={{ ...tdStyle, color: "#aaa", fontSize: "11px", whiteSpace: "nowrap" }}>
                            {row.device_family || "—"}
                          </td>
                        )}
                        {visibleCols.mac && (
                          <td style={{ ...tdStyle, color: "#7ec8e3", fontFamily: "monospace", whiteSpace: "nowrap" }}>
                            {row.mac}
                            {row.random_mac && (
                              <span style={{ color: "#555", fontSize: "10px", marginLeft: "6px" }}>rnd</span>
                            )}
                            {row.last_username && (
                              <span style={{ color: SA_COLOR, fontSize: "10px", marginLeft: "6px", fontFamily: "monospace" }}
                                title={`username: ${row.last_username}`}>
                                {row.last_username}
                              </span>
                            )}
                          </td>
                        )}
                        {visibleCols.primary_family && data.family_kind === "service_account" && (
                          <td style={{ ...tdStyle, color: "#888", fontSize: "11px", whiteSpace: "nowrap" }}>
                            {row.primary_device_family || "—"}
                          </td>
                        )}
                        {visibleCols.health && (
                          <td style={{ ...tdStyle, minWidth: "90px" }}>
                            {(() => {
                              const h = computeMacHealth(row.categories);
                              if (h === null) return <span style={{ color: "#444" }}>—</span>;
                              const color = healthColor(h);
                              const pct = Math.round(h * 100);
                              return (
                                <div style={{ display: "flex", alignItems: "center", gap: "5px" }}>
                                  <div style={{ width: "40px", height: "6px", background: "#222", borderRadius: "2px", overflow: "hidden" }}>
                                    <div style={{ width: `${pct}%`, height: "100%", background: color, borderRadius: "2px" }} />
                                  </div>
                                  <span style={{ fontSize: "11px", color }}>{pct}%</span>
                                </div>
                              );
                            })()}
                          </td>
                        )}
                        {visibleCols.service_alarm && (
                          <td style={{ ...tdStyle, minWidth: "100px" }}>
                            <ServiceAlarmCards alarms={computeMacServiceAlarms(row.categories)} />
                          </td>
                        )}
                        {visibleCols.if_score && (
                          <td style={{ ...tdStyle, minWidth: "120px" }}>
                            {bar ? (
                              <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                                <div style={{ width: "60px", height: "8px", background: "#222", borderRadius: "2px", overflow: "hidden" }}>
                                  <div style={{ width: `${Math.round(bar.fraction * 100)}%`, height: "100%", background: bar.color, borderRadius: "2px" }} />
                                </div>
                                <span style={{ color: "#888", fontSize: "11px" }}>{row.if_score.toFixed(3)}</span>
                              </div>
                            ) : (
                              <span style={{ color: "#555" }}>—</span>
                            )}
                          </td>
                        )}
                        {visibleCols.if_flag && (
                          <td style={{ ...tdStyle, textAlign: "center" }}>
                            {row.is_if_outlier ? (
                              <span style={{
                                color: SEVERITY_COLOR.significant, fontSize: "10px",
                                background: SEVERITY_COLOR.significant + "22", padding: "1px 5px",
                                borderRadius: "3px", border: `1px solid ${SEVERITY_COLOR.significant}44`,
                              }}>▲</span>
                            ) : (
                              <span style={{ color: "#333", fontSize: "10px" }}>—</span>
                            )}
                          </td>
                        )}
                        {visibleCols.dbscan && (
                          <td style={{ ...tdStyle, textAlign: "center" }}>
                            {row.is_dbscan_outlier ? (
                              <span style={{
                                color: SEVERITY_COLOR.significant, fontSize: "10px",
                                background: SEVERITY_COLOR.significant + "22", padding: "1px 5px",
                                borderRadius: "3px", border: `1px solid ${SEVERITY_COLOR.significant}44`,
                              }}>YES</span>
                            ) : (
                              <span style={{ color: "#444", fontSize: "10px" }}>—</span>
                            )}
                          </td>
                        )}
                        {visibleCols.markov && (
                          <td style={{ ...tdStyle, textAlign: "center", minWidth: "80px" }}>
                            {row.is_markov_outlier ? (
                              <span
                                title={`Markov ${row.markov_reason || "anomaly"}: ${row.markov_anomalous_episodes}/${row.markov_scoreable_episodes} episodes anomalous`}
                                style={{
                                  color: "#4ab0e8", fontSize: "10px",
                                  background: "#0d2535", padding: "1px 5px",
                                  borderRadius: "3px", border: "1px solid #2a6a8a",
                                  whiteSpace: "nowrap",
                                }}
                              >
                                {row.markov_reason || "chain"}
                              </span>
                            ) : row.markov_scoreable_episodes > 0 ? (
                              <span
                                title={`${row.markov_anomalous_episodes}/${row.markov_scoreable_episodes} episodes anomalous`}
                                style={{ color: "#2d7a4f", fontSize: "10px" }}
                              >OK</span>
                            ) : (
                              <span style={{ color: "#333", fontSize: "10px" }}>—</span>
                            )}
                          </td>
                        )}
                        {EVENT_CATEGORIES.map(cat => (
                          visibleCols[`cat_${cat}`] && (
                            <td key={cat} style={{ ...tdStyle, color: (row.categories[cat] || 0) > 0 ? "#aaa" : "#333", textAlign: "right" }}>
                              {(row.categories[cat] || 0) > 0 ? row.categories[cat] : "—"}
                            </td>
                          )
                        ))}
                        {visibleCols.total_events && (
                          <td style={{ ...tdStyle, color: "#ccc", textAlign: "right", fontWeight: "500" }}>
                            {row.total_events}
                          </td>
                        )}
                        {visibleCols.model && <td style={{ ...tdStyle, color: "#999" }}>{row.client_metadata?.model || "—"}</td>}
                        {visibleCols.os && <td style={{ ...tdStyle, color: "#999" }}>{row.client_metadata?.os || "—"}</td>}
                        {visibleCols.manufacturer && <td style={{ ...tdStyle, color: "#999" }}>{row.client_metadata?.manufacturer || "—"}</td>}
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}

          <div style={{ marginTop: "8px", fontSize: "11px", color: "#444" }}>
            ▲IF = Isolation Forest outlier {(searchQuery || macSearchQuery) ? `(${data.scope || "site"}-scope)` : "within site peer group"}.
            DBSCAN = {(searchQuery || macSearchQuery) ? `flagged ${data.scope === "org" ? "org-wide" : "site-wide"}` : "flagged site-wide"}.
            Markov = anomaly (anomalous connection-chain transitions) or repeated (stuck failure loop) — always site-WLAN scoped; hover for episode counts.
            Click a row to open MAC timeline.
          </div>
        </>
      )}
    </div>
  );
}
