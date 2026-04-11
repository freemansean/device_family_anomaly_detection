import { useState, useEffect, useCallback, useRef } from "react";
import { apiFetch } from "../api";
import { familyColor } from "./familyColors";

const W = 600;
const H = 440;
const PAD = 40;

const HIDDEN_FAMILIES = new Set(["Unknown", "IoT (Unknown)"]);
const MIN_DISPLAY_CLIENTS = 5;
// If there are too many points, sample down for rendering performance.
const MAX_RENDER_POINTS = 4000;

function siteColor(siteId) {
  let hash = 0;
  for (let i = 0; i < siteId.length; i++) {
    hash = (siteId.charCodeAt(i) + ((hash << 5) - hash)) | 0;
  }
  const hue = Math.abs(hash) % 360;
  return `hsl(${hue}, 55%, 56%)`;
}

function scaleCoords(points) {
  if (!points.length) return [];
  const xs = points.map(p => p.x);
  const ys = points.map(p => p.y);
  const xMin = Math.min(...xs), xMax = Math.max(...xs);
  const yMin = Math.min(...ys), yMax = Math.max(...ys);
  const xRange = xMax - xMin || 1;
  const yRange = yMax - yMin || 1;
  const plotW = W - PAD * 2;
  const plotH = H - PAD * 2;
  return points.map(p => ({
    ...p,
    sx: PAD + ((p.x - xMin) / xRange) * plotW,
    sy: PAD + ((yMax - p.y) / yRange) * plotH, // SVG y-axis inverted
  }));
}

// Deterministic subsample — keeps outliers, samples normals.
function subsample(points, max) {
  if (points.length <= max) return points;
  const outliers = points.filter(p => p.is_outlier);
  const normals  = points.filter(p => !p.is_outlier);
  const budget   = Math.max(0, max - outliers.length);
  // Deterministic shuffle via index parity so the sample is stable across re-renders.
  const sampled  = normals.filter((_, i) => i % Math.ceil(normals.length / budget) === 0).slice(0, budget);
  return [...outliers, ...sampled];
}

export default function OrgClusterViz({ apiBase, onMacSiteSelect, refreshToken, wlan, selectedFamilies }) {
  const [data, setData]             = useState(null);
  const [loading, setLoading]       = useState(true);
  const [error, setError]           = useState(null);
  const [tooltip, setTooltip]       = useState(null);
  const [colorMode, setColorMode]   = useState("family"); // "family" | "site"
  const svgRef = useRef(null);

  const load = useCallback(() => {
    setLoading(true);
    apiFetch(`${apiBase}/api/v1/org/cluster-viz?wlan=${encodeURIComponent(wlan)}`)
      .then(r => r.json())
      .then(d => { setData(d); setError(null); })
      .catch(e => setError(e.message))
      .finally(() => setLoading(false));
  }, [apiBase, refreshToken, wlan]);

  useEffect(() => {
    load();
    const iv = setInterval(load, 90_000);
    return () => clearInterval(iv);
  }, [load]);

  if (loading && !data) return (
    <div style={{ color: "#555", fontSize: "12px", padding: "12px 0" }}>Loading org cluster view…</div>
  );
  if (error) return (
    <div style={{ color: "#e05555", fontSize: "12px", padding: "8px 0" }}>Org cluster viz unavailable</div>
  );
  if (!data || !data.points?.length) return (
    <div style={{ color: "#444", fontSize: "12px", padding: "12px 0" }}>
      No cluster data yet — run Full Discovery across org sites first.
    </div>
  );

  // Count MACs per family to apply the same MIN_DISPLAY_CLIENTS filter as per-site ClusterViz.
  const familyCounts = {};
  for (const p of data.points) {
    if (!HIDDEN_FAMILIES.has(p.device_family)) {
      familyCounts[p.device_family] = (familyCounts[p.device_family] ?? 0) + 1;
    }
  }

  // When the caller passes an explicit selection, honor it as-is (don't apply the
  // min-size declutter — the user explicitly opted that family in via checkbox).
  const filtered = data.points.filter(p => {
    if (HIDDEN_FAMILIES.has(p.device_family)) return false;
    if (selectedFamilies) return selectedFamilies.has(p.device_family);
    return (familyCounts[p.device_family] ?? 0) >= MIN_DISPLAY_CLIENTS;
  });

  const sampled = subsample(filtered, MAX_RENDER_POINTS);
  const scaled  = scaleCoords(sampled);

  // Build legend entries for each mode.
  const families   = [...new Set(scaled.map(p => p.device_family))].sort();
  const siteEntries = [...new Map(scaled.map(p => [p.site_id, p.site_name])).entries()]
    .map(([id, name]) => ({ id, name }))
    .sort((a, b) => a.name.localeCompare(b.name));

  const legendItems = colorMode === "family"
    ? families.map(f => ({ key: f, label: f, color: familyColor(f) }))
    : siteEntries.map(s => ({ key: s.id, label: s.name, color: siteColor(s.id) }));

  const pointColor = p => colorMode === "family" ? familyColor(p.device_family) : siteColor(p.site_id);

  const visiblePoints = scaled;

  const [ev0, ev1] = data.explained_variance || [];
  const sampledNote = filtered.length > MAX_RENDER_POINTS
    ? ` · showing ${sampled.length.toLocaleString()} of ${filtered.length.toLocaleString()} MACs`
    : "";

  return (
    <div style={{ userSelect: "none", width: `${W}px` }}>
      {/* Header row */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "6px" }}>
        <div style={{ fontSize: "12px", color: "#666" }}>
          Org PCA — {data.total_points?.toLocaleString()} MACs · {data.site_count} sites
          {ev0 != null && (
            <span style={{ marginLeft: "8px", color: "#444" }}>
              PC1 {(ev0 * 100).toFixed(1)}% · PC2 {(ev1 * 100).toFixed(1)}% variance
            </span>
          )}
          {sampledNote && <span style={{ color: "#444" }}>{sampledNote}</span>}
        </div>
        {/* Color mode toggle */}
        <div style={{ display: "flex", border: "1px solid #2a2a2a", borderRadius: "4px", overflow: "hidden" }}>
          {["family", "site"].map(mode => (
            <button
              key={mode}
              onClick={() => setColorMode(mode)}
              style={{
                background: colorMode === mode ? "#2a3a4a" : "#161616",
                color: colorMode === mode ? "#7ec8e3" : "#555",
                border: "none",
                padding: "3px 10px",
                cursor: "pointer",
                fontSize: "11px",
              }}
            >
              by {mode}
            </button>
          ))}
        </div>
      </div>

      {/* SVG chart */}
      <svg
        ref={svgRef}
        width={W}
        height={H}
        style={{ background: "#111", borderRadius: "4px", border: "1px solid #222", display: "block" }}
        onMouseLeave={() => setTooltip(null)}
      >
        <line x1={PAD} y1={H - PAD} x2={W - PAD} y2={H - PAD} stroke="#1e1e1e" strokeWidth={1} />
        <line x1={PAD} y1={PAD}     x2={PAD}     y2={H - PAD} stroke="#1e1e1e" strokeWidth={1} />

        {/* Normal points first, outliers on top */}
        {[false, true].map(outlierPass =>
          visiblePoints
            .filter(p => p.is_outlier === outlierPass)
            .map((p, i) => {
              const color = pointColor(p);
              const r = p.is_outlier ? 5 : 3;
              return (
                <g
                  key={`${outlierPass}-${i}`}
                  style={{ cursor: onMacSiteSelect ? "pointer" : "default" }}
                  onClick={() => onMacSiteSelect && onMacSiteSelect(p.mac, p.site_id)}
                >
                  {p.is_outlier && (
                    <circle cx={p.sx} cy={p.sy} r={r + 3} fill="none" stroke={color} strokeWidth={1} opacity={0.45} />
                  )}
                  <circle
                    cx={p.sx}
                    cy={p.sy}
                    r={r}
                    fill={color}
                    opacity={p.is_outlier ? 1.0 : 0.6}
                    onMouseEnter={e => {
                      const rect = svgRef.current?.getBoundingClientRect();
                      setTooltip({ x: e.clientX - (rect?.left ?? 0), y: e.clientY - (rect?.top ?? 0), point: p });
                    }}
                    onMouseLeave={() => setTooltip(null)}
                  />
                </g>
              );
            })
        )}

        {/* Tooltip */}
        {tooltip && (() => {
          const { x, y, point } = tooltip;
          const tipW = 180;
          const tipH = point.is_outlier ? 72 : 60;
          const bx = Math.min(x + 10, W - tipW - 4);
          const by = Math.min(y - 10, H - tipH - 4);
          return (
            <g style={{ pointerEvents: "none" }}>
              <rect x={bx} y={by} width={tipW} height={tipH} rx={3} fill="#1a1a1a" stroke="#333" strokeWidth={1} />
              <text x={bx + 8} y={by + 15} fontSize={10} fill="#aaa">{point.device_family}</text>
              <text x={bx + 8} y={by + 28} fontSize={9}  fill="#666">{point.site_name}</text>
              <text x={bx + 8} y={by + 40} fontSize={9}  fill="#444" fontFamily="monospace">{point.mac}</text>
              {point.is_outlier && (
                <text x={bx + 8} y={by + 53} fontSize={9} fill="#e05555">⚠ outlier</text>
              )}
              {onMacSiteSelect && (
                <text x={bx + 8} y={by + (point.is_outlier ? 66 : 53)} fontSize={9} fill="#4a90c4">click to open →</text>
              )}
            </g>
          );
        })()}
      </svg>

      {/* Legend — selection is controlled by the PCA column in the Family Insights table */}
      <div style={{ marginTop: "8px", display: "flex", flexWrap: "wrap", gap: "5px 10px", maxHeight: "56px", overflowY: "auto" }}>
        {legendItems.map(item => (
          <div
            key={item.key}
            style={{ display: "flex", alignItems: "center", gap: "4px", fontSize: "10px", color: "#888" }}
          >
            <div style={{ width: 7, height: 7, borderRadius: "50%", background: item.color, flexShrink: 0 }} />
            {item.label}
          </div>
        ))}
        <div style={{ display: "flex", alignItems: "center", gap: "4px", fontSize: "10px", color: "#888" }}>
          <div style={{ width: 7, height: 7, borderRadius: "50%", border: "1.5px solid #e05555", flexShrink: 0 }} />
          outlier
        </div>
      </div>
    </div>
  );
}
