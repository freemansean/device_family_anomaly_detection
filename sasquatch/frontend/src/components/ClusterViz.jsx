import { useState, useEffect, useCallback, useRef } from "react";
import { apiFetch } from "../api";
import { familyColor } from "./familyColors";

const W = 380;
const H = 340;
const PAD = 36;

function scaleCoords(points) {
  if (!points.length) return [];
  const xs = points.map((p) => p.x);
  const ys = points.map((p) => p.y);
  const xMin = Math.min(...xs), xMax = Math.max(...xs);
  const yMin = Math.min(...ys), yMax = Math.max(...ys);
  const xRange = xMax - xMin || 1;
  const yRange = yMax - yMin || 1;
  const plotW = W - PAD * 2;
  const plotH = H - PAD * 2;
  return points.map((p) => ({
    ...p,
    sx: PAD + ((p.x - xMin) / xRange) * plotW,
    // SVG y-axis is inverted
    sy: PAD + ((yMax - p.y) / yRange) * plotH,
  }));
}

export default function ClusterViz({ siteId, apiBase, onMacSelect, refreshToken }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [tooltip, setTooltip] = useState(null);
  const [hiddenFamilies, setHiddenFamilies] = useState(new Set());
  const svgRef = useRef(null);

  const load = useCallback(() => {
    setLoading(true);
    apiFetch(`${apiBase}/api/v1/sites/${siteId}/cluster-viz`)
      .then((r) => r.json())
      .then((d) => { setData(d); setError(null); })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [siteId, apiBase, refreshToken]);

  useEffect(() => {
    load();
    const iv = setInterval(load, 60_000);
    return () => clearInterval(iv);
  }, [load]);

  if (loading && !data) return (
    <div style={{ color: "#555", fontSize: "12px", padding: "12px 0" }}>Loading cluster viz…</div>
  );
  if (error) return (
    <div style={{ color: "#e05555", fontSize: "12px" }}>Cluster viz unavailable</div>
  );
  if (!data || !data.points?.length) return (
    <div style={{ color: "#444", fontSize: "12px", padding: "12px 0" }}>No cluster data yet</div>
  );

  const HIDDEN_FAMILIES = new Set(["Unknown", "IoT (Unknown)"]);
  const MIN_DISPLAY_CLIENTS = 5;
  // Count MACs per family to match the SiteOverview threshold
  const familyPointCounts = {};
  for (const p of data.points) {
    if (!HIDDEN_FAMILIES.has(p.device_family)) {
      familyPointCounts[p.device_family] = (familyPointCounts[p.device_family] ?? 0) + 1;
    }
  }
  const scaled = scaleCoords(
    data.points.filter(
      (p) => !HIDDEN_FAMILIES.has(p.device_family) && (familyPointCounts[p.device_family] ?? 0) >= MIN_DISPLAY_CLIENTS
    )
  );

  // Unique families sorted for legend
  const families = [...new Set(scaled.map((p) => p.device_family))].sort();

  // DBSCAN cluster IDs (excluding -1 noise)
  const clusterIds = [...new Set(scaled.map((p) => p.dbscan_label).filter((l) => l != null && l >= 0))].sort((a, b) => a - b);

  const [ev0, ev1] = data.explained_variance || [];

  function toggleFamily(family) {
    setHiddenFamilies((prev) => {
      const next = new Set(prev);
      if (next.has(family)) next.delete(family);
      else next.add(family);
      return next;
    });
  }

  const visiblePoints = scaled.filter((p) => !hiddenFamilies.has(p.device_family));

  function handleDotClick(point) {
    if (onMacSelect) onMacSelect(point.mac);
  }

  return (
    <div style={{ userSelect: "none", width: `${W}px` }}>
      <div style={{ fontSize: "12px", color: "#666", marginBottom: "6px" }}>
        PCA Cluster View
        {ev0 != null && (
          <span style={{ marginLeft: "8px", color: "#444" }}>
            PC1 {(ev0 * 100).toFixed(1)}% · PC2 {(ev1 * 100).toFixed(1)}% variance
          </span>
        )}
      </div>

      <svg
        ref={svgRef}
        width={W}
        height={H}
        style={{ background: "#111", borderRadius: "4px", border: "1px solid #222", display: "block" }}
        onMouseLeave={() => setTooltip(null)}
      >
        {/* Axis lines */}
        <line x1={PAD} y1={H - PAD} x2={W - PAD} y2={H - PAD} stroke="#222" strokeWidth={1} />
        <line x1={PAD} y1={PAD} x2={PAD} y2={H - PAD} stroke="#222" strokeWidth={1} />

        {/* Points — normal first, outliers on top */}
        {[false, true].map((outlierPass) =>
          visiblePoints
            .filter((p) => p.is_outlier === outlierPass)
            .map((p, i) => {
              const color = familyColor(p.device_family);
              const r = p.is_outlier ? 5 : 3.5;
              const clickable = !!onMacSelect;
              return (
                <g key={`${outlierPass}-${i}`} style={{ cursor: clickable ? "pointer" : "default" }} onClick={() => handleDotClick(p)}>
                  {p.is_outlier && (
                    <circle cx={p.sx} cy={p.sy} r={r + 3} fill="none" stroke={color} strokeWidth={1} opacity={0.5} />
                  )}
                  <circle
                    cx={p.sx}
                    cy={p.sy}
                    r={r}
                    fill={color}
                    opacity={p.is_outlier ? 1.0 : 0.7}
                    onMouseEnter={(e) => {
                      const rect = svgRef.current?.getBoundingClientRect();
                      setTooltip({
                        x: e.clientX - (rect?.left ?? 0),
                        y: e.clientY - (rect?.top ?? 0),
                        point: p,
                      });
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
          const bx = Math.min(x + 10, W - 160);
          const by = Math.min(y - 10, H - 68);
          return (
            <g style={{ pointerEvents: "none" }}>
              <rect x={bx} y={by} width={150} height={point.is_outlier ? 60 : 48} rx={3} fill="#1a1a1a" stroke="#333" strokeWidth={1} />
              <text x={bx + 8} y={by + 15} fontSize={10} fill="#aaa">{point.device_family}</text>
              <text x={bx + 8} y={by + 28} fontSize={9} fill="#555">{point.mac}</text>
              {point.is_outlier && (
                <text x={bx + 8} y={by + 41} fontSize={9} fill="#e05555">⚠ outlier</text>
              )}
              {onMacSelect && (
                <text x={bx + 8} y={by + (point.is_outlier ? 54 : 41)} fontSize={9} fill="#4a90c4">click to open →</text>
              )}
            </g>
          );
        })()}
      </svg>

      {/* Legend — click to toggle family visibility */}
      <div style={{ marginTop: "8px", display: "flex", flexWrap: "wrap", gap: "6px 12px" }}>
        <div
          onClick={() => setHiddenFamilies(new Set(families))}
          style={{
            fontSize: "10px",
            color: "#555",
            cursor: "pointer",
            padding: "0 4px",
            borderRight: "1px solid #333",
            marginRight: "4px",
            lineHeight: "16px",
          }}
        >
          deselect all
        </div>
        {families.map((family) => {
          const hidden = hiddenFamilies.has(family);
          const color = familyColor(family);
          return (
            <div
              key={family}
              onClick={() => toggleFamily(family)}
              style={{
                display: "flex",
                alignItems: "center",
                gap: "4px",
                fontSize: "10px",
                color: hidden ? "#444" : "#888",
                cursor: "pointer",
                opacity: hidden ? 0.5 : 1,
                transition: "opacity 0.15s, color 0.15s",
              }}
            >
              <div style={{
                width: 8,
                height: 8,
                borderRadius: "50%",
                background: hidden ? "#333" : color,
                flexShrink: 0,
                transition: "background 0.15s",
              }} />
              {family}
            </div>
          );
        })}
        <div style={{ display: "flex", alignItems: "center", gap: "4px", fontSize: "10px", color: "#888" }}>
          <div style={{ width: 8, height: 8, borderRadius: "50%", border: "1.5px solid #e05555", flexShrink: 0 }} />
          outlier
        </div>
      </div>
    </div>
  );
}
