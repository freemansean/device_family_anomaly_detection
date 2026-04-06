import { useState, useEffect, useCallback } from "react";
import { apiFetch } from "../api";

const ORG_SCOPE_VALUE = "__org__";

// Severity badge colours — consistent with the rest of the dashboard
const SEVERITY_COLOR = {
  significant: "#e05555",
  moderate:    "#e0a835",
  minimal:     "#7ec8e3",
};

function FamilyCheckbox({ family, checked, onChange, disabled }) {
  const sev = family.worst_severity;
  const dot = sev ? (
    <span style={{ color: SEVERITY_COLOR[sev] || "#888", marginLeft: "6px", fontSize: "10px" }}>●</span>
  ) : null;

  return (
    <label
      style={{
        display: "flex",
        alignItems: "center",
        gap: "8px",
        padding: "7px 10px",
        borderRadius: "4px",
        cursor: disabled && !checked ? "not-allowed" : "pointer",
        background: checked ? "#1a2a3a" : "transparent",
        border: `1px solid ${checked ? "#2a5a7e" : "#2a2a2a"}`,
        marginBottom: "4px",
        opacity: disabled && !checked ? 0.4 : 1,
        transition: "background 0.15s, border-color 0.15s",
      }}
    >
      <input
        type="checkbox"
        checked={checked}
        disabled={disabled && !checked}
        onChange={() => onChange(family.name)}
        style={{ accentColor: "#7ec8e3", width: "14px", height: "14px", cursor: "pointer" }}
      />
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ color: "#e0e0e0", fontSize: "13px", display: "flex", alignItems: "center" }}>
          {family.name}
          {dot}
          {family.if_outlier_count > 0 && (
            <span style={{ marginLeft: "8px", color: "#e0a835", fontSize: "10px", fontStyle: "italic" }}>
              {family.if_outlier_count} IF outlier{family.if_outlier_count !== 1 ? "s" : ""}
            </span>
          )}
        </div>
        <div style={{ color: "#555", fontSize: "11px" }}>
          {family.client_count} client{family.client_count !== 1 ? "s" : ""}
          {" · "}
          {family.total_events?.toLocaleString()} events
        </div>
      </div>
    </label>
  );
}

function OllamaStatusBadge({ status }) {
  if (!status) return null;
  if (!status.reachable) {
    return (
      <span style={{ fontSize: "11px", color: "#e05555", marginLeft: "8px" }}>
        ● Ollama unreachable
      </span>
    );
  }
  if (status.model_available === false) {
    return (
      <span style={{ fontSize: "11px", color: "#e0a835", marginLeft: "8px" }}>
        ● Model "{status.model}" not pulled
      </span>
    );
  }
  return (
    <span style={{ fontSize: "11px", color: "#2d7a4f", marginLeft: "8px" }}>
      ● {status.model} ready
    </span>
  );
}

export default function AiAssist({ apiBase, sites }) {
  // Scope selection
  const [scopeValue, setScopeValue] = useState(ORG_SCOPE_VALUE);

  // Family list for the selected scope
  const [families, setFamilies] = useState([]);
  const [familiesLoading, setFamiliesLoading] = useState(false);
  const [familiesError, setFamiliesError] = useState(null);

  // Checkbox selection — max 2
  const [selected, setSelected] = useState([]);

  // LLM output
  const [result, setResult] = useState(null);        // {mode, result, families, timestamp}
  const [running, setRunning] = useState(false);
  const [runError, setRunError] = useState(null);

  // Ollama health
  const [ollamaStatus, setOllamaStatus] = useState(null);

  // Check Ollama on mount
  useEffect(() => {
    apiFetch(`${apiBase}/api/v1/ai/status`)
      .then(r => r.json())
      .then(setOllamaStatus)
      .catch(() => setOllamaStatus({ reachable: false }));
  }, [apiBase]);

  // Derive scope + site_id from the dropdown value
  const scope = scopeValue === ORG_SCOPE_VALUE ? "org" : "site";
  const activeSiteId = scopeValue === ORG_SCOPE_VALUE ? null : scopeValue;

  // Reload family list whenever scope changes
  useEffect(() => {
    setSelected([]);
    setResult(null);
    setRunError(null);
    setFamilies([]);
    setFamiliesError(null);
    setFamiliesLoading(true);

    const params = new URLSearchParams({ scope });
    if (activeSiteId) params.set("site_id", activeSiteId);

    apiFetch(`${apiBase}/api/v1/ai/families?${params}`)
      .then(r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then(data => {
        setFamilies(data.families || []);
        setFamiliesLoading(false);
      })
      .catch(err => {
        setFamiliesError(err.message);
        setFamiliesLoading(false);
      });
  }, [apiBase, scopeValue]);   // eslint-disable-line react-hooks/exhaustive-deps

  const handleFamilyToggle = useCallback((name) => {
    setSelected(prev => {
      if (prev.includes(name)) return prev.filter(n => n !== name);
      if (prev.length >= 2)   return prev;   // hard cap — should be unreachable (checkbox is disabled)
      return [...prev, name];
    });
  }, []);

  async function handleRun() {
    if (selected.length === 0 || running) return;
    setRunning(true);
    setRunError(null);
    setResult(null);

    const body = { families: selected, scope };
    if (activeSiteId) body.site_id = activeSiteId;

    try {
      const r = await apiFetch(`${apiBase}/api/v1/ai/assist`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!r.ok) {
        const err = await r.json().catch(() => ({ detail: `HTTP ${r.status}` }));
        throw new Error(err.detail || `HTTP ${r.status}`);
      }
      const data = await r.json();
      setResult(data);
    } catch (err) {
      setRunError(err.message);
    } finally {
      setRunning(false);
    }
  }

  const ollamaReady = ollamaStatus?.reachable && ollamaStatus?.model_available !== false;
  const canRun = selected.length >= 1 && !running && ollamaReady;
  const mode = selected.length === 2 ? "compare" : "analyze";
  const btnLabel = running
    ? (mode === "compare" ? "Comparing…" : "Analysing…")
    : !ollamaReady
      ? "Ollama not ready"
      : (mode === "compare" ? "Compare" : "Analyze");

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>

      {/* Header row */}
      <div style={{ display: "flex", alignItems: "center", gap: "12px", flexWrap: "wrap" }}>
        <span style={{ color: "#7ec8e3", fontSize: "14px", fontWeight: "bold" }}>AI Assist</span>
        <OllamaStatusBadge status={ollamaStatus} />
        <span style={{ color: "#555", fontSize: "12px", marginLeft: "auto" }}>
          Select 1 family to analyse · Select 2 to compare
        </span>
      </div>

      {/* Scope selector + run button */}
      <div style={{ display: "flex", alignItems: "center", gap: "10px", flexWrap: "wrap" }}>
        <span style={{ color: "#888", fontSize: "13px" }}>Scope:</span>
        <select
          value={scopeValue}
          onChange={e => setScopeValue(e.target.value)}
          style={{
            background: "#1a1a1a",
            color: "#e0e0e0",
            border: "1px solid #444",
            borderRadius: "4px",
            padding: "5px 10px",
            fontSize: "13px",
            fontFamily: "monospace",
            cursor: "pointer",
            minWidth: "260px",
          }}
        >
          <option value={ORG_SCOPE_VALUE}>Organization (all sites)</option>
          {(sites || []).map(s => (
            <option key={s.id} value={s.id}>Site: {s.name}</option>
          ))}
        </select>
        <button
          onClick={handleRun}
          disabled={!canRun}
          style={{
            padding: "5px 16px",
            borderRadius: "4px",
            border: `1px solid ${canRun ? "#2a5a7e" : "#2a2a2a"}`,
            background: canRun ? "#1a3a4e" : "#1a1a1a",
            color: canRun ? "#7ec8e3" : "#444",
            fontSize: "13px",
            fontFamily: "monospace",
            cursor: canRun ? "pointer" : "not-allowed",
            transition: "background 0.15s",
          }}
        >
          {btnLabel}
        </button>
        {runError && (
          <span style={{ color: "#e05555", fontSize: "11px" }}>{runError}</span>
        )}
      </div>

      {/* Two-panel body */}
      <div style={{ display: "flex", gap: "16px", alignItems: "flex-start" }}>

        {/* LEFT — Family list */}
        <div style={{
          width: "320px",
          flexShrink: 0,
          background: "#161616",
          border: "1px solid #2a2a2a",
          borderRadius: "6px",
          padding: "12px",
          display: "flex",
          flexDirection: "column",
          gap: "8px",
          overflowY: "auto",
          maxHeight: "calc(100vh - 200px)",
        }}>
          <div style={{ color: "#888", fontSize: "12px", marginBottom: "4px" }}>
            Device Families
            {families.length > 0 && (
              <span style={{ color: "#555", marginLeft: "6px" }}>({families.length})</span>
            )}
          </div>

          {familiesLoading && (
            <div style={{ color: "#555", fontSize: "13px" }}>Loading families…</div>
          )}

          {familiesError && (
            <div style={{ color: "#e05555", fontSize: "12px" }}>
              Error: {familiesError}
            </div>
          )}

          {!familiesLoading && !familiesError && families.length === 0 && (
            <div style={{ color: "#555", fontSize: "12px", fontStyle: "italic" }}>
              No family data found. Run a detection cycle first.
            </div>
          )}

          {!familiesLoading && families.map(family => (
            <FamilyCheckbox
              key={family.name}
              family={family}
              checked={selected.includes(family.name)}
              onChange={handleFamilyToggle}
              disabled={selected.length >= 2}
            />
          ))}

        </div>

        {/* RIGHT — Output panel */}
        <div style={{
          flex: 1,
          minHeight: "400px",
          background: "#161616",
          border: "1px solid #2a2a2a",
          borderRadius: "6px",
          padding: "16px",
          display: "flex",
          flexDirection: "column",
          gap: "10px",
        }}>

          {/* Idle / loading state */}
          {!result && !running && !runError && (
            <div style={{ color: "#333", fontSize: "13px", margin: "auto", textAlign: "center" }}>
              <div style={{ fontSize: "28px", marginBottom: "8px" }}>⬡</div>
              Select one or two device families and click Analyze or Compare
            </div>
          )}

          {running && (
            <div style={{ color: "#555", fontSize: "13px", margin: "auto", textAlign: "center" }}>
              <div style={{ fontSize: "22px", marginBottom: "8px", animation: "spin 1s linear infinite" }}>◌</div>
              Waiting for local LLM response…
            </div>
          )}

          {/* Result */}
          {result && !running && (
            <>
              {/* Result header */}
              <div style={{ display: "flex", alignItems: "center", gap: "10px", borderBottom: "1px solid #2a2a2a", paddingBottom: "8px" }}>
                <span style={{ color: "#7ec8e3", fontSize: "12px" }}>
                  {result.mode === "compare" ? "Comparison" : "Analysis"}:
                </span>
                <span style={{ color: "#e0e0e0", fontSize: "12px" }}>
                  {result.families.join(" vs ")}
                </span>
                <span style={{ color: "#555", fontSize: "11px", marginLeft: "auto" }}>
                  {result.scope === "org" ? "org-wide" : `site ${result.site_id}`}
                  {" · "}
                  {new Date(result.timestamp).toLocaleTimeString()}
                </span>
              </div>

              {/* LLM output */}
              <pre style={{
                flex: 1,
                margin: 0,
                padding: "4px 0",
                color: "#d0d0d0",
                fontSize: "13px",
                fontFamily: "monospace",
                lineHeight: "1.65",
                whiteSpace: "pre-wrap",
                wordBreak: "break-word",
                overflowY: "auto",
              }}>
                {result.result}
              </pre>

              {/* Clear button */}
              <div style={{ borderTop: "1px solid #2a2a2a", paddingTop: "8px" }}>
                <button
                  onClick={() => { setResult(null); setSelected([]); }}
                  style={{
                    background: "transparent",
                    color: "#555",
                    border: "1px solid #2a2a2a",
                    borderRadius: "4px",
                    padding: "3px 10px",
                    fontSize: "11px",
                    fontFamily: "monospace",
                    cursor: "pointer",
                  }}
                >
                  Clear
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
