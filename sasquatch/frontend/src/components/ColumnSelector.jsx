import { useEffect, useRef, useState } from "react";

const btnStyle = {
  background: "#1a1a1a",
  color: "#7ec8e3",
  border: "1px solid #2a6a8a",
  padding: "4px 10px",
  borderRadius: "4px",
  cursor: "pointer",
  fontSize: "12px",
};

const popupStyle = {
  position: "absolute",
  top: "calc(100% + 6px)",
  right: 0,
  background: "#161616",
  border: "1px solid #333",
  borderRadius: "4px",
  padding: "10px 12px",
  boxShadow: "0 4px 14px rgba(0,0,0,0.6)",
  zIndex: 50,
  minWidth: "220px",
  maxHeight: "70vh",
  overflowY: "auto",
};

const rowStyle = {
  display: "flex",
  alignItems: "center",
  gap: "6px",
  padding: "3px 0",
  fontSize: "12px",
  color: "#ccc",
  cursor: "pointer",
  userSelect: "none",
};

export default function ColumnSelector({ columns, visible, onChange, storageKey }) {
  const [open, setOpen] = useState(false);
  const rootRef = useRef(null);

  useEffect(() => {
    if (!open) return;
    const onDocClick = (e) => {
      if (rootRef.current && !rootRef.current.contains(e.target)) setOpen(false);
    };
    document.addEventListener("mousedown", onDocClick);
    return () => document.removeEventListener("mousedown", onDocClick);
  }, [open]);

  const toggle = (key) => {
    const next = { ...visible, [key]: !visible[key] };
    onChange(next);
    if (storageKey) {
      try { localStorage.setItem(storageKey, JSON.stringify(next)); } catch {}
    }
  };

  const setAll = (val) => {
    const next = {};
    for (const c of columns) next[c.key] = val;
    onChange(next);
    if (storageKey) {
      try { localStorage.setItem(storageKey, JSON.stringify(next)); } catch {}
    }
  };

  return (
    <div ref={rootRef} style={{ position: "relative", display: "inline-block" }}>
      <button onClick={() => setOpen(o => !o)} style={btnStyle} title="Select which columns are visible">
        Columns ▾
      </button>
      {open && (
        <div style={popupStyle}>
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "8px", fontSize: "11px" }}>
            <span style={{ color: "#888" }}>Visible columns</span>
            <span>
              <button
                onClick={() => setAll(true)}
                style={{ background: "none", border: "none", color: "#7ec8e3", fontSize: "11px", cursor: "pointer", padding: "0 4px" }}
              >
                All
              </button>
              <button
                onClick={() => setAll(false)}
                style={{ background: "none", border: "none", color: "#7ec8e3", fontSize: "11px", cursor: "pointer", padding: "0 4px" }}
              >
                None
              </button>
            </span>
          </div>
          {columns.map(c => (
            <label key={c.key} style={rowStyle}>
              <input
                type="checkbox"
                checked={!!visible[c.key]}
                onChange={() => toggle(c.key)}
                disabled={c.required}
                style={{ accentColor: "#2a5a7a" }}
              />
              <span style={{ color: c.required ? "#666" : "#ccc" }}>
                {c.label}{c.required ? " (required)" : ""}
              </span>
            </label>
          ))}
        </div>
      )}
    </div>
  );
}

export function loadVisibleFromStorage(storageKey, defaults) {
  try {
    const raw = localStorage.getItem(storageKey);
    if (!raw) return defaults;
    const parsed = JSON.parse(raw);
    const merged = { ...defaults };
    for (const k of Object.keys(defaults)) {
      if (typeof parsed[k] === "boolean") merged[k] = parsed[k];
    }
    return merged;
  } catch {
    return defaults;
  }
}
