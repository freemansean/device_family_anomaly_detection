import { useState, useEffect, useRef } from "react";
import FamilyDrilldown from "./components/FamilyDrilldown";
import FindingsFeed from "./components/FindingsFeed";
import Login from "./components/Login";
import MacDrilldown from "./components/MacDrilldown";
import OrgOverview from "./components/OrgOverview";
import SiteOverview from "./components/SiteOverview";
import { apiFetch, getToken, setToken, clearToken } from "./api";

const ORG_FOCUS_VALUE = "__org__";

const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

const ACTION_BTN_PULSE_STYLE = `
@keyframes sq-btn-pulse {
  0%, 100% { border-color: #2a2a3a; }
  50%       { border-color: #4a4a7a; }
}`;

function actionBtnStyle(state) {
  const base = { border: "1px solid", borderRadius: "4px", padding: "4px 10px", cursor: "pointer", fontSize: "12px", fontFamily: "monospace" };
  if (state === "ok")      return { ...base, background: "#1a3a1a", color: "#2d7a4f", borderColor: "#2d7a4f55" };
  if (state === "error")   return { ...base, background: "#2a1515", color: "#e05555", borderColor: "#e0555555" };
  if (state === "loading") return { ...base, background: "#1a1a2a", color: "#555", borderColor: "#2a2a3a", cursor: "default", animation: "sq-btn-pulse 1.2s ease-in-out infinite" };
  if (state === "warn")    return { ...base, background: "#2a1f10", color: "#e0a835", borderColor: "#e0a83555" };
  return { ...base, background: "#1a1a1a", color: "#888", borderColor: "#333" };
}

function WlanFallbackToast({ wlan, onDismiss }) {
  return (
    <div style={{
      position: "fixed", bottom: "24px", right: "24px", zIndex: 200,
      background: "#221a0a", border: "1px solid #e0a83560",
      borderRadius: "6px", padding: "10px 14px",
      color: "#e0a835", fontSize: "12px", fontFamily: "monospace",
      maxWidth: "300px", boxShadow: "0 4px 16px rgba(0,0,0,0.6)",
      display: "flex", alignItems: "flex-start", gap: "10px",
    }}>
      <span style={{ fontSize: "13px", lineHeight: "1.4" }}>⚠</span>
      <div style={{ flex: 1 }}>
        <div style={{ marginBottom: "2px", color: "#e0e0e0" }}>WLAN not available at this site</div>
        <div><span style={{ color: "#e0a835" }}>{wlan}</span> — showing all WLANs</div>
      </div>
      <button onClick={onDismiss} style={{ background: "none", border: "none", color: "#555", cursor: "pointer", fontSize: "16px", padding: 0, lineHeight: 1 }}>×</button>
    </div>
  );
}

function WlanLoadingOverlay() {
  return (
    <>
      <style>{`@keyframes sq-spin { to { transform: rotate(360deg); } }`}</style>
      <div style={{
        position: "absolute", inset: 0, zIndex: 50,
        background: "rgba(17,17,17,0.72)",
        display: "flex", alignItems: "center", justifyContent: "center",
        borderRadius: "4px",
      }}>
        <div style={{ textAlign: "center" }}>
          <div style={{
            width: "22px", height: "22px", margin: "0 auto",
            border: "2px solid #2a2a3a", borderTopColor: "#7ec8e3",
            borderRadius: "50%", animation: "sq-spin 0.75s linear infinite",
          }} />
          <div style={{ color: "#7ec8e3", fontSize: "12px", marginTop: "10px", letterSpacing: "0.05em" }}>
            Loading…
          </div>
        </div>
      </div>
    </>
  );
}

function ProgressBar({ progress }) {
  if (!progress || progress.phase === "idle") return null;
  const { phase, events_fetched, total_estimated, pages, macs_scored, message } = progress;

  let pct = 0;
  let label = "";
  let color = "#7ec8e3";

  if (phase === "starting") {
    pct = 2;
    label = "Initializing…";
  } else if (phase === "collecting") {
    if (total_estimated) {
      pct = Math.min((events_fetched / total_estimated) * 65 + 5, 68);
      const pagesLeft = Math.max(0, Math.ceil((total_estimated - events_fetched) / 1000));
      label = `Collecting events… ${(events_fetched || 0).toLocaleString()} / ${total_estimated.toLocaleString()} (page ${pages}${pagesLeft > 0 ? `, ~${pagesLeft} more` : ""})`;
    } else {
      pct = Math.min(5 + (pages || 0) * 5, 65);
      label = `Collecting events… ${(events_fetched || 0).toLocaleString()} events (page ${pages || 1})`;
    }
  } else if (phase === "scoring") {
    pct = 75;
    label = `Running anomaly detection… ${(events_fetched || 0).toLocaleString()} events`;
  } else if (phase === "complete") {
    pct = 100;
    color = "#2d7a4f";
    label = `Done — ${(events_fetched || 0).toLocaleString()} events, ${macs_scored || 0} MACs scored`;
  } else if (phase === "error") {
    pct = 100;
    color = "#e05555";
    label = `Error: ${message || "Unknown error"}`;
  }

  return (
    <div style={{ marginTop: "8px" }}>
      <div style={{ background: "#1a1a1a", border: "1px solid #2a2a2a", borderRadius: "4px", overflow: "hidden", height: "5px" }}>
        <div style={{ width: `${pct}%`, height: "100%", background: color, transition: "width 0.6s ease" }} />
      </div>
      <div style={{ fontSize: "11px", color: color === "#e05555" ? "#e05555" : "#555", marginTop: "3px" }}>{label}</div>
    </div>
  );
}

export default function App() {
  const [token, setTokenState] = useState(() => getToken());
  const [sites, setSites] = useState([]); // [{id, name}]
  const [selectedSite, setSelectedSite] = useState(null); // site ID string
  const [selectedMac, setSelectedMac] = useState(null);
  const [selectedFamily, setSelectedFamily] = useState(null);
  const [view, setView] = useState("overview"); // "overview" | "findings" | "family" | "mac"
  const [siteSearch, setSiteSearch] = useState("");
  const [siteDropdownOpen, setSiteDropdownOpen] = useState(false);
  const [discoveryRefreshToken, setDiscoveryRefreshToken] = useState(0);

  // WLAN scope
  const [wlans, setWlans] = useState([]); // list of SSID name strings
  const [selectedWlan, setSelectedWlan] = useState("__all__");
  const [wlanLoading, setWlanLoading] = useState(false);
  const [wlanFallbackToast, setWlanFallbackToast] = useState(null); // WLAN name that was dropped
  // Ref so the WLAN fetch effect can read the current selection without it being a dep
  const selectedWlanRef = useRef(selectedWlan);
  useEffect(() => { selectedWlanRef.current = selectedWlan; }, [selectedWlan]);

  // Action bar state
  const [focusSite, setFocusSite] = useState(null); // {site_id, source}
  const [progress, setProgress] = useState(null);
  const [progressPolling, setProgressPolling] = useState(false);
  const [actionState, setActionState] = useState({
    clientRefresh: "idle", // idle | loading | ok | error
    flush: "idle",         // idle | confirm | loading | ok | error
    detect: "idle",
    discover: "idle",      // idle | running | ok | error
    swapFocus: "idle",
  });

  function setAS(key, val) {
    setActionState(prev => ({ ...prev, [key]: val }));
  }

  // Handle token expiry from any component via custom event
  useEffect(() => {
    function handleUnauthorized() {
      setTokenState(null);
    }
    window.addEventListener("sasquatch:unauthorized", handleUnauthorized);
    return () => window.removeEventListener("sasquatch:unauthorized", handleUnauthorized);
  }, []);

  useEffect(() => {
    if (!token) return;
    apiFetch(`${API_BASE}/api/v1/org/sites`)
      .then((r) => r.json())
      .then((data) => { setSites(data.sites || []); })
      .catch(console.error);
    apiFetch(`${API_BASE}/api/v1/focus`)
      .then((r) => r.json())
      .then((data) => {
        setFocusSite(data);
        if (data?.site_id) setSelectedSite((prev) => prev ?? data.site_id);
      })
      .catch(console.error);
  }, [token]);

  // Fetch available WLANs whenever the selected site changes.
  // If the previously-selected WLAN doesn't exist at the new site, fall back to __all__ and toast.
  useEffect(() => {
    setWlans([]);
    if (!token || !selectedSite) return;
    const url = selectedSite === ORG_FOCUS_VALUE
      ? `${API_BASE}/api/v1/wlans`
      : `${API_BASE}/api/v1/wlans?site_id=${selectedSite}`;
    apiFetch(url)
      .then((r) => r.json())
      .then((data) => {
        const newWlans = data.wlans || [];
        setWlans(newWlans);
        const prev = selectedWlanRef.current;
        if (prev !== "__all__" && !newWlans.includes(prev)) {
          setSelectedWlan("__all__");
          setWlanFallbackToast(prev);
          setTimeout(() => setWlanFallbackToast(null), 3500);
        }
      })
      .catch(console.error);
  }, [token, selectedSite]);

  // Poll progress while Full Discovery is running
  useEffect(() => {
    if (!progressPolling || !selectedSite) return;
    const poll = setInterval(async () => {
      try {
        const progressUrl = selectedSite === ORG_FOCUS_VALUE
          ? `${API_BASE}/api/v1/org/progress`
          : `${API_BASE}/api/v1/sites/${selectedSite}/progress`;
        const r = await apiFetch(progressUrl);
        const data = await r.json();
        setProgress(data);
        if (data.phase === "complete" || data.phase === "error" || data.phase === "idle") {
          setProgressPolling(false);
          setAS("discover", data.phase === "complete" ? "ok" : data.phase === "error" ? "error" : "idle");
          if (data.phase === "complete") {
            setDiscoveryRefreshToken((t) => t + 1);
            setTimeout(() => { setAS("discover", "idle"); setProgress(null); }, 5000);
          }
        }
      } catch (e) { console.error(e); }
    }, 750);
    return () => clearInterval(poll);
  }, [progressPolling, selectedSite]);

  async function handleClientRefresh() {
    if (!selectedSite) return;
    setAS("clientRefresh", "loading");
    try {
      const endpoint = selectedSite === ORG_FOCUS_VALUE
        ? `${API_BASE}/api/v1/org/refresh`
        : `${API_BASE}/api/v1/sites/${selectedSite}/refresh`;
      const r = await apiFetch(endpoint, { method: "POST" });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      setAS("clientRefresh", "ok");
      setTimeout(() => setAS("clientRefresh", "idle"), 2000);
    } catch {
      setAS("clientRefresh", "error");
      setTimeout(() => setAS("clientRefresh", "idle"), 3000);
    }
  }

  async function handleFullDiscovery() {
    if (!selectedSite || actionState.discover === "running") return;
    setProgress({ phase: "starting" });
    setAS("discover", "running");
    setProgressPolling(true);
    try {
      const endpoint = selectedSite === ORG_FOCUS_VALUE
        ? `${API_BASE}/api/v1/org/run`
        : `${API_BASE}/api/v1/sites/${selectedSite}/run`;
      const r = await apiFetch(endpoint, { method: "POST" });
      if (!r.ok && r.status !== 409) throw new Error(`HTTP ${r.status}`);
    } catch (e) {
      setProgress({ phase: "error", message: e.message });
      setProgressPolling(false);
      setAS("discover", "error");
      setTimeout(() => { setAS("discover", "idle"); setProgress(null); }, 4000);
    }
  }

  async function handleFlush() {
    if (!selectedSite) return;
    if (actionState.flush === "idle") { setAS("flush", "confirm"); setTimeout(() => setActionState(prev => prev.flush === "confirm" ? { ...prev, flush: "idle" } : prev), 4000); return; }
    if (actionState.flush !== "confirm") return;
    setAS("flush", "loading");
    try {
      const endpoint = selectedSite === ORG_FOCUS_VALUE
        ? `${API_BASE}/api/v1/org/flush`
        : `${API_BASE}/api/v1/sites/${selectedSite}/flush`;
      await apiFetch(endpoint, { method: "POST" });
      setAS("flush", "ok");
      setTimeout(() => setAS("flush", "idle"), 2000);
    } catch {
      setAS("flush", "error");
      setTimeout(() => setAS("flush", "idle"), 3000);
    }
  }

  async function handleDetect() {
    if (!selectedSite) return;
    setAS("detect", "loading");
    try {
      const endpoint = selectedSite === ORG_FOCUS_VALUE
        ? `${API_BASE}/api/v1/org/detect`
        : `${API_BASE}/api/v1/sites/${selectedSite}/detect`;
      await apiFetch(endpoint, { method: "POST" });
      setAS("detect", "ok");
      setDiscoveryRefreshToken((t) => t + 1);
      setTimeout(() => setAS("detect", "idle"), 2000);
    } catch {
      setAS("detect", "error");
      setTimeout(() => setAS("detect", "idle"), 3000);
    }
  }

  async function handleSwapFocus() {
    if (!selectedSite) return;
    setAS("swapFocus", "loading");
    try {
      await apiFetch(`${API_BASE}/api/v1/focus`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ site_id: selectedSite }),
      });
      const r = await apiFetch(`${API_BASE}/api/v1/focus`);
      setFocusSite(await r.json());
      setAS("swapFocus", "ok");
      setTimeout(() => setAS("swapFocus", "idle"), 2000);
    } catch {
      setAS("swapFocus", "error");
      setTimeout(() => setAS("swapFocus", "idle"), 3000);
    }
  }

  function handleLogin(newToken) {
    setToken(newToken);
    setTokenState(newToken);
  }

  if (!token) {
    return <Login apiBase={API_BASE} onLogin={handleLogin} />;
  }

  function handleMacSelect(mac) {
    setSelectedMac(mac);
    setView("mac");
  }

  function handleFamilySelect(family) {
    setSelectedFamily(family);
    setView("family");
  }

  function handleSiteSelect(siteId) {
    setSelectedSite(siteId);
    setView("overview");
    setSelectedMac(null);
    setSelectedFamily(null);
  }

  function handleOrgMacSelect(mac, siteId) {
    setSelectedSite(siteId);
    setSelectedMac(mac);
    setView("mac");
  }

  return (
    <div style={{ fontFamily: "monospace", padding: "16px", background: "#111", minHeight: "100vh", color: "#e0e0e0" }}>
      <style>{ACTION_BTN_PULSE_STYLE}</style>
      <header style={{ borderBottom: "1px solid #333", paddingBottom: "12px", marginBottom: "16px" }}>
        <h1 style={{ margin: 0, fontSize: "18px", color: "#7ec8e3" }}>
          Project Sasquatch — Client Anomaly Detection
        </h1>
        <div style={{ marginTop: "8px", display: "flex", gap: "12px", alignItems: "center" }}>
          <span style={{ color: "#888", fontSize: "13px" }}>Site:</span>
          <div style={{ position: "relative" }}>
            <input
              type="text"
              value={siteDropdownOpen ? siteSearch : (selectedSite === ORG_FOCUS_VALUE ? "Organization" : (sites.find(s => s.id === selectedSite)?.name ?? ""))}
              placeholder={sites.length === 0 ? "Loading sites…" : "Search sites…"}
              onFocus={() => { setSiteDropdownOpen(true); setSiteSearch(""); }}
              onChange={(e) => { setSiteSearch(e.target.value); setSiteDropdownOpen(true); }}
              onBlur={() => setTimeout(() => setSiteDropdownOpen(false), 150)}
              style={{ background: "#222", color: "#e0e0e0", border: "1px solid #444", padding: "4px 8px", borderRadius: "4px", width: "260px", cursor: "text" }}
            />
            {siteDropdownOpen && (
              <div style={{ position: "absolute", top: "100%", left: 0, zIndex: 100, background: "#1a1a1a", border: "1px solid #444", borderRadius: "4px", marginTop: "2px", maxHeight: "260px", overflowY: "auto", width: "320px", boxShadow: "0 4px 12px rgba(0,0,0,0.5)" }}>
                {/* Organization option */}
                {"organization".includes(siteSearch.toLowerCase()) || siteSearch === "" ? (
                  <div
                    onMouseDown={() => { setSelectedSite(ORG_FOCUS_VALUE); setSiteDropdownOpen(false); setSiteSearch(""); setView("overview"); setSelectedMac(null); setSelectedFamily(null); }}
                    style={{ padding: "6px 10px", cursor: "pointer", borderBottom: "1px solid #333", background: selectedSite === ORG_FOCUS_VALUE ? "#2a4a5e" : "transparent" }}
                    onMouseEnter={e => e.currentTarget.style.background = selectedSite === ORG_FOCUS_VALUE ? "#2a4a5e" : "#252525"}
                    onMouseLeave={e => e.currentTarget.style.background = selectedSite === ORG_FOCUS_VALUE ? "#2a4a5e" : "transparent"}
                  >
                    <div style={{ color: "#7ec8e3", fontSize: "13px" }}>Organization</div>
                    <div style={{ color: "#555", fontSize: "11px" }}>All sites — org-wide polling</div>
                  </div>
                ) : null}
                {sites
                  .filter(s =>
                    s.name.toLowerCase().includes(siteSearch.toLowerCase()) ||
                    s.id.toLowerCase().includes(siteSearch.toLowerCase())
                  )
                  .map(s => (
                    <div
                      key={s.id}
                      onMouseDown={() => {
                        setSelectedSite(s.id);
                        setSiteDropdownOpen(false);
                        setSiteSearch("");
                        setView("overview");
                        setSelectedMac(null);
                        setSelectedFamily(null);
                      }}
                      style={{ padding: "6px 10px", cursor: "pointer", borderBottom: "1px solid #2a2a2a", background: s.id === selectedSite ? "#2a4a5e" : "transparent" }}
                      onMouseEnter={e => e.currentTarget.style.background = s.id === selectedSite ? "#2a4a5e" : "#252525"}
                      onMouseLeave={e => e.currentTarget.style.background = s.id === selectedSite ? "#2a4a5e" : "transparent"}
                    >
                      <div style={{ color: "#e0e0e0", fontSize: "13px" }}>{s.name}</div>
                      <div style={{ color: "#555", fontSize: "11px", fontFamily: "monospace" }}>{s.id}</div>
                    </div>
                  ))
                }
                {sites.filter(s =>
                  s.name.toLowerCase().includes(siteSearch.toLowerCase()) ||
                  s.id.toLowerCase().includes(siteSearch.toLowerCase())
                ).length === 0 && (
                  <div style={{ padding: "8px 10px", color: "#555", fontSize: "13px" }}>No sites match</div>
                )}
              </div>
            )}
          </div>
          {/* WLAN Scope Selector */}
          {wlans.length > 0 && (
            <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
              <span style={{ color: "#888", fontSize: "13px" }}>WLAN:</span>
              <select
                value={selectedWlan}
                onChange={(e) => { setWlanLoading(true); setSelectedWlan(e.target.value); setView("overview"); setSelectedMac(null); setSelectedFamily(null); }}
                style={{
                  background: "#222",
                  color: selectedWlan === "__all__" ? "#7ec8e3" : "#e0e0e0",
                  border: `1px solid ${selectedWlan === "__all__" ? "#2a4a5e" : "#2d7a4f"}`,
                  padding: "4px 8px",
                  borderRadius: "4px",
                  cursor: "pointer",
                  fontSize: "13px",
                  fontFamily: "monospace",
                }}
              >
                <option value="__all__">All WLANs</option>
                {wlans.map((w) => (
                  <option key={w} value={w}>{w}</option>
                ))}
              </select>
            </div>
          )}

          <nav style={{ display: "flex", gap: "8px" }}>
            {["overview", "findings"].map((v) => {
              if (selectedSite === ORG_FOCUS_VALUE && v !== "overview") return null;
              return (
                <button
                  key={v}
                  onClick={() => setView(v)}
                  style={{
                    background: view === v ? "#2a4a5e" : "#1a1a1a",
                    color: view === v ? "#7ec8e3" : "#888",
                    border: "1px solid #333",
                    padding: "4px 12px",
                    borderRadius: "4px",
                    cursor: "pointer",
                    textTransform: "capitalize",
                  }}
                >
                  {v === "overview" ? (selectedSite === ORG_FOCUS_VALUE ? "Organization" : "Site Overview") : "Findings"}
                </button>
              );
            })}
          </nav>
          <button
            onClick={() => { clearToken(); setTokenState(null); }}
            style={{
              marginLeft: "auto",
              background: "transparent",
              color: "#555",
              border: "1px solid #2a2a2a",
              padding: "4px 10px",
              borderRadius: "4px",
              cursor: "pointer",
              fontSize: "12px",
            }}
          >
            Sign out
          </button>
        </div>

        {/* Action bar */}
        <div style={{ marginTop: "10px", display: "flex", gap: "8px", alignItems: "center", flexWrap: "wrap" }}>

          {/* Site Focus */}
          {(() => {
            const focusName = focusSite
              ? (focusSite.site_id === ORG_FOCUS_VALUE ? "Organization" : (sites.find(s => s.id === focusSite.site_id)?.name || focusSite.site_id))
              : "—";
            const isAlreadyFocus = focusSite?.site_id === selectedSite;
            const s = actionState.swapFocus;
            return (
              <div style={{ display: "flex", alignItems: "center", gap: "6px", background: "#161616", border: "1px solid #2a2a2a", borderRadius: "4px", padding: "4px 10px" }}>
                <span style={{ color: "#555", fontSize: "11px" }}>Focus:</span>
                <span style={{ color: "#7ec8e3", fontSize: "12px", maxWidth: "160px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={focusSite?.site_id}>
                  {focusName}
                </span>
                {focusSite?.source === "override" && (
                  <span style={{ color: "#555", fontSize: "10px", fontStyle: "italic" }}>override</span>
                )}
                {selectedSite && !isAlreadyFocus && (
                  <button
                    onClick={handleSwapFocus}
                    disabled={s === "loading"}
                    style={{ background: s === "ok" ? "#1a3a1a" : "#1a2a1a", color: s === "ok" ? "#2d7a4f" : s === "error" ? "#e05555" : "#888", border: `1px solid ${s === "ok" ? "#2d7a4f" : "#2a3a2a"}`, borderRadius: "3px", padding: "2px 8px", cursor: s === "loading" ? "default" : "pointer", fontSize: "11px" }}
                  >
                    {s === "loading" ? "…" : s === "ok" ? "Swapped" : s === "error" ? "Error" : "Swap Focus"}
                  </button>
                )}
                {isAlreadyFocus && <span style={{ color: "#2d7a4f", fontSize: "10px" }}>● active</span>}
              </div>
            );
          })()}

          <div style={{ width: "1px", height: "24px", background: "#2a2a2a" }} />

          {/* Client Refresh */}
          {(() => {
            const s = actionState.clientRefresh;
            const isOrg = selectedSite === ORG_FOCUS_VALUE;
            const label = isOrg ? "Org Client Refresh" : "Client Refresh";
            return (
              <button
                onClick={handleClientRefresh}
                disabled={!selectedSite || s === "loading"}
                style={actionBtnStyle(s)}
              >
                {s === "loading" ? "Refreshing…" : s === "ok" ? "Refreshed ✓" : s === "error" ? "Error ✗" : label}
              </button>
            );
          })()}

          {/* Full Discovery */}
          {(() => {
            const s = actionState.discover;
            return (
              <button
                onClick={handleFullDiscovery}
                disabled={!selectedSite || s === "running" || actionState.clientRefresh === "loading"}
                style={actionBtnStyle(s === "running" ? "loading" : s)}
              >
                {s === "running" ? "Discovering…" : s === "ok" ? "Discovery Done ✓" : s === "error" ? "Error ✗" : "Full Discovery"}
              </button>
            );
          })()}

          {/* Flush Events */}
          {(() => {
            const s = actionState.flush;
            return (
              <button
                onClick={handleFlush}
                disabled={!selectedSite || s === "loading"}
                style={actionBtnStyle(s === "confirm" ? "warn" : s)}
              >
                {s === "loading" ? "Flushing…" : s === "confirm" ? "Confirm Flush?" : s === "ok" ? "Flushed ✓" : s === "error" ? "Error ✗" : "Flush Events"}
              </button>
            );
          })()}

          {/* Re-trigger Detection */}
          {(() => {
            const s = actionState.detect;
            return (
              <button
                onClick={handleDetect}
                disabled={!selectedSite || s === "loading"}
                style={actionBtnStyle(s)}
              >
                {s === "loading" ? "Detecting…" : s === "ok" ? "Detection Done ✓" : s === "error" ? "Error ✗" : "Re-detect Anomalies"}
              </button>
            );
          })()}

        </div>

        {/* Progress bar for Full Discovery */}
        <ProgressBar progress={progress} />
      </header>

      <div style={{ position: "relative" }}>
        {wlanLoading && <WlanLoadingOverlay />}
        {selectedSite === ORG_FOCUS_VALUE && view === "overview" && (
          <OrgOverview apiBase={API_BASE} onSiteSelect={handleSiteSelect} onMacSiteSelect={handleOrgMacSelect} refreshToken={discoveryRefreshToken} wlan={selectedWlan} onLoaded={() => setWlanLoading(false)} />
        )}
        {selectedSite && selectedSite !== ORG_FOCUS_VALUE && view === "overview" && (
          <SiteOverview siteId={selectedSite} apiBase={API_BASE} onMacSelect={handleMacSelect} onFamilySelect={handleFamilySelect} refreshToken={discoveryRefreshToken} wlan={selectedWlan} onLoaded={() => setWlanLoading(false)} />
        )}
      </div>
      {selectedSite && selectedSite !== ORG_FOCUS_VALUE && view === "findings" && (
        <FindingsFeed siteId={selectedSite} apiBase={API_BASE} onMacSelect={handleMacSelect} refreshToken={discoveryRefreshToken} wlan={selectedWlan} />
      )}
      {selectedSite && selectedSite !== ORG_FOCUS_VALUE && view === "family" && selectedFamily && (
        <FamilyDrilldown
          siteId={selectedSite}
          family={selectedFamily}
          apiBase={API_BASE}
          onMacSelect={handleMacSelect}
          onBack={() => setView("overview")}
          refreshToken={discoveryRefreshToken}
          wlan={selectedWlan}
        />
      )}
      {selectedSite && selectedSite !== ORG_FOCUS_VALUE && view === "mac" && selectedMac && (
        <MacDrilldown
          siteId={selectedSite}
          mac={selectedMac}
          apiBase={API_BASE}
          onBack={() => selectedFamily ? setView("family") : setView("findings")}
          wlan={selectedWlan}
        />
      )}
      {wlanFallbackToast && (
        <WlanFallbackToast wlan={wlanFallbackToast} onDismiss={() => setWlanFallbackToast(null)} />
      )}
    </div>
  );
}
