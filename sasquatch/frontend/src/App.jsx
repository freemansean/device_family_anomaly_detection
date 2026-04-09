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
  const [selectedWlan, setSelectedWlan] = useState(null); // null until WLANs are loaded
  const [wlanLoading, setWlanLoading] = useState(false);
  // Ref so the WLAN fetch effect can read the current selection without it being a dep
  const selectedWlanRef = useRef(selectedWlan);
  useEffect(() => { selectedWlanRef.current = selectedWlan; }, [selectedWlan]);

  // Config state (shared across unified config modal tabs)
  const [webhookConfig, setWebhookConfig] = useState(null);
  const [webhookDraft, setWebhookDraft] = useState(null);
  const [webhookSaveState, setWebhookSaveState] = useState("idle");

  const [generalConfig, setGeneralConfig] = useState(null);
  const [generalConfigDraft, setGeneralConfigDraft] = useState(null);
  const [generalConfigSaveState, setGeneralConfigSaveState] = useState("idle");

  const [anomalyConfig, setAnomalyConfig] = useState(null);
  const [anomalyConfigDraft, setAnomalyConfigDraft] = useState(null);
  const [anomalyConfigSaveState, setAnomalyConfigSaveState] = useState("idle");

  // Utilities dropdown
  const [utilDropdownOpen, setUtilDropdownOpen] = useState(false);

  // Unified config modal
  const [configModalOpen, setConfigModalOpen] = useState(false);
  const [configTab, setConfigTab] = useState("general"); // "general" | "anomaly" | "webhook"

  // Action bar state
  const [focusSite, setFocusSite] = useState(null); // {site_id, source}
  const [orgDetectionEnabled, setOrgDetectionEnabled] = useState(true);
  const [progress, setProgress] = useState(null);
  const [progressPolling, setProgressPolling] = useState(false);
  const [actionState, setActionState] = useState({
    clientRefresh: "idle", // idle | loading | ok | error
    flush: "idle",         // idle | confirm | loading | ok | error
    detect: "idle",
    discover: "idle",      // idle | running | ok | error
    collect: "idle",       // idle | loading | ok | error
    swapFocus: "idle",
    orgDetection: "idle",  // idle | loading | ok | error
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
    apiFetch(`${API_BASE}/api/v1/org/detection-enabled`)
      .then((r) => r.json())
      .then((data) => setOrgDetectionEnabled(data.enabled !== false))
      .catch(console.error);
    apiFetch(`${API_BASE}/api/v1/webhook-config`)
      .then((r) => r.json())
      .then((data) => setWebhookConfig(data))
      .catch(console.error);
    apiFetch(`${API_BASE}/api/v1/general-config`)
      .then((r) => r.json())
      .then((data) => setGeneralConfig(data))
      .catch(console.error);
    apiFetch(`${API_BASE}/api/v1/anomaly-config`)
      .then((r) => r.json())
      .then((data) => setAnomalyConfig(data))
      .catch(console.error);
  }, [token]);

  // Fetch available WLANs whenever the selected site changes.
  // Auto-select the first WLAN alphabetically. If the previously-selected WLAN
  // exists at the new site, keep it; otherwise fall back to the first available.
  useEffect(() => {
    setWlans([]);
    setSelectedWlan(null);
    if (!token || !selectedSite) return;
    const url = selectedSite === ORG_FOCUS_VALUE
      ? `${API_BASE}/api/v1/wlans`
      : `${API_BASE}/api/v1/wlans?site_id=${selectedSite}`;
    apiFetch(url)
      .then((r) => r.json())
      .then((data) => {
        const newWlans = [...(data.wlans || [])].sort();
        setWlans(newWlans);
        if (newWlans.length === 0) {
          setSelectedWlan(null);
          return;
        }
        const prev = selectedWlanRef.current;
        setSelectedWlan(newWlans.includes(prev) ? prev : newWlans[0]);
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

  async function handleCollectEvents() {
    if (!selectedSite) return;
    setAS("collect", "loading");
    try {
      const endpoint = selectedSite === ORG_FOCUS_VALUE
        ? `${API_BASE}/api/v1/org/collect`
        : `${API_BASE}/api/v1/sites/${selectedSite}/collect`;
      const r = await apiFetch(endpoint, { method: "POST" });
      if (!r.ok && r.status !== 409) throw new Error(`HTTP ${r.status}`);
      setAS("collect", "ok");
      setTimeout(() => setAS("collect", "idle"), 2000);
    } catch {
      setAS("collect", "error");
      setTimeout(() => setAS("collect", "idle"), 3000);
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

  async function handleToggleOrgDetection() {
    const newVal = !orgDetectionEnabled;
    setAS("orgDetection", "loading");
    try {
      await apiFetch(`${API_BASE}/api/v1/org/detection-enabled`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled: newVal }),
      });
      setOrgDetectionEnabled(newVal);
      setAS("orgDetection", "ok");
      setTimeout(() => setAS("orgDetection", "idle"), 2000);
    } catch {
      setAS("orgDetection", "error");
      setTimeout(() => setAS("orgDetection", "idle"), 3000);
    }
  }

  function handleOpenWebhookConfig() {
    setWebhookDraft(webhookConfig ? { ...webhookConfig } : {
      enabled: false, url: "", scope: "org_and_site", marvis_tshoot_enabled: false, family_size_threshold: 1,
    });
    setWebhookSaveState("idle");
  }

  async function handleSaveWebhookConfig() {
    if (!webhookDraft) return;
    setWebhookSaveState("saving");
    try {
      const r = await apiFetch(`${API_BASE}/api/v1/webhook-config`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(webhookDraft),
      });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const saved = await r.json();
      setWebhookConfig(saved);
      setWebhookSaveState("ok");
      setTimeout(() => {
        setConfigModalOpen(false);
        setWebhookSaveState("idle");
      }, 800);
    } catch {
      setWebhookSaveState("error");
    }
  }

  function handleOpenGeneralConfig() {
    setGeneralConfigDraft(generalConfig ? { ...generalConfig } : {
      site_focus_detection_interval: 60,
      org_detection_interval_hours: 1,
      cache_miss_refresh_threshold: 10,
      anomaly_min_mac_events: 5,
    });
    setGeneralConfigSaveState("idle");
  }

  async function handleSaveGeneralConfig() {
    if (!generalConfigDraft) return;
    setGeneralConfigSaveState("saving");
    try {
      const r = await apiFetch(`${API_BASE}/api/v1/general-config`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(generalConfigDraft),
      });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const saved = await r.json();
      setGeneralConfig(saved);
      setGeneralConfigSaveState("ok");
      setTimeout(() => { setConfigModalOpen(false); setGeneralConfigSaveState("idle"); }, 800);
    } catch {
      setGeneralConfigSaveState("error");
    }
  }

  function handleOpenAnomalyConfig() {
    setAnomalyConfigDraft(anomalyConfig ? { ...anomalyConfig } : {
      anomaly_if_contamination: 0.05,
      anomaly_dbscan_eps: 2.5,
      anomaly_dbscan_min_samples: 5,
      anomaly_dbscan_min_family_size: 2,
      anomaly_finding_threshold: 0.2,
      anomaly_min_peers: 3,
      anomaly_centroid_if_min_families: 3,
      anomaly_centroid_dist_max_families: 10,
      anomaly_centroid_dist_threshold: 0.35,
      anomaly_health_score_threshold: 0.80,
      markov_family_outlier_ratio: 0.5,
      markov_stuck_loop_threshold: 0.4,
      markov_stuck_loop_min_events: 20,
      markov_min_episode_length: 3,
      markov_outlier_episode_ratio: 0.5,
      markov_short_episode_min_count: 3,
      markov_min_scoreable_episodes: 2,
    });
    setAnomalyConfigSaveState("idle");
  }

  async function handleSaveAnomalyConfig() {
    if (!anomalyConfigDraft) return;
    setAnomalyConfigSaveState("saving");
    try {
      const r = await apiFetch(`${API_BASE}/api/v1/anomaly-config`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(anomalyConfigDraft),
      });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const saved = await r.json();
      setAnomalyConfig(saved);
      setAnomalyConfigSaveState("ok");
      setTimeout(() => { setConfigModalOpen(false); setAnomalyConfigSaveState("idle"); }, 800);
    } catch {
      setAnomalyConfigSaveState("error");
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
          {selectedSite && (
            <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
              <span style={{ color: "#888", fontSize: "13px" }}>WLAN:</span>
              {wlans.length === 0 ? (
                <select
                  disabled
                  style={{
                    background: "#1a1a1a",
                    color: "#555",
                    border: "1px solid #2a2a2a",
                    padding: "4px 8px",
                    borderRadius: "4px",
                    cursor: "default",
                    fontSize: "13px",
                    fontFamily: "monospace",
                  }}
                >
                  <option>No WLANs detected yet</option>
                </select>
              ) : (
                <select
                  value={selectedWlan ?? ""}
                  onChange={(e) => { setWlanLoading(true); setSelectedWlan(e.target.value); setView("overview"); setSelectedMac(null); setSelectedFamily(null); }}
                  style={{
                    background: "#222",
                    color: "#e0e0e0",
                    border: "1px solid #2d7a4f",
                    padding: "4px 8px",
                    borderRadius: "4px",
                    cursor: "pointer",
                    fontSize: "13px",
                    fontFamily: "monospace",
                  }}
                >
                  {wlans.map((w) => (
                    <option key={w} value={w}>{w}</option>
                  ))}
                </select>
              )}
            </div>
          )}

          {/* Utilities Dropdown */}
          {selectedSite && (
            <div style={{ position: "relative" }}>
              <button
                onClick={() => setUtilDropdownOpen(o => !o)}
                onBlur={() => setTimeout(() => setUtilDropdownOpen(false), 150)}
                style={{ background: "#222", color: "#888", border: "1px solid #444", padding: "4px 8px", borderRadius: "4px", cursor: "pointer", fontSize: "13px", fontFamily: "monospace" }}
              >
                Utilities ▾
              </button>
              {utilDropdownOpen && (
                <div style={{ position: "absolute", top: "100%", left: 0, zIndex: 100, background: "#1a1a1a", border: "1px solid #444", borderRadius: "4px", marginTop: "2px", minWidth: "180px", boxShadow: "0 4px 12px rgba(0,0,0,0.5)" }}>
                  {[
                    { key: "clientRefresh", label: "Client Refresh", handler: handleClientRefresh, loadLabel: "Refreshing…", okLabel: "Refreshed ✓" },
                    { key: "discover", label: "Full Discovery", handler: handleFullDiscovery, loadLabel: "Discovering…", okLabel: "Done ✓", loadKey: "running" },
                    { key: "collect", label: "Full Events", handler: handleCollectEvents, loadLabel: "Collecting…", okLabel: "Collected ✓" },
                    { key: "detect", label: "Re-detect Anomalies", handler: handleDetect, loadLabel: "Detecting…", okLabel: "Done ✓" },
                  ].map(item => {
                    const s = actionState[item.key];
                    const busy = s === "loading" || s === "running";
                    const label = busy ? item.loadLabel : s === "ok" ? item.okLabel : s === "error" ? "Error ✗" : item.label;
                    return (
                      <div
                        key={item.key}
                        onMouseDown={() => { if (!busy) { item.handler(); setUtilDropdownOpen(false); } }}
                        onMouseEnter={e => { if (!busy) e.currentTarget.style.background = "#252525"; }}
                        onMouseLeave={e => e.currentTarget.style.background = "transparent"}
                        style={{ padding: "7px 12px", cursor: busy ? "default" : "pointer", fontSize: "12px", fontFamily: "monospace", color: s === "ok" ? "#2d7a4f" : s === "error" ? "#e05555" : busy ? "#555" : "#ccc", borderBottom: "1px solid #2a2a2a" }}
                      >
                        {label}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}

          <div style={{ marginLeft: "auto", display: "flex", gap: "8px", alignItems: "center" }}>
            <button
              onClick={() => { setConfigTab("general"); setConfigModalOpen(true); handleOpenGeneralConfig(); }}
              style={{
                background: "transparent",
                color: "#7ec8e3",
                border: "1px solid #2d5a8a",
                padding: "4px 10px",
                borderRadius: "4px",
                cursor: "pointer",
                fontSize: "12px",
                fontFamily: "monospace",
              }}
            >
              Config
            </button>
            <button
              onClick={() => { clearToken(); setTokenState(null); }}
              style={{
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

          {/* Org Detection Toggle */}
          {(() => {
            const s = actionState.orgDetection;
            const on = orgDetectionEnabled;
            return (
              <button
                onClick={handleToggleOrgDetection}
                disabled={s === "loading"}
                title={on ? "Org-wide scheduled detection is active — click to disable" : "Org-wide scheduled detection is disabled — click to enable"}
                style={{
                  background: s === "error" ? "#3a1a1a" : on ? "#1a2a1a" : "#2a1a1a",
                  color: s === "error" ? "#e05555" : s === "ok" ? "#7ec8e3" : on ? "#2d7a4f" : "#c08030",
                  border: `1px solid ${s === "error" ? "#5a2a2a" : on ? "#2d4a2d" : "#5a3a1a"}`,
                  borderRadius: "4px",
                  padding: "4px 10px",
                  cursor: s === "loading" ? "default" : "pointer",
                  fontSize: "12px",
                  fontFamily: "monospace",
                }}
              >
                {s === "loading" ? "…" : s === "error" ? "Error ✗" : on ? "Org Detection: On" : "Org Detection: Off"}
              </button>
            );
          })()}

          <div style={{ width: "1px", height: "24px", background: "#2a2a2a" }} />

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

        </div>

        {/* Progress bar for Full Discovery */}
        <ProgressBar progress={progress} />
      </header>

      {selectedSite && selectedSite !== ORG_FOCUS_VALUE && (view === "overview" || view === "findings") && (
        <div style={{ display: "flex", gap: "8px", marginBottom: "18px" }}>
          {["overview", "findings"].map((v) => {
            const label = v === "overview" ? "Site Overview" : "Findings";
            const active = view === v;
            return (
              <button
                key={v}
                onClick={() => setView(v)}
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
      )}
      <div style={{ position: "relative" }}>
        {wlanLoading && <WlanLoadingOverlay />}
        {selectedSite === ORG_FOCUS_VALUE && view === "overview" && selectedWlan && (
          <OrgOverview apiBase={API_BASE} onSiteSelect={handleSiteSelect} onMacSiteSelect={handleOrgMacSelect} refreshToken={discoveryRefreshToken} wlan={selectedWlan} onLoaded={() => setWlanLoading(false)} />
        )}
        {selectedSite && selectedSite !== ORG_FOCUS_VALUE && view === "overview" && selectedWlan && (
          <SiteOverview siteId={selectedSite} apiBase={API_BASE} onMacSelect={handleMacSelect} onFamilySelect={handleFamilySelect} refreshToken={discoveryRefreshToken} wlan={selectedWlan} onLoaded={() => setWlanLoading(false)} />
        )}
      </div>
      {selectedSite && selectedSite !== ORG_FOCUS_VALUE && view === "findings" && selectedWlan && (
        <FindingsFeed siteId={selectedSite} apiBase={API_BASE} onMacSelect={handleMacSelect} refreshToken={discoveryRefreshToken} wlan={selectedWlan} />
      )}
      {selectedSite && selectedSite !== ORG_FOCUS_VALUE && view === "family" && selectedFamily && selectedWlan && (
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
      {selectedSite && selectedSite !== ORG_FOCUS_VALUE && view === "mac" && selectedMac && selectedWlan && (
        <MacDrilldown
          siteId={selectedSite}
          mac={selectedMac}
          apiBase={API_BASE}
          onBack={() => selectedFamily ? setView("family") : setView("findings")}
          wlan={selectedWlan}
        />
      )}

      {/* Unified Config Modal */}
      {configModalOpen && (
        <div
          style={{ position: "fixed", inset: 0, zIndex: 200, background: "rgba(0,0,0,0.65)", display: "flex", alignItems: "center", justifyContent: "center" }}
          onClick={(e) => { if (e.target === e.currentTarget) setConfigModalOpen(false); }}
        >
          <div style={{ background: "#161616", border: "1px solid #2a2a3a", borderRadius: "6px", padding: "24px 28px", width: "540px", maxWidth: "95vw", maxHeight: "90vh", overflowY: "auto", boxShadow: "0 8px 32px rgba(0,0,0,0.7)", fontFamily: "monospace" }}>
            {/* Header with close */}
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
              <h2 style={{ margin: 0, fontSize: "15px", color: "#7ec8e3" }}>Configuration</h2>
              <button onClick={() => setConfigModalOpen(false)} style={{ background: "none", border: "none", color: "#555", cursor: "pointer", fontSize: "18px", lineHeight: 1, padding: "0 2px" }}>×</button>
            </div>

            {/* Tab bar */}
            <div style={{ display: "flex", gap: "4px", marginBottom: "20px", borderBottom: "1px solid #2a2a2a", paddingBottom: "0" }}>
              {[
                { key: "general", label: "General Config" },
                { key: "anomaly", label: "Anomaly Config" },
                { key: "webhook", label: "Webhook Config" },
              ].map(tab => {
                const active = configTab === tab.key;
                return (
                  <button
                    key={tab.key}
                    onClick={() => {
                      setConfigTab(tab.key);
                      if (tab.key === "general") handleOpenGeneralConfig();
                      else if (tab.key === "anomaly") handleOpenAnomalyConfig();
                      else handleOpenWebhookConfig();
                    }}
                    style={{
                      background: active ? "#1a2a3a" : "transparent",
                      color: active ? "#7ec8e3" : "#666",
                      border: "1px solid",
                      borderColor: active ? "#2d5a8a" : "transparent",
                      borderBottom: active ? "1px solid #161616" : "1px solid #2a2a2a",
                      borderRadius: "4px 4px 0 0",
                      padding: "6px 14px",
                      cursor: "pointer",
                      fontSize: "12px",
                      fontFamily: "monospace",
                      marginBottom: "-1px",
                    }}
                  >
                    {tab.label}
                  </button>
                );
              })}
            </div>

            {/* ═══════ General Config Tab ═══════ */}
            {configTab === "general" && generalConfigDraft && (<>
              <div style={{ marginBottom: "18px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: "5px" }}>
                  <div style={{ color: "#888", fontSize: "11px" }}>SITE DETECTION INTERVAL (MINUTES)</div>
                  <div style={{ color: "#7ec8e3", fontSize: "13px", fontWeight: "bold" }}>{generalConfigDraft.site_focus_detection_interval} min</div>
                </div>
                <input type="range" min={1} max={120} value={generalConfigDraft.site_focus_detection_interval} onChange={(e) => setGeneralConfigDraft(d => ({ ...d, site_focus_detection_interval: Number(e.target.value) }))} style={{ width: "100%", accentColor: "#7ec8e3", cursor: "pointer" }} />
                <div style={{ color: "#555", fontSize: "11px", marginTop: "4px" }}>How often the detection pipeline runs for the focused site. Lower values = more frequent detection but more Mist API calls.</div>
              </div>

              <div style={{ marginBottom: "18px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: "5px" }}>
                  <div style={{ color: "#888", fontSize: "11px" }}>ORG DETECTION INTERVAL (HOURS)</div>
                  <div style={{ color: "#7ec8e3", fontSize: "13px", fontWeight: "bold" }}>{generalConfigDraft.org_detection_interval_hours} hr</div>
                </div>
                <input type="range" min={1} max={24} value={generalConfigDraft.org_detection_interval_hours} onChange={(e) => setGeneralConfigDraft(d => ({ ...d, org_detection_interval_hours: Number(e.target.value) }))} style={{ width: "100%", accentColor: "#7ec8e3", cursor: "pointer" }} />
                <div style={{ color: "#555", fontSize: "11px", marginTop: "4px" }}>How often the org-wide cross-site detection job runs. Each run collects events from all org sites and scores them together.</div>
              </div>

              <div style={{ marginBottom: "18px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: "5px" }}>
                  <div style={{ color: "#888", fontSize: "11px" }}>CACHE MISS REFRESH THRESHOLD</div>
                  <div style={{ color: "#7ec8e3", fontSize: "13px", fontWeight: "bold" }}>{generalConfigDraft.cache_miss_refresh_threshold} misses</div>
                </div>
                <input type="range" min={1} max={100} value={generalConfigDraft.cache_miss_refresh_threshold} onChange={(e) => setGeneralConfigDraft(d => ({ ...d, cache_miss_refresh_threshold: Number(e.target.value) }))} style={{ width: "100%", accentColor: "#7ec8e3", cursor: "pointer" }} />
                <div style={{ color: "#555", fontSize: "11px", marginTop: "4px" }}>Number of MAC cache misses per batch that trigger an early client cache refresh. Prevents stale device family labels mid-cycle.</div>
              </div>

              <div style={{ marginBottom: "24px", paddingBottom: "20px", borderBottom: "1px solid #222" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: "5px" }}>
                  <div style={{ color: "#888", fontSize: "11px" }}>MIN MAC EVENTS FOR ML SCORING</div>
                  <div style={{ color: "#7ec8e3", fontSize: "13px", fontWeight: "bold" }}>{generalConfigDraft.anomaly_min_mac_events} events</div>
                </div>
                <input type="range" min={1} max={50} value={generalConfigDraft.anomaly_min_mac_events} onChange={(e) => setGeneralConfigDraft(d => ({ ...d, anomaly_min_mac_events: Number(e.target.value) }))} style={{ width: "100%", accentColor: "#7ec8e3", cursor: "pointer" }} />
                <div style={{ color: "#555", fontSize: "11px", marginTop: "4px" }}>Minimum events a MAC must have in the rolling 24hr window to be included in anomaly scoring. Lower for IoT/device WLANs; raise for high-traffic WLANs.</div>
              </div>

              <div style={{ display: "flex", gap: "10px", justifyContent: "flex-end" }}>
                <button onClick={() => setConfigModalOpen(false)} style={{ background: "transparent", color: "#666", border: "1px solid #2a2a2a", borderRadius: "4px", padding: "6px 16px", cursor: "pointer", fontSize: "12px", fontFamily: "monospace" }}>Cancel</button>
                <button
                  onClick={handleSaveGeneralConfig}
                  disabled={generalConfigSaveState === "saving"}
                  style={{ background: generalConfigSaveState === "ok" ? "#1a3a1a" : generalConfigSaveState === "error" ? "#2a1515" : "#0d2a38", color: generalConfigSaveState === "ok" ? "#2d7a4f" : generalConfigSaveState === "error" ? "#e05555" : "#7ec8e3", border: `1px solid ${generalConfigSaveState === "ok" ? "#2d7a4f55" : generalConfigSaveState === "error" ? "#e0555555" : "#2d5a8a"}`, borderRadius: "4px", padding: "6px 18px", cursor: generalConfigSaveState === "saving" ? "default" : "pointer", fontSize: "12px", fontFamily: "monospace" }}
                >
                  {generalConfigSaveState === "saving" ? "Saving…" : generalConfigSaveState === "ok" ? "Saved ✓" : generalConfigSaveState === "error" ? "Error ✗" : "Save"}
                </button>
              </div>
            </>)}

            {/* ═══════ Anomaly Config Tab ═══════ */}
            {configTab === "anomaly" && anomalyConfigDraft && (<>
              <div style={{ color: "#c08030", fontSize: "11px", marginBottom: "20px", background: "#2a1f10", border: "1px solid #3a2a10", borderRadius: "4px", padding: "7px 10px" }}>
                Changes take effect on the next detection run. Use <strong>Utilities → Re-detect Anomalies</strong> to apply immediately.
              </div>

              {/* ── Isolation Forest ── */}
              <div style={{ color: "#555", fontSize: "10px", letterSpacing: "0.08em", marginBottom: "12px" }}>ISOLATION FOREST</div>

              <div style={{ marginBottom: "18px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: "5px" }}>
                  <div style={{ color: "#888", fontSize: "11px" }}>IF CONTAMINATION</div>
                  <div style={{ color: "#7ec8e3", fontSize: "13px", fontWeight: "bold" }}>{anomalyConfigDraft.anomaly_if_contamination.toFixed(2)}</div>
                </div>
                <input type="range" min={1} max={50} value={Math.round(anomalyConfigDraft.anomaly_if_contamination * 100)} onChange={(e) => setAnomalyConfigDraft(d => ({ ...d, anomaly_if_contamination: Number(e.target.value) / 100 }))} style={{ width: "100%", accentColor: "#7ec8e3", cursor: "pointer" }} />
                <div style={{ color: "#555", fontSize: "11px", marginTop: "4px" }}>Expected fraction of MACs per family that are behavioral outliers. Lower = stricter (fewer individual flags). Range: 0.01–0.50.</div>
              </div>

              <div style={{ marginBottom: "18px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: "5px" }}>
                  <div style={{ color: "#888", fontSize: "11px" }}>MIN PEERS FOR IF</div>
                  <div style={{ color: "#7ec8e3", fontSize: "13px", fontWeight: "bold" }}>{anomalyConfigDraft.anomaly_min_peers}</div>
                </div>
                <input type="range" min={2} max={20} value={anomalyConfigDraft.anomaly_min_peers} onChange={(e) => setAnomalyConfigDraft(d => ({ ...d, anomaly_min_peers: Number(e.target.value) }))} style={{ width: "100%", accentColor: "#7ec8e3", cursor: "pointer" }} />
                <div style={{ color: "#555", fontSize: "11px", marginTop: "4px" }}>Minimum MACs a family needs at a site before Isolation Forest runs on it. Families below this threshold use org-level pooling.</div>
              </div>

              {/* ── DBSCAN ── */}
              <div style={{ color: "#555", fontSize: "10px", letterSpacing: "0.08em", marginBottom: "12px", marginTop: "4px" }}>DBSCAN</div>

              <div style={{ marginBottom: "18px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: "5px" }}>
                  <div style={{ color: "#888", fontSize: "11px" }}>DBSCAN EPSILON (EPS)</div>
                  <div style={{ color: "#7ec8e3", fontSize: "13px", fontWeight: "bold" }}>{anomalyConfigDraft.anomaly_dbscan_eps.toFixed(1)}</div>
                </div>
                <input type="range" min={1} max={100} value={Math.round(anomalyConfigDraft.anomaly_dbscan_eps * 10)} onChange={(e) => setAnomalyConfigDraft(d => ({ ...d, anomaly_dbscan_eps: Number(e.target.value) / 10 }))} style={{ width: "100%", accentColor: "#7ec8e3", cursor: "pointer" }} />
                <div style={{ color: "#555", fontSize: "11px", marginTop: "4px" }}>Neighborhood radius in PCA-reduced feature space. Higher = looser clusters (fewer noise/outlier points). Re-tune with a k-distance plot.</div>
              </div>

              <div style={{ marginBottom: "18px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: "5px" }}>
                  <div style={{ color: "#888", fontSize: "11px" }}>DBSCAN MIN SAMPLES</div>
                  <div style={{ color: "#7ec8e3", fontSize: "13px", fontWeight: "bold" }}>{anomalyConfigDraft.anomaly_dbscan_min_samples}</div>
                </div>
                <input type="range" min={2} max={30} value={anomalyConfigDraft.anomaly_dbscan_min_samples} onChange={(e) => setAnomalyConfigDraft(d => ({ ...d, anomaly_dbscan_min_samples: Number(e.target.value) }))} style={{ width: "100%", accentColor: "#7ec8e3", cursor: "pointer" }} />
                <div style={{ color: "#555", fontSize: "11px", marginTop: "4px" }}>Minimum neighbors required for a point to be a DBSCAN core point. Lower = easier cluster formation (fewer orphan noise points).</div>
              </div>

              <div style={{ marginBottom: "18px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: "5px" }}>
                  <div style={{ color: "#888", fontSize: "11px" }}>DBSCAN MIN FAMILY SIZE</div>
                  <div style={{ color: "#7ec8e3", fontSize: "13px", fontWeight: "bold" }}>{anomalyConfigDraft.anomaly_dbscan_min_family_size}</div>
                </div>
                <input type="range" min={1} max={20} value={anomalyConfigDraft.anomaly_dbscan_min_family_size} onChange={(e) => setAnomalyConfigDraft(d => ({ ...d, anomaly_dbscan_min_family_size: Number(e.target.value) }))} style={{ width: "100%", accentColor: "#7ec8e3", cursor: "pointer" }} />
                <div style={{ color: "#555", fontSize: "11px", marginTop: "4px" }}>Minimum MACs a family must have to participate in site-wide DBSCAN. Smaller families skip DBSCAN but still go through Isolation Forest.</div>
              </div>

              {/* ── Centroid Detection ── */}
              <div style={{ color: "#555", fontSize: "10px", letterSpacing: "0.08em", marginBottom: "12px", marginTop: "4px" }}>CENTROID DETECTION (INTER-FAMILY)</div>

              <div style={{ marginBottom: "18px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: "5px" }}>
                  <div style={{ color: "#888", fontSize: "11px" }}>MIN QUALIFYING FAMILIES</div>
                  <div style={{ color: "#7ec8e3", fontSize: "13px", fontWeight: "bold" }}>{anomalyConfigDraft.anomaly_centroid_if_min_families}</div>
                </div>
                <input type="range" min={2} max={20} value={anomalyConfigDraft.anomaly_centroid_if_min_families} onChange={(e) => setAnomalyConfigDraft(d => ({ ...d, anomaly_centroid_if_min_families: Number(e.target.value) }))} style={{ width: "100%", accentColor: "#7ec8e3", cursor: "pointer" }} />
                <div style={{ color: "#555", fontSize: "11px", marginTop: "4px" }}>Minimum qualifying device families required before inter-family centroid detection runs. Below this, all families pass (no family-level flags).</div>
              </div>

              <div style={{ marginBottom: "18px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: "5px" }}>
                  <div style={{ color: "#888", fontSize: "11px" }}>COSINE DISTANCE MAX FAMILIES</div>
                  <div style={{ color: "#7ec8e3", fontSize: "13px", fontWeight: "bold" }}>{anomalyConfigDraft.anomaly_centroid_dist_max_families}</div>
                </div>
                <input type="range" min={3} max={30} value={anomalyConfigDraft.anomaly_centroid_dist_max_families} onChange={(e) => setAnomalyConfigDraft(d => ({ ...d, anomaly_centroid_dist_max_families: Number(e.target.value) }))} style={{ width: "100%", accentColor: "#7ec8e3", cursor: "pointer" }} />
                <div style={{ color: "#555", fontSize: "11px", marginTop: "4px" }}>Sites with up to this many qualifying families use cosine-distance detection instead of Isolation Forest. IF is statistically unreliable at small N.</div>
              </div>

              <div style={{ marginBottom: "18px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: "5px" }}>
                  <div style={{ color: "#888", fontSize: "11px" }}>COSINE DISTANCE THRESHOLD</div>
                  <div style={{ color: "#7ec8e3", fontSize: "13px", fontWeight: "bold" }}>{anomalyConfigDraft.anomaly_centroid_dist_threshold.toFixed(2)}</div>
                </div>
                <input type="range" min={0} max={100} value={Math.round(anomalyConfigDraft.anomaly_centroid_dist_threshold * 100)} onChange={(e) => setAnomalyConfigDraft(d => ({ ...d, anomaly_centroid_dist_threshold: Number(e.target.value) / 100 }))} style={{ width: "100%", accentColor: "#7ec8e3", cursor: "pointer" }} />
                <div style={{ color: "#555", fontSize: "11px", marginTop: "4px" }}>Cosine distance from the population median above which a family centroid is flagged as a behavioral outlier (is_family_outlier). Higher = less sensitive.</div>
              </div>

              {/* ── Centroid Healthy Ref ── */}
              <div style={{ color: "#555", fontSize: "10px", letterSpacing: "0.08em", marginBottom: "12px", marginTop: "4px" }}>CENTROID HEALTHY REFERENCE</div>

              <div style={{ marginBottom: "18px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: "5px" }}>
                  <div style={{ color: "#888", fontSize: "11px" }}>HEALTHY REF THRESHOLD</div>
                  <div style={{ color: "#7ec8e3", fontSize: "13px", fontWeight: "bold" }}>{((anomalyConfigDraft.anomaly_centroid_healthy_ref_threshold ?? 0.75) * 100).toFixed(0)}%</div>
                </div>
                <input type="range" min={0} max={100} value={Math.round((anomalyConfigDraft.anomaly_centroid_healthy_ref_threshold ?? 0.75) * 100)} onChange={(e) => setAnomalyConfigDraft(d => ({ ...d, anomaly_centroid_healthy_ref_threshold: Number(e.target.value) / 100 }))} style={{ width: "100%", accentColor: "#7ec8e3", cursor: "pointer" }} />
                <div style={{ color: "#555", fontSize: "11px", marginTop: "4px" }}>Families with mean health above this form the healthy reference pool for centroid detection. Below this they are measured against it, not part of it.</div>
              </div>

              {/* ── Finding Rollup ── */}
              <div style={{ color: "#555", fontSize: "10px", letterSpacing: "0.08em", marginBottom: "12px", marginTop: "4px" }}>FINDING ROLLUP</div>

              <div style={{ marginBottom: "18px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: "5px" }}>
                  <div style={{ color: "#888", fontSize: "11px" }}>FINDING THRESHOLD</div>
                  <div style={{ color: "#7ec8e3", fontSize: "13px", fontWeight: "bold" }}>{(anomalyConfigDraft.anomaly_finding_threshold * 100).toFixed(0)}%</div>
                </div>
                <input type="range" min={0} max={100} value={Math.round(anomalyConfigDraft.anomaly_finding_threshold * 100)} onChange={(e) => setAnomalyConfigDraft(d => ({ ...d, anomaly_finding_threshold: Number(e.target.value) / 100 }))} style={{ width: "100%", accentColor: "#7ec8e3", cursor: "pointer" }} />
                <div style={{ color: "#555", fontSize: "11px", marginTop: "4px" }}>Fraction of outlier MACs required before a finding is generated for a device family. Lower = more findings. Severity is separate (minimal/moderate/significant).</div>
              </div>

              {/* ── Health Score ── */}
              <div style={{ color: "#555", fontSize: "10px", letterSpacing: "0.08em", marginBottom: "12px", marginTop: "4px" }}>HEALTH SCORE</div>

              <div style={{ marginBottom: "18px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: "5px" }}>
                  <div style={{ color: "#888", fontSize: "11px" }}>HEALTH SCORE THRESHOLD</div>
                  <div style={{ color: "#7ec8e3", fontSize: "13px", fontWeight: "bold" }}>{(anomalyConfigDraft.anomaly_health_score_threshold * 100).toFixed(0)}%</div>
                </div>
                <input type="range" min={0} max={100} value={Math.round(anomalyConfigDraft.anomaly_health_score_threshold * 100)} onChange={(e) => setAnomalyConfigDraft(d => ({ ...d, anomaly_health_score_threshold: Number(e.target.value) / 100 }))} style={{ width: "100%", accentColor: "#7ec8e3", cursor: "pointer" }} />
                <div style={{ color: "#555", fontSize: "11px", marginTop: "4px" }}>Health score below which a family is considered degraded. Both anomaly AND health must fail for the webhook dual gate to trigger an alert.</div>
              </div>

              {/* ── Markov Chain ── */}
              <div style={{ color: "#555", fontSize: "10px", letterSpacing: "0.08em", marginBottom: "12px", marginTop: "4px" }}>MARKOV CHAIN</div>

              <div style={{ marginBottom: "18px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: "5px" }}>
                  <div style={{ color: "#888", fontSize: "11px" }}>FAMILY OUTLIER RATIO</div>
                  <div style={{ color: "#7ec8e3", fontSize: "13px", fontWeight: "bold" }}>{(anomalyConfigDraft.markov_family_outlier_ratio * 100).toFixed(0)}%</div>
                </div>
                <input type="range" min={0} max={100} value={Math.round(anomalyConfigDraft.markov_family_outlier_ratio * 100)} onChange={(e) => setAnomalyConfigDraft(d => ({ ...d, markov_family_outlier_ratio: Number(e.target.value) / 100 }))} style={{ width: "100%", accentColor: "#7ec8e3", cursor: "pointer" }} />
                <div style={{ color: "#555", fontSize: "11px", marginTop: "4px" }}>Fraction of clients in a family with anomalous Markov episode patterns before the family is flagged as is_family_markov_outlier.</div>
              </div>

              <div style={{ marginBottom: "18px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: "5px" }}>
                  <div style={{ color: "#888", fontSize: "11px" }}>STUCK LOOP THRESHOLD</div>
                  <div style={{ color: "#7ec8e3", fontSize: "13px", fontWeight: "bold" }}>{(anomalyConfigDraft.markov_stuck_loop_threshold * 100).toFixed(0)}%</div>
                </div>
                <input type="range" min={10} max={90} value={Math.round(anomalyConfigDraft.markov_stuck_loop_threshold * 100)} onChange={(e) => setAnomalyConfigDraft(d => ({ ...d, markov_stuck_loop_threshold: Number(e.target.value) / 100 }))} style={{ width: "100%", accentColor: "#7ec8e3", cursor: "pointer" }} />
                <div style={{ color: "#555", fontSize: "11px", marginTop: "4px" }}>Fraction of a MAC's transition pairs dominated by a single failure pair to flag it as stuck in a loop. Baseline-independent — catches devices that contaminate their own Markov baseline.</div>
              </div>

              <div style={{ marginBottom: "18px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: "5px" }}>
                  <div style={{ color: "#888", fontSize: "11px" }}>STUCK LOOP MIN EVENTS</div>
                  <div style={{ color: "#7ec8e3", fontSize: "13px", fontWeight: "bold" }}>{anomalyConfigDraft.markov_stuck_loop_min_events}</div>
                </div>
                <input type="range" min={5} max={200} value={anomalyConfigDraft.markov_stuck_loop_min_events} onChange={(e) => setAnomalyConfigDraft(d => ({ ...d, markov_stuck_loop_min_events: Number(e.target.value) }))} style={{ width: "100%", accentColor: "#7ec8e3", cursor: "pointer" }} />
                <div style={{ color: "#555", fontSize: "11px", marginTop: "4px" }}>Minimum events a MAC must have before stuck-loop detection runs. Fewer events makes single-pair dominance statistically noisy.</div>
              </div>

              <div style={{ marginBottom: "18px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: "5px" }}>
                  <div style={{ color: "#888", fontSize: "11px" }}>MIN EPISODE LENGTH</div>
                  <div style={{ color: "#7ec8e3", fontSize: "13px", fontWeight: "bold" }}>{anomalyConfigDraft.markov_min_episode_length}</div>
                </div>
                <input type="range" min={2} max={20} value={anomalyConfigDraft.markov_min_episode_length} onChange={(e) => setAnomalyConfigDraft(d => ({ ...d, markov_min_episode_length: Number(e.target.value) }))} style={{ width: "100%", accentColor: "#7ec8e3", cursor: "pointer" }} />
                <div style={{ color: "#555", fontSize: "11px", marginTop: "4px" }}>Episodes shorter than this go into the short-episode state machine. Longer episodes are scored via the event-level transition matrix.</div>
              </div>

              <div style={{ marginBottom: "18px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: "5px" }}>
                  <div style={{ color: "#888", fontSize: "11px" }}>EPISODE OUTLIER RATIO</div>
                  <div style={{ color: "#7ec8e3", fontSize: "13px", fontWeight: "bold" }}>{(anomalyConfigDraft.markov_outlier_episode_ratio * 100).toFixed(0)}%</div>
                </div>
                <input type="range" min={10} max={100} value={Math.round(anomalyConfigDraft.markov_outlier_episode_ratio * 100)} onChange={(e) => setAnomalyConfigDraft(d => ({ ...d, markov_outlier_episode_ratio: Number(e.target.value) / 100 }))} style={{ width: "100%", accentColor: "#7ec8e3", cursor: "pointer" }} />
                <div style={{ color: "#555", fontSize: "11px", marginTop: "4px" }}>Fraction of a MAC's scoreable normal episodes that must be anomalous to flag the MAC as a Markov outlier.</div>
              </div>

              <div style={{ marginBottom: "18px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: "5px" }}>
                  <div style={{ color: "#888", fontSize: "11px" }}>SHORT EPISODE MIN COUNT</div>
                  <div style={{ color: "#7ec8e3", fontSize: "13px", fontWeight: "bold" }}>{anomalyConfigDraft.markov_short_episode_min_count}</div>
                </div>
                <input type="range" min={1} max={20} value={anomalyConfigDraft.markov_short_episode_min_count} onChange={(e) => setAnomalyConfigDraft(d => ({ ...d, markov_short_episode_min_count: Number(e.target.value) }))} style={{ width: "100%", accentColor: "#7ec8e3", cursor: "pointer" }} />
                <div style={{ color: "#555", fontSize: "11px", marginTop: "4px" }}>Minimum number of short episodes before the repeated-short-episode flag can trigger.</div>
              </div>

              <div style={{ marginBottom: "24px", paddingBottom: "20px", borderBottom: "1px solid #222" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: "5px" }}>
                  <div style={{ color: "#888", fontSize: "11px" }}>MIN SCOREABLE EPISODES</div>
                  <div style={{ color: "#7ec8e3", fontSize: "13px", fontWeight: "bold" }}>{anomalyConfigDraft.markov_min_scoreable_episodes}</div>
                </div>
                <input type="range" min={1} max={20} value={anomalyConfigDraft.markov_min_scoreable_episodes} onChange={(e) => setAnomalyConfigDraft(d => ({ ...d, markov_min_scoreable_episodes: Number(e.target.value) }))} style={{ width: "100%", accentColor: "#7ec8e3", cursor: "pointer" }} />
                <div style={{ color: "#555", fontSize: "11px", marginTop: "4px" }}>Minimum scoreable normal episodes required before event-level ratio is computed. MACs with fewer are evaluated only via short-episode and sequence rules.</div>
              </div>

              <div style={{ display: "flex", gap: "10px", justifyContent: "flex-end" }}>
                <button onClick={() => setConfigModalOpen(false)} style={{ background: "transparent", color: "#666", border: "1px solid #2a2a2a", borderRadius: "4px", padding: "6px 16px", cursor: "pointer", fontSize: "12px", fontFamily: "monospace" }}>Cancel</button>
                <button
                  onClick={handleSaveAnomalyConfig}
                  disabled={anomalyConfigSaveState === "saving"}
                  style={{ background: anomalyConfigSaveState === "ok" ? "#1a3a1a" : anomalyConfigSaveState === "error" ? "#2a1515" : "#0d2a38", color: anomalyConfigSaveState === "ok" ? "#2d7a4f" : anomalyConfigSaveState === "error" ? "#e05555" : "#7ec8e3", border: `1px solid ${anomalyConfigSaveState === "ok" ? "#2d7a4f55" : anomalyConfigSaveState === "error" ? "#e0555555" : "#2d5a8a"}`, borderRadius: "4px", padding: "6px 18px", cursor: anomalyConfigSaveState === "saving" ? "default" : "pointer", fontSize: "12px", fontFamily: "monospace" }}
                >
                  {anomalyConfigSaveState === "saving" ? "Saving…" : anomalyConfigSaveState === "ok" ? "Saved ✓" : anomalyConfigSaveState === "error" ? "Error ✗" : "Save"}
                </button>
              </div>
            </>)}

            {/* ═══════ Webhook Config Tab ═══════ */}
            {configTab === "webhook" && webhookDraft && (<>
              <div style={{ marginBottom: "18px" }}>
                <label style={{ display: "flex", alignItems: "center", gap: "10px", cursor: "pointer" }}>
                  <input
                    type="checkbox"
                    checked={!!webhookDraft.enabled}
                    onChange={(e) => setWebhookDraft(d => ({ ...d, enabled: e.target.checked }))}
                    style={{ width: "15px", height: "15px", accentColor: "#7ec8e3", cursor: "pointer" }}
                  />
                  <span style={{ color: "#e0e0e0", fontSize: "13px" }}>Webhooks enabled</span>
                </label>
              </div>

              <div style={{ marginBottom: "18px" }}>
                <div style={{ color: "#888", fontSize: "11px", marginBottom: "5px" }}>WEBHOOK HTTP TARGET</div>
                <input
                  type="text"
                  value={webhookDraft.url ?? ""}
                  onChange={(e) => setWebhookDraft(d => ({ ...d, url: e.target.value }))}
                  placeholder="https://your-server/webhook"
                  disabled={!webhookDraft.enabled}
                  style={{
                    width: "100%", boxSizing: "border-box",
                    background: webhookDraft.enabled ? "#1e1e2e" : "#141414",
                    color: webhookDraft.enabled ? "#e0e0e0" : "#444",
                    border: "1px solid #2a2a3a", borderRadius: "4px",
                    padding: "6px 10px", fontSize: "12px", fontFamily: "monospace",
                  }}
                />
              </div>

              <div style={{ marginBottom: "18px" }}>
                <div style={{ color: "#888", fontSize: "11px", marginBottom: "8px" }}>WEBHOOK SCOPE</div>
                {[
                  { value: "org_and_site", label: "Org alarms and site alarms", desc: "Dispatch for both org-wide and per-site dual-gate alerts" },
                  { value: "org_only",     label: "Org alarms only",            desc: "Suppress site-level dispatches; only fire on org-wide findings" },
                ].map(opt => (
                  <label key={opt.value} style={{ display: "flex", alignItems: "flex-start", gap: "10px", marginBottom: "10px", cursor: webhookDraft.enabled ? "pointer" : "default" }}>
                    <input
                      type="radio"
                      name="webhook-scope"
                      value={opt.value}
                      checked={webhookDraft.scope === opt.value}
                      onChange={() => setWebhookDraft(d => ({ ...d, scope: opt.value }))}
                      disabled={!webhookDraft.enabled}
                      style={{ marginTop: "2px", accentColor: "#7ec8e3", cursor: "pointer" }}
                    />
                    <div>
                      <div style={{ color: webhookDraft.enabled ? "#e0e0e0" : "#444", fontSize: "13px" }}>{opt.label}</div>
                      <div style={{ color: webhookDraft.enabled ? "#555" : "#333", fontSize: "11px" }}>{opt.desc}</div>
                    </div>
                  </label>
                ))}
              </div>

              <div style={{ marginBottom: "18px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: "5px" }}>
                  <div style={{ color: "#888", fontSize: "11px" }}>MINIMUM FAMILY SIZE FOR WEBHOOK</div>
                  <div style={{ color: webhookDraft.enabled ? "#7ec8e3" : "#444", fontSize: "13px", fontWeight: "bold" }}>
                    {webhookDraft.family_size_threshold ?? 1} {(webhookDraft.family_size_threshold ?? 1) === 1 ? "device" : "devices"}
                  </div>
                </div>
                <input
                  type="range" min={1} max={50}
                  value={webhookDraft.family_size_threshold ?? 1}
                  onChange={(e) => setWebhookDraft(d => ({ ...d, family_size_threshold: Number(e.target.value) }))}
                  disabled={!webhookDraft.enabled}
                  style={{ width: "100%", accentColor: "#7ec8e3", cursor: webhookDraft.enabled ? "pointer" : "default" }}
                />
                <div style={{ color: "#555", fontSize: "11px", marginTop: "4px" }}>
                  Families with fewer affected devices than this threshold appear in the UI as alarms but do not trigger a webhook.
                </div>
              </div>

              <div style={{ marginBottom: "24px", paddingBottom: "20px", borderBottom: "1px solid #222" }}>
                <label style={{ display: "flex", alignItems: "flex-start", gap: "10px", cursor: webhookDraft.enabled ? "pointer" : "default" }}>
                  <input
                    type="checkbox"
                    checked={!!webhookDraft.marvis_tshoot_enabled}
                    onChange={(e) => setWebhookDraft(d => ({ ...d, marvis_tshoot_enabled: e.target.checked }))}
                    disabled={!webhookDraft.enabled}
                    style={{ marginTop: "2px", width: "15px", height: "15px", accentColor: "#7ec8e3", cursor: "pointer" }}
                  />
                  <div>
                    <div style={{ color: webhookDraft.enabled ? "#e0e0e0" : "#444", fontSize: "13px" }}>Marvis TSHOOT augmentation</div>
                    <div style={{ color: webhookDraft.enabled ? "#555" : "#333", fontSize: "11px" }}>Enrich webhook payloads with Marvis client troubleshoot results for worst-health MACs</div>
                  </div>
                </label>
              </div>

              <div style={{ display: "flex", gap: "10px", justifyContent: "flex-end" }}>
                <button onClick={() => setConfigModalOpen(false)} style={{ background: "transparent", color: "#666", border: "1px solid #2a2a2a", borderRadius: "4px", padding: "6px 16px", cursor: "pointer", fontSize: "12px", fontFamily: "monospace" }}>Cancel</button>
                <button
                  onClick={handleSaveWebhookConfig}
                  disabled={webhookSaveState === "saving"}
                  style={{
                    background: webhookSaveState === "ok" ? "#1a3a1a" : webhookSaveState === "error" ? "#2a1515" : "#0d2a38",
                    color: webhookSaveState === "ok" ? "#2d7a4f" : webhookSaveState === "error" ? "#e05555" : "#7ec8e3",
                    border: `1px solid ${webhookSaveState === "ok" ? "#2d7a4f55" : webhookSaveState === "error" ? "#e0555555" : "#2d5a8a"}`,
                    borderRadius: "4px", padding: "6px 18px", cursor: webhookSaveState === "saving" ? "default" : "pointer",
                    fontSize: "12px", fontFamily: "monospace",
                  }}
                >
                  {webhookSaveState === "saving" ? "Saving…" : webhookSaveState === "ok" ? "Saved ✓" : webhookSaveState === "error" ? "Error ✗" : "Save"}
                </button>
              </div>
            </>)}
          </div>
        </div>
      )}
    </div>
  );
}
