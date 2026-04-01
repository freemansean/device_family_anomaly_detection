import { useState, useEffect } from "react";
import SiteOverview from "./components/SiteOverview";
import FindingsFeed from "./components/FindingsFeed";
import MacDrilldown from "./components/MacDrilldown";

const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

export default function App() {
  const [sites, setSites] = useState([]);
  const [selectedSite, setSelectedSite] = useState(null);
  const [selectedMac, setSelectedMac] = useState(null);
  const [view, setView] = useState("overview"); // "overview" | "findings" | "mac"

  useEffect(() => {
    fetch(`${API_BASE}/api/v1/sites`)
      .then((r) => r.json())
      .then((data) => {
        setSites(data.sites || []);
        if (data.sites?.length > 0) setSelectedSite(data.sites[0]);
      })
      .catch(console.error);
  }, []);

  function handleMacSelect(mac) {
    setSelectedMac(mac);
    setView("mac");
  }

  return (
    <div style={{ fontFamily: "monospace", padding: "16px", background: "#111", minHeight: "100vh", color: "#e0e0e0" }}>
      <header style={{ borderBottom: "1px solid #333", paddingBottom: "12px", marginBottom: "16px" }}>
        <h1 style={{ margin: 0, fontSize: "18px", color: "#7ec8e3" }}>
          Project Sasquatch — Client Anomaly Detection
        </h1>
        <div style={{ marginTop: "8px", display: "flex", gap: "12px", alignItems: "center" }}>
          <span style={{ color: "#888", fontSize: "13px" }}>Site:</span>
          <select
            value={selectedSite || ""}
            onChange={(e) => { setSelectedSite(e.target.value); setView("overview"); setSelectedMac(null); }}
            style={{ background: "#222", color: "#e0e0e0", border: "1px solid #444", padding: "4px 8px", borderRadius: "4px" }}
          >
            {sites.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <nav style={{ display: "flex", gap: "8px" }}>
            {["overview", "findings"].map((v) => (
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
                {v === "overview" ? "Site Overview" : "Findings"}
              </button>
            ))}
          </nav>
        </div>
      </header>

      {selectedSite && view === "overview" && (
        <SiteOverview siteId={selectedSite} apiBase={API_BASE} onMacSelect={handleMacSelect} />
      )}
      {selectedSite && view === "findings" && (
        <FindingsFeed siteId={selectedSite} apiBase={API_BASE} onMacSelect={handleMacSelect} />
      )}
      {selectedSite && view === "mac" && selectedMac && (
        <MacDrilldown
          siteId={selectedSite}
          mac={selectedMac}
          apiBase={API_BASE}
          onBack={() => setView("findings")}
        />
      )}
    </div>
  );
}
