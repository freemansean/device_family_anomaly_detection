import { useState } from "react";

export default function Login({ apiBase, onLogin }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${apiBase}/api/v1/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      if (res.status === 401) {
        setError("Invalid username or password.");
        return;
      }
      if (!res.ok) {
        setError(`Server error (${res.status}). Try again.`);
        return;
      }
      const { token } = await res.json();
      onLogin(token);
    } catch {
      setError("Could not reach the server. Is the backend running?");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={{
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      minHeight: "100vh",
      background: "#111",
    }}>
      <div style={{
        background: "#161616",
        border: "1px solid #2a2a2a",
        borderRadius: "6px",
        padding: "32px 40px",
        width: "320px",
      }}>
        <h1 style={{ margin: "0 0 4px 0", fontSize: "16px", color: "#7ec8e3" }}>
          Project Sasquatch
        </h1>
        <p style={{ margin: "0 0 24px 0", fontSize: "12px", color: "#555" }}>
          Client Anomaly Detection
        </p>

        <form onSubmit={handleSubmit}>
          <div style={{ marginBottom: "14px" }}>
            <label style={labelStyle}>Username</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
              required
              style={inputStyle}
            />
          </div>
          <div style={{ marginBottom: "20px" }}>
            <label style={labelStyle}>Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              required
              style={inputStyle}
            />
          </div>

          {error && (
            <div style={{ color: "#e05555", fontSize: "12px", marginBottom: "14px" }}>
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            style={{
              width: "100%",
              padding: "8px",
              background: loading ? "#1a3040" : "#2a4a5e",
              color: loading ? "#555" : "#7ec8e3",
              border: "1px solid #3a6a8e",
              borderRadius: "4px",
              cursor: loading ? "default" : "pointer",
              fontSize: "13px",
            }}
          >
            {loading ? "Signing in…" : "Sign in"}
          </button>
        </form>
      </div>
    </div>
  );
}

const labelStyle = {
  display: "block",
  fontSize: "12px",
  color: "#666",
  marginBottom: "5px",
};

const inputStyle = {
  width: "100%",
  background: "#0e0e0e",
  border: "1px solid #2a2a2a",
  borderRadius: "4px",
  color: "#e0e0e0",
  padding: "7px 10px",
  fontSize: "13px",
  boxSizing: "border-box",
  outline: "none",
};
