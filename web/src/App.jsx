import { useState } from "react";
import "./App.css";

const API = "http://localhost:3001";

export default function App() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  async function runScan() {
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const res = await fetch(`${API}/api/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
      const data = await res.json();

      if (!res.ok) {
        setError(data.error ?? "Scan failed");
      } else {
        setResult(data);
      }
    } catch {
      setError("Could not reach the scanner service");
    } finally {
      setLoading(false);
    }
  }

  function onKeyDown(e) {
    if (e.key === "Enter" && url && !loading) runScan();
  }

  return (
    <main className="app">
      <h1>Web Security Scanner</h1>
      <p className="sub">
        Passive check of security headers. Fetches the URL once — no active probing.
      </p>

      <div className="row">
        <input
          type="text"
          value={url}
          placeholder="https://example.com"
          onChange={(e) => setUrl(e.target.value)}
          onKeyDown={onKeyDown}
        />
        <button onClick={runScan} disabled={loading || !url}>
          {loading ? "Scanning…" : "Scan"}
        </button>
      </div>

      {error && <div className="error">{error}</div>}

      {result && (
        <section className="results">
          <div className="meta">
            <strong>{result.target}</strong>
            <span>
              {result.redirectHops} hop{result.redirectHops === 1 ? "" : "s"}
            </span>
          </div>

          {result.findings.map((f) => (
            <article key={f.id} className={`finding ${f.status}`}>
              <header>
                <span className={`badge ${f.severity}`}>{f.severity}</span>
                <h3>{f.title}</h3>
                <span className="status">{f.status === "pass" ? "✓" : "✕"}</span>
              </header>
              {f.status === "fail" ? (
                <>
                  <p className="why">{f.why}</p>
                  <code className="fix">{f.fix}</code>
                </>
              ) : (
                <p className="detail">{f.detail}</p>
              )}
            </article>
          ))}
        </section>
      )}
    </main>
  );
}
