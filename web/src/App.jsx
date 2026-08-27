import { useState } from "react";
import "./App.css";

const API = "http://localhost:3001";

const CATEGORY_LABELS = {
  tls: "Transport security",
  headers: "Security headers",
  cookies: "Cookies",
};

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
      if (!res.ok) setError(data.error ?? "Scan failed");
      else setResult(data);
    } catch {
      setError("Could not reach the scanner service");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="app">
      <header className="masthead">
        <h1>Web Security Scanner</h1>
        <p className="sub">
          Passive assessment of TLS, security headers, and cookie configuration.
          Fetches the URL once — no active probing.
        </p>
      </header>

      <div className="row">
        <input
          type="text"
          value={url}
          placeholder="https://example.com"
          onChange={(e) => setUrl(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && url && !loading && runScan()}
        />
        <button onClick={runScan} disabled={loading || !url}>
          {loading ? "Scanning…" : "Scan"}
        </button>
      </div>

      {error && <div className="error">{error}</div>}

      {result && (
        <section className="results">
          <div className={`scorecard grade-${result.grade}`}>
            <div className="grade">{result.grade}</div>
            <div className="scoremeta">
              <div className="target">{result.target}</div>
              <div className="score">
                {result.score}/100 · {result.redirectHops} hop
                {result.redirectHops === 1 ? "" : "s"}
              </div>
              {result.gates?.map((g) => (
                <div className="gate" key={g}>{g}</div>
              ))}
            </div>
          </div>

          {Object.entries(result.categories).map(([key, findings]) => {
            const bd = result.breakdown.find((b) => b.category === key);
            return (
              <div className="category" key={key}>
                <h2>
                  {CATEGORY_LABELS[key] ?? key}
                  <span className="tally">
                    {bd?.passed ?? 0} passed · {bd?.failed ?? 0} failed
                    {bd?.cappedAt != null && ` · capped at −${bd.cappedAt}`}
                  </span>
                </h2>

                {findings.map((f) => (
                  <article key={f.id} className={`finding ${f.status}`}>
                    <header>
                      <span className={`badge ${f.severity}`}>{f.severity}</span>
                      <h3>{f.title}</h3>
                      <span className="status">
                        {f.status === "pass" ? "✓" : "✕"}
                      </span>
                    </header>
                    {f.status === "fail" ? (
                      <>
                        <p className="why">{f.why}</p>
                        <code className="fix">{f.fix}</code>
                        {f.detail && <p className="detail">{f.detail}</p>}
                      </>
                    ) : (
                      f.detail && <p className="detail">{f.detail}</p>
                    )}
                  </article>
                ))}
              </div>
            );
          })}
        </section>
      )}
    </main>
  );
}
