import { useEffect, useState } from "react";

const API_BASE = "http://127.0.0.1:8000";

export default function App() {
  const [health, setHealth] = useState("checking");

  useEffect(() => {
    fetch(`${API_BASE}/health`)
      .then((res) => res.json())
      .then((data) => setHealth(data.status || "unknown"))
      .catch(() => setHealth("offline"));
  }, []);

  return (
    <main className="page">
      <section className="hero">
        <h1>VulBox</h1>
        <p>Automated security assessment pipeline for containerized apps.</p>
      </section>
      <section className="card">
        <h2>Backend Health</h2>
        <p>Status: {health}</p>
      </section>
      <section className="card">
        <h2>Next Build Targets</h2>
        <ul>
          <li>Create run workflow form</li>
          <li>Ingest Trivy and Falco results</li>
          <li>Correlated findings board</li>
        </ul>
      </section>
    </main>
  );
}
