import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import axios from "axios";

const API = "http://46.101.193.155:8000";

function authHeaders() {
  return { Authorization: `Bearer ${localStorage.getItem("token")}` };
}

const CONFIDENCE_COLORS = {
  critical: "#dc2626",
  high: "#ea580c",
  medium: "#d97706",
  low: "#65a30d",
};

function riskColor(score) {
  if (score >= 40) return "#dc2626";
  if (score >= 25) return "#ea580c";
  if (score >= 15) return "#d97706";
  return "#65a30d";
}

export default function Report() {
  const { runId } = useParams();
  const [report, setReport] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    axios
      .get(`${API}/reports/${runId}`, { headers: authHeaders() })
      .then(r => setReport(r.data))
      .catch(err => setError(err.response?.data?.detail || "Failed to load report"));
  }, [runId]);

  function exportPDF() {
    window.open(`${API}/reports/${runId}/export?format=pdf`, "_blank");
  }

  function exportCSV() {
    window.open(`${API}/reports/${runId}/export?format=csv`, "_blank");
  }

  if (error) return <main className="page"><div className="card"><p className="error">{error}</p></div></main>;
  if (!report) return <main className="page"><div className="card"><p>Loading report…</p></div></main>;

  return (
    <main className="page">
      <section className="hero">
        <h1>Security Report — {report.project_name}</h1>
        <p>Run #{report.run_id} · {report.image_tag} · {report.status}</p>
      </section>

      <div className="card stats-row">
        <div className="stat"><span className="stat-num">{report.trivy_findings_count}</span><span>Trivy Findings</span></div>
        <div className="stat"><span className="stat-num">{report.art_tests_count}</span><span>ART Tests</span></div>
        <div className="stat"><span className="stat-num">{report.remediations_count}</span><span>Remediations</span></div>
        <div style={{ marginLeft: "auto", display: "flex", gap: "0.5rem", alignItems: "center" }}>
          <button onClick={exportCSV} className="btn-ghost">Export CSV</button>
          <button onClick={exportPDF} className="btn-primary">Export PDF</button>
        </div>
      </div>

      <div className="card">
        <h2>Security Matrix</h2>
        {report.security_matrix.length === 0
          ? <p className="muted">No matrix entries yet. Assessment may still be running.</p>
          : (
            <table className="matrix-table">
              <thead>
                <tr>
                  <th>MITRE Tactic</th>
                  <th>Present</th>
                  <th>Exploitable</th>
                  <th>Detectable</th>
                  <th>Risk Score</th>
                </tr>
              </thead>
              <tbody>
                {report.security_matrix.map(e => (
                  <tr key={e.entry_id}>
                    <td><code>{e.mitre_tactic_id || "—"}</code></td>
                    <td>{e.is_present ? "✓" : "✗"}</td>
                    <td style={{ color: e.is_exploitable ? "#dc2626" : "#16a34a", fontWeight: "bold" }}>
                      {e.is_exploitable ? "✓ Yes" : "✗ No"}
                    </td>
                    <td style={{ color: e.is_detectable ? "#16a34a" : "#dc2626", fontWeight: "bold" }}>
                      {e.is_detectable ? "✓ Yes" : "✗ No"}
                    </td>
                    <td>
                      <span className="risk-badge" style={{ background: riskColor(e.risk_score) }}>
                        {e.risk_score}/50
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
      </div>

      {report.remediations.length > 0 && (
        <div className="card">
          <h2>Remediation Actions</h2>
          {report.remediations.map(r => (
            <div key={r.id} className="remediation-card">
              <div className="rem-header">
                <strong>{r.summary}</strong>
                <span
                  className="confidence-badge"
                  style={{ background: CONFIDENCE_COLORS[r.confidence] || "#64748b" }}
                >
                  {r.confidence}
                </span>
              </div>
              <p><strong>Action:</strong> {r.priority_action}</p>
              <p><strong>Why:</strong> {r.why_it_matters}</p>
              <p><strong>Example:</strong> <code>{r.example_fix}</code></p>
            </div>
          ))}
        </div>
      )}
    </main>
  );
}
