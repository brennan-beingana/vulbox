import { useState } from "react";
import { useNavigate } from "react-router-dom";
import axios from "axios";

const API = "http://127.0.0.1:8000";

function authHeaders() {
  return { Authorization: `Bearer ${localStorage.getItem("token")}` };
}

export default function NewRun() {
  const navigate = useNavigate();
  const [form, setForm] = useState({
    project_name: "",
    repo_url: "",
    branch: "main",
    image_tag: "latest",
    consent_granted: false,
  });
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    if (!form.consent_granted) {
      setError("You must consent to adversarial testing before proceeding.");
      return;
    }
    setError("");
    setLoading(true);
    try {
      const { data } = await axios.post(`${API}/runs`, form, { headers: authHeaders() });
      navigate(`/runs/${data.id}/status`);
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to start assessment");
      setLoading(false);
    }
  }

  function logout() {
    localStorage.removeItem("token");
    navigate("/login");
  }

  return (
    <main className="page">
      <section className="hero">
        <h1>VulBox</h1>
        <p>Submit a repository for automated security assessment.</p>
        <button onClick={logout} className="btn-ghost" style={{ marginTop: "0.5rem" }}>Sign out</button>
      </section>

      <div className="card">
        <h2>New Assessment</h2>
        <form onSubmit={handleSubmit}>
          <label>Project Name *
            <input value={form.project_name}
              onChange={e => setForm({ ...form, project_name: e.target.value })} required />
          </label>
          <label>GitHub Repository URL
            <input type="url" placeholder="https://github.com/org/repo"
              value={form.repo_url}
              onChange={e => setForm({ ...form, repo_url: e.target.value })} />
          </label>
          <label>Branch
            <input value={form.branch}
              onChange={e => setForm({ ...form, branch: e.target.value })} />
          </label>
          <label>Image Tag
            <input value={form.image_tag}
              onChange={e => setForm({ ...form, image_tag: e.target.value })} />
          </label>

          <div className="consent-block">
            <h3>Consent to Adversarial Testing</h3>
            <p>
              VulBox will build your repository into a Docker container and run it in an isolated
              sandbox. It will execute Atomic Red Team tests — controlled attack simulations — against
              your running application to measure exploitability. Falco will monitor the container for
              suspicious behaviour throughout the test. <strong>No network access is permitted during
              testing.</strong> This process is non-destructive but intentionally adversarial.
            </p>
            <label className="checkbox-label">
              <input type="checkbox" checked={form.consent_granted}
                onChange={e => setForm({ ...form, consent_granted: e.target.checked })} />
              I understand and consent to adversarial security testing of this repository
            </label>
          </div>

          {error && <p className="error">{error}</p>}
          <button type="submit" className="btn-primary" disabled={loading}>
            {loading ? "Starting..." : "Start Assessment"}
          </button>
        </form>
      </div>
    </main>
  );
}
