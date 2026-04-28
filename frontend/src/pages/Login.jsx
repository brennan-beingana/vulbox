import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import axios from "axios";

const API = "http://127.0.0.1:8000";

export default function Login() {
  const navigate = useNavigate();
  const [form, setForm] = useState({ email: "", password: "" });
  const [error, setError] = useState("");

  async function handleSubmit(e) {
    e.preventDefault();
    setError("");
    try {
      const { data } = await axios.post(`${API}/auth/login`, form);
      localStorage.setItem("token", data.access_token);
      navigate("/");
    } catch (err) {
      setError(err.response?.data?.detail || "Login failed");
    }
  }

  return (
    <main className="page auth-page">
      <div className="auth-card">
        <div className="hero" style={{ marginBottom: "1.5rem" }}>
          <h1>VulBox</h1>
          <p>Automated security assessment pipeline</p>
        </div>
        <div className="card">
          <h2>Sign In</h2>
          <form onSubmit={handleSubmit}>
            <label>Email
              <input type="email" value={form.email}
                onChange={e => setForm({ ...form, email: e.target.value })} required />
            </label>
            <label>Password
              <input type="password" value={form.password}
                onChange={e => setForm({ ...form, password: e.target.value })} required />
            </label>
            {error && <p className="error">{error}</p>}
            <button type="submit" className="btn-primary">Sign In</button>
          </form>
          <p className="auth-link">No account? <Link to="/register">Register</Link></p>
        </div>
      </div>
    </main>
  );
}
