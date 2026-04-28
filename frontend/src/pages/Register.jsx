import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import axios from "axios";

const API = "http://127.0.0.1:8000";

export default function Register() {
  const navigate = useNavigate();
  const [form, setForm] = useState({ email: "", password: "", role: "provider" });
  const [error, setError] = useState("");

  async function handleSubmit(e) {
    e.preventDefault();
    setError("");
    try {
      await axios.post(`${API}/auth/register`, form);
      navigate("/login");
    } catch (err) {
      setError(err.response?.data?.detail || "Registration failed");
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
          <h2>Create Account</h2>
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
            <button type="submit" className="btn-primary">Create Account</button>
          </form>
          <p className="auth-link">Already have an account? <Link to="/login">Sign in</Link></p>
        </div>
      </div>
    </main>
  );
}
