import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import api from '../api';
import Layout from '../components/Layout';

const API_BASE = 'http://46.101.193.155:8000';

function riskColor(score) {
  if (score >= 40) return '#dc2626';
  if (score >= 25) return '#ea580c';
  if (score >= 15) return '#d97706';
  return '#059669';
}

function confidenceBadge(c) {
  const map = { critical: 'badge-danger', high: 'badge-warning', medium: 'badge-info', low: 'badge-success' };
  return map[c] || 'badge-neutral';
}

function BoolCell({ value, trueLabel = '✓ Yes', falseLabel = '✗ No', trueColor = 'var(--danger)', falseColor = 'var(--success)' }) {
  return (
    <span style={{ fontWeight: 700, color: value ? trueColor : falseColor }}>
      {value ? trueLabel : falseLabel}
    </span>
  );
}

export default function Report() {
  const { runId } = useParams();
  const [report, setReport] = useState(null);
  const [error, setError] = useState('');

  useEffect(() => {
    api.get(`/reports/${runId}`)
      .then(r => setReport(r.data))
      .catch(err => setError(err.response?.data?.detail || 'Failed to load report'));
  }, [runId]);

  function exportFile(format) {
    const token = localStorage.getItem('token');
    window.open(`${API_BASE}/reports/${runId}/export?format=${format}&token=${token}`, '_blank');
  }

  if (error) {
    return (
      <Layout title="Security Report" breadcrumb="Reports">
        <div className="alert alert-error">{error}</div>
        <Link to="/reports" className="btn btn-secondary btn-sm">Back to Reports</Link>
      </Layout>
    );
  }

  if (!report) {
    return (
      <Layout title="Security Report" breadcrumb="Reports">
        <div className="card card-pad" style={{ color: 'var(--text-muted)', textAlign: 'center', padding: '3rem' }}>
          Loading report…
        </div>
      </Layout>
    );
  }

  return (
    <Layout title={`Report — ${report.project_name}`} breadcrumb="Reports">
      {/* Header row */}
      <div className="flex items-center justify-between mb-6 flex-wrap gap-3">
        <div>
          <div className="text-muted text-sm">
            Run #{report.run_id} · {report.image_tag} · {report.status}
          </div>
        </div>
        <div className="flex gap-3">
          <button onClick={() => exportFile('csv')} className="btn btn-secondary btn-sm">
            Export CSV
          </button>
          <button onClick={() => exportFile('pdf')} className="btn btn-primary btn-sm">
            Export PDF
          </button>
        </div>
      </div>

      {/* Summary stats */}
      <div className="stats-grid mb-6">
        <div className="stat-card">
          <div className="stat-label">Trivy Findings</div>
          <div className="stat-value">{report.trivy_findings_count}</div>
          <div className="stat-trend">Static analysis CVEs</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">ART Tests Run</div>
          <div className="stat-value">{report.art_tests_count}</div>
          <div className="stat-trend">Atomic Red Team techniques</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Remediations</div>
          <div className="stat-value">{report.remediations_count}</div>
          <div className="stat-trend">Actionable fixes generated</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Max Risk Score</div>
          <div className="stat-value" style={{ color: riskColor(Math.max(0, ...report.security_matrix.map(e => e.risk_score))) }}>
            {report.security_matrix.length > 0
              ? Math.max(...report.security_matrix.map(e => e.risk_score))
              : '—'
            }
            {report.security_matrix.length > 0 && <span style={{ fontSize: '1rem', fontWeight: 400, color: 'var(--text-muted)' }}>/50</span>}
          </div>
          <div className="stat-trend">Highest entry score</div>
        </div>
      </div>

      {/* Security Matrix */}
      <div className="page-section">
        <div className="section-heading">Security Matrix</div>
        <div className="table-wrap">
          {report.security_matrix.length === 0 ? (
            <div className="empty-state">
              <div className="empty-state-icon">🔍</div>
              <h3>No matrix entries</h3>
              <p>The assessment may still be running or no findings were correlated.</p>
            </div>
          ) : (
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
                    <td>
                      <code style={{ fontSize: '0.8125rem', background: 'var(--bg)', padding: '0.125rem 0.375rem', borderRadius: 5 }}>
                        {e.mitre_tactic_id || '—'}
                      </code>
                    </td>
                    <td>
                      <BoolCell
                        value={e.is_present}
                        trueLabel="✓ Yes"
                        falseLabel="✗ No"
                        trueColor="var(--text)"
                        falseColor="var(--text-muted)"
                      />
                    </td>
                    <td>
                      <BoolCell value={e.is_exploitable} />
                    </td>
                    <td>
                      <BoolCell
                        value={e.is_detectable}
                        trueColor="var(--success)"
                        falseColor="var(--danger)"
                      />
                    </td>
                    <td>
                      <span
                        className="risk-chip"
                        style={{ background: riskColor(e.risk_score) }}
                      >
                        {e.risk_score}/50
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Remediations */}
      {report.remediations.length > 0 && (
        <div className="page-section">
          <div className="section-heading">Remediation Actions</div>
          {report.remediations.map(r => (
            <div key={r.id} className="remediation-card">
              <div className="rem-header">
                <div className="rem-summary">{r.summary}</div>
                <span className={`badge ${confidenceBadge(r.confidence)}`}>{r.confidence}</span>
              </div>
              <div className="rem-body">
                <p><strong>Priority action:</strong> {r.priority_action}</p>
                <p><strong>Why it matters:</strong> {r.why_it_matters}</p>
                {r.example_fix && (
                  <div className="code-block">{r.example_fix}</div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </Layout>
  );
}
