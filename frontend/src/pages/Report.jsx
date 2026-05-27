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

const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 };
const SEVERITY_COLOR = { critical: '#dc2626', high: '#ea580c', medium: '#d97706', low: '#059669' };

function SeverityCell({ severity }) {
  if (!severity) return <span className="text-muted">—</span>;
  return (
    <span
      className="badge"
      style={{ color: '#fff', background: SEVERITY_COLOR[severity] || '#6b7280', textTransform: 'capitalize' }}
    >
      {severity}
    </span>
  );
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
  // Shared filter for the matrix table + remediation cards (client-side).
  const [minSeverity, setMinSeverity] = useState('all');
  const [minRisk, setMinRisk] = useState(0);

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

  const maxRisk = report.security_matrix.length > 0
    ? Math.max(...report.security_matrix.map(e => e.risk_score))
    : null;

  const sevThreshold = minSeverity === 'all' ? 0 : SEVERITY_RANK[minSeverity];
  const passesFilter = (severity, risk) =>
    (risk ?? 0) >= minRisk &&
    (SEVERITY_RANK[severity] ?? 0) >= sevThreshold;

  const filteredMatrix = report.security_matrix.filter(e => passesFilter(e.severity, e.risk_score));
  const filteredRemediations = report.remediations.filter(r => passesFilter(r.severity, r.risk_score));
  const filtersActive = minSeverity !== 'all' || minRisk > 0;

  const filterBar = (
    <div className="report-toolbar" style={{ gap: '1.25rem', flexWrap: 'wrap' }}>
      <div className="flex items-center gap-3" style={{ flexWrap: 'wrap' }}>
        <span className="form-label" style={{ margin: 0 }}>Min severity</span>
        <select
          className="form-input"
          style={{ width: 'auto', textTransform: 'capitalize' }}
          value={minSeverity}
          onChange={e => setMinSeverity(e.target.value)}
        >
          <option value="all">All</option>
          <option value="critical">Critical</option>
          <option value="high">High &amp; above</option>
          <option value="medium">Medium &amp; above</option>
          <option value="low">Low &amp; above</option>
        </select>
      </div>
      <div className="flex items-center gap-3">
        <span className="form-label" style={{ margin: 0 }}>Min risk score</span>
        <input
          type="range"
          min="0"
          max="75"
          step="5"
          value={minRisk}
          onChange={e => setMinRisk(Number(e.target.value))}
          style={{ accentColor: riskColor(minRisk || 0) }}
        />
        <span className="risk-chip" style={{ background: riskColor(minRisk || 0) }}>{minRisk}/75</span>
      </div>
      {filtersActive && (
        <button
          className="btn btn-secondary btn-sm"
          onClick={() => { setMinSeverity('all'); setMinRisk(0); }}
        >
          Clear filters
        </button>
      )}
    </div>
  );

  return (
    <Layout title={`Report — ${report.project_name}`} breadcrumb="Reports">
      {/* Toolbar: metadata chips + export actions */}
      <div className="report-toolbar">
        <div className="report-meta">
          <span className="meta-chip"><span className="meta-key">Run</span> #{report.run_id}</span>
          <span className="meta-chip"><span className="meta-key">Image</span> <code>{report.image_tag}</code></span>
          <span className="meta-chip">
            <span className="meta-key">Status</span>
            <span className={`badge ${report.status === 'COMPLETE' ? 'badge-success' : 'badge-neutral'}`}>{report.status}</span>
          </span>
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
          <div className="stat-value" style={{ color: maxRisk !== null ? riskColor(maxRisk) : 'var(--text)' }}>
            {maxRisk !== null ? maxRisk : '—'}
            {maxRisk !== null && <span className="text-muted" style={{ fontSize: '1rem', fontWeight: 500 }}>/75</span>}
          </div>
          <div className="stat-trend">Highest entry score</div>
        </div>
      </div>

      {/* Executive Summary */}
      {report.executive_summary && (
        <div className="page-section">
          <div className="rep-section-head">
            <h2>Executive Summary</h2>
            <span className={`badge ${report.executive_summary.generated_by === 'llm' ? 'badge-info' : 'badge-neutral'}`}>
              {report.executive_summary.generated_by === 'llm' ? '✨ AI-generated' : 'rule-based'}
            </span>
          </div>
          <div className="exec-summary">
            <div className="exec-top">
              <div className="exec-headline">{report.executive_summary.headline}</div>
              <span className={`badge ${confidenceBadge(report.executive_summary.confidence)}`}>
                {report.executive_summary.confidence}
              </span>
            </div>
            <p className="exec-posture">{report.executive_summary.overall_posture}</p>
            {report.executive_summary.top_priorities.length > 0 && (
              <>
                <div className="exec-priorities-label">Top priorities</div>
                <ol className="exec-priorities">
                  {report.executive_summary.top_priorities.map((p, i) => (
                    <li key={i}><span className="pri-num">{i + 1}</span><span>{p}</span></li>
                  ))}
                </ol>
              </>
            )}
          </div>
        </div>
      )}

      {/* Filter bar (applies to matrix + remediations) */}
      {(report.security_matrix.length > 0 || report.remediations.length > 0) && filterBar}

      {/* Security Matrix */}
      <div className="page-section">
        <div className="rep-section-head">
          <h2>Security Matrix</h2>
          {report.security_matrix.length > 0 && (
            <span className="rep-count">
              {filtersActive
                ? `${filteredMatrix.length} / ${report.security_matrix.length}`
                : report.security_matrix.length}
            </span>
          )}
        </div>
        <div className="table-wrap">
          {report.security_matrix.length === 0 ? (
            <div className="empty-state">
              <div className="empty-state-icon">🔍</div>
              <h3>No matrix entries</h3>
              <p>The assessment may still be running or no findings were correlated.</p>
            </div>
          ) : filteredMatrix.length === 0 ? (
            <div className="empty-state">
              <div className="empty-state-icon">🧹</div>
              <h3>No entries match the filter</h3>
              <p>Lower the minimum severity or risk score to see more.</p>
            </div>
          ) : (
            <table className="matrix-table">
              <thead>
                <tr>
                  <th>MITRE Tactic</th>
                  <th>Severity</th>
                  <th>Present</th>
                  <th>Exploitable</th>
                  <th>Detectable</th>
                  <th>Risk Score</th>
                </tr>
              </thead>
              <tbody>
                {filteredMatrix.map(e => (
                  <tr key={e.entry_id}>
                    <td>
                      <code className="id-tag">{e.mitre_tactic_id || '—'}</code>
                    </td>
                    <td>
                      <SeverityCell severity={e.severity} />
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
                        {e.risk_score}/75
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
          <div className="rep-section-head">
            <h2>Remediation Actions</h2>
            <span className="rep-count">
              {filtersActive
                ? `${filteredRemediations.length} / ${report.remediations.length}`
                : report.remediations.length}
            </span>
          </div>
          {filteredRemediations.length === 0 ? (
            <div className="empty-state">
              <div className="empty-state-icon">🧹</div>
              <h3>No remediations match the filter</h3>
              <p>Lower the minimum severity or risk score to see more.</p>
            </div>
          ) : filteredRemediations.map(r => (
            <div key={r.id} className={`rem-card acc-${r.confidence}`}>
              <div className="rem-header">
                <div className="rem-summary">{r.summary}</div>
                <span className="rem-badges">
                  <span className={`badge ${r.generated_by === 'llm' ? 'badge-info' : 'badge-neutral'}`}>
                    {r.generated_by === 'llm' ? '✨ AI' : 'rule'}
                  </span>
                  <span className={`badge ${confidenceBadge(r.confidence)}`}>{r.confidence}</span>
                </span>
              </div>
              <div className="rem-field">
                <span className="rem-field-label">Priority action</span>
                <span className="rem-field-val">{r.priority_action}</span>
              </div>
              <div className="rem-field">
                <span className="rem-field-label">Why it matters</span>
                <span className="rem-field-val">{r.why_it_matters}</span>
              </div>
              {r.example_fix && (
                <div className="rem-field">
                  <span className="rem-field-label">Example fix</span>
                  <div className="code-block">{r.example_fix}</div>
                </div>
              )}
              {r.references && r.references.trim() && (
                <div className="rem-field">
                  <span className="rem-field-label">References</span>
                  <div className="rem-refs">
                    {r.references.split('\n').filter(Boolean).map((ref, i) => (
                      /^https?:\/\//.test(ref)
                        ? <a key={i} className="ref-chip" href={ref} target="_blank" rel="noreferrer">{ref}</a>
                        : <span key={i} className="ref-chip">{ref}</span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </Layout>
  );
}
