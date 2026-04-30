import { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import api from '../api';
import Layout from '../components/Layout';

function PlusIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
      <line x1="12" y1="5" x2="12" y2="19" />
      <line x1="5" y1="12" x2="19" y2="12" />
    </svg>
  );
}

function statusBadgeClass(status) {
  const map = {
    COMPLETE: 'badge-success',
    FAILED: 'badge-danger',
    BUILDING: 'badge-warning',
    SCANNING: 'badge-warning',
    TESTING: 'badge-warning',
    REBUILDING: 'badge-warning',
    REPORTING: 'badge-purple',
    SUBMITTED: 'badge-neutral',
  };
  return map[status] || 'badge-neutral';
}

export default function NewRun() {
  const navigate = useNavigate();
  const [form, setForm] = useState({
    project_name: '',
    repo_url: '',
    branch: 'main',
    image_tag: 'latest',
    consent_granted: false,
  });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [recentRuns, setRecentRuns] = useState([]);

  useEffect(() => {
    api.get('/runs').then(r => setRecentRuns(r.data.slice(0, 5))).catch(() => {});
  }, []);

  async function handleSubmit(e) {
    e.preventDefault();
    if (!form.consent_granted) {
      setError('You must consent to adversarial testing before proceeding.');
      return;
    }
    setError('');
    setLoading(true);
    try {
      const { data } = await api.post('/runs', form);
      navigate(`/runs/${data.id}/status`);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to start assessment.');
      setLoading(false);
    }
  }

  const complete = recentRuns.filter(r => r.status === 'COMPLETE').length;
  const running  = recentRuns.filter(r => !['COMPLETE', 'FAILED'].includes(r.status)).length;
  const failed   = recentRuns.filter(r => r.status === 'FAILED').length;

  return (
    <Layout title="Dashboard" breadcrumb="VulBox">
      {/* Quick stats */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-label">Total Runs</div>
          <div className="stat-value">{recentRuns.length}</div>
          <div className="stat-trend">All time</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Completed</div>
          <div className="stat-value" style={{ color: 'var(--success)' }}>{complete}</div>
          <div className="stat-trend">Assessments finished</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">In Progress</div>
          <div className="stat-value" style={{ color: 'var(--warning)' }}>{running}</div>
          <div className="stat-trend">Active pipelines</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Failed</div>
          <div className="stat-value" style={{ color: 'var(--danger)' }}>{failed}</div>
          <div className="stat-trend">Need attention</div>
        </div>
      </div>

      <div className="grid-2" style={{ alignItems: 'start' }}>
        {/* New Assessment Form */}
        <div className="card card-pad">
          <div className="flex items-center gap-3 mb-6">
            <div style={{ width: 36, height: 36, background: 'var(--accent-light)', borderRadius: 9, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--accent)' }}>
              <PlusIcon />
            </div>
            <div>
              <div className="card-title">New Assessment</div>
              <div className="card-desc">Submit a repository to the security pipeline</div>
            </div>
          </div>

          {error && <div className="alert alert-error">{error}</div>}

          <form onSubmit={handleSubmit}>
            <div className="form-group">
              <label className="form-label" htmlFor="project_name">Project Name *</label>
              <input
                id="project_name"
                className="form-input"
                placeholder="my-service"
                value={form.project_name}
                onChange={e => setForm({ ...form, project_name: e.target.value })}
                required
              />
            </div>

            <div className="form-group">
              <label className="form-label" htmlFor="repo_url">GitHub Repository URL</label>
              <input
                id="repo_url"
                className="form-input"
                type="url"
                placeholder="https://github.com/org/repo"
                value={form.repo_url}
                onChange={e => setForm({ ...form, repo_url: e.target.value })}
              />
              <span className="form-hint">Leave blank to use a pre-built image</span>
            </div>

            <div className="form-row">
              <div className="form-group">
                <label className="form-label" htmlFor="branch">Branch</label>
                <input
                  id="branch"
                  className="form-input"
                  value={form.branch}
                  onChange={e => setForm({ ...form, branch: e.target.value })}
                />
              </div>
              <div className="form-group">
                <label className="form-label" htmlFor="image_tag">Image Tag</label>
                <input
                  id="image_tag"
                  className="form-input"
                  value={form.image_tag}
                  onChange={e => setForm({ ...form, image_tag: e.target.value })}
                />
              </div>
            </div>

            <div className="consent-block mb-4">
              <div className="consent-title">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                Consent Required
              </div>
              <p>
                VulBox will build your repository into a Docker container and execute controlled
                Atomic Red Team attack simulations against it in an isolated sandbox under Falco
                monitoring. <strong>No network access</strong> is permitted during testing.
                This process is intentionally adversarial.
              </p>
              <label className="checkbox-row">
                <input
                  type="checkbox"
                  checked={form.consent_granted}
                  onChange={e => setForm({ ...form, consent_granted: e.target.checked })}
                />
                <span>I understand and consent to adversarial security testing</span>
              </label>
            </div>

            <button
              type="submit"
              className="btn btn-primary btn-full"
              disabled={loading}
            >
              {loading ? 'Starting pipeline…' : 'Start Assessment'}
            </button>
          </form>
        </div>

        {/* Recent Runs */}
        <div className="card card-pad">
          <div className="flex items-center justify-between mb-6">
            <div>
              <div className="card-title">Recent Runs</div>
              <div className="card-desc">Last 5 assessments</div>
            </div>
            <Link to="/reports" className="btn btn-secondary btn-sm">View all</Link>
          </div>

          {recentRuns.length === 0 ? (
            <div className="empty-state" style={{ padding: '2rem 1rem' }}>
              <div className="empty-state-icon">📋</div>
              <h3>No runs yet</h3>
              <p>Submit your first repository to get started</p>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              {recentRuns.map(run => (
                <div key={run.id} style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', padding: '0.75rem', borderRadius: 10, background: 'var(--bg)', border: '1px solid var(--border)' }}>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div className="fw-600 text-sm" style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {run.project_name}
                    </div>
                    <div className="text-xs text-muted mt-1">Run #{run.id}</div>
                  </div>
                  <span className={`badge ${statusBadgeClass(run.status)}`}>{run.status}</span>
                  {run.status === 'COMPLETE'
                    ? <Link to={`/runs/${run.id}/report`} className="btn btn-secondary btn-xs">Report</Link>
                    : <Link to={`/runs/${run.id}/status`} className="btn btn-secondary btn-xs">Status</Link>
                  }
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </Layout>
  );
}
