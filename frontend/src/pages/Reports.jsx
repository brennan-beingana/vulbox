import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import api from '../api';
import Layout from '../components/Layout';

function statusBadge(status) {
  const map = {
    COMPLETE:   'badge-success',
    FAILED:     'badge-danger',
    BUILDING:   'badge-warning',
    SCANNING:   'badge-warning',
    TESTING:    'badge-warning',
    REBUILDING: 'badge-warning',
    REPORTING:  'badge-purple',
    SUBMITTED:  'badge-neutral',
  };
  return map[status] || 'badge-neutral';
}

function formatDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleString(undefined, {
    month: 'short', day: 'numeric', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

export default function Reports() {
  const [runs, setRuns] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [filter, setFilter] = useState('ALL');

  useEffect(() => {
    api.get('/runs')
      .then(r => setRuns(r.data))
      .catch(() => setError('Failed to load assessment history.'))
      .finally(() => setLoading(false));
  }, []);

  const statuses = ['ALL', 'COMPLETE', 'FAILED', 'BUILDING', 'SCANNING', 'TESTING', 'SUBMITTED'];
  const filtered = filter === 'ALL' ? runs : runs.filter(r => r.status === filter);

  const total    = runs.length;
  const complete = runs.filter(r => r.status === 'COMPLETE').length;
  const failed   = runs.filter(r => r.status === 'FAILED').length;
  const running  = runs.filter(r => !['COMPLETE', 'FAILED'].includes(r.status)).length;

  return (
    <Layout title="Reports" breadcrumb="VulBox">
      {/* Stats */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-label">Total Assessments</div>
          <div className="stat-value">{total}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Completed</div>
          <div className="stat-value" style={{ color: 'var(--success)' }}>{complete}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">In Progress</div>
          <div className="stat-value" style={{ color: 'var(--warning)' }}>{running}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Failed</div>
          <div className="stat-value" style={{ color: 'var(--danger)' }}>{failed}</div>
        </div>
      </div>

      {/* Table */}
      <div className="card">
        <div className="card-header">
          <div>
            <div className="card-title">Assessment History</div>
            <div className="card-desc">{filtered.length} {filter === 'ALL' ? 'total' : filter.toLowerCase()} runs</div>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            {statuses.map(s => (
              <button
                key={s}
                onClick={() => setFilter(s)}
                className={`btn btn-sm ${filter === s ? 'btn-primary' : 'btn-secondary'}`}
                style={{ fontWeight: filter === s ? 700 : 500 }}
              >
                {s}
              </button>
            ))}
          </div>
        </div>

        {error && <div className="alert alert-error" style={{ margin: '1rem 1.5rem' }}>{error}</div>}

        {loading ? (
          <div style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-muted)' }}>
            Loading assessments…
          </div>
        ) : filtered.length === 0 ? (
          <div className="empty-state">
            <div className="empty-state-icon">📋</div>
            <h3>No assessments found</h3>
            <p>
              {filter === 'ALL'
                ? 'Submit your first repository from the Dashboard.'
                : `No runs with status "${filter}".`}
            </p>
            {filter === 'ALL' && (
              <Link to="/" className="btn btn-primary btn-sm mt-4">New Assessment</Link>
            )}
          </div>
        ) : (
          <div className="table-wrap" style={{ border: 'none', borderRadius: 0 }}>
            <table className="tbl">
              <thead>
                <tr>
                  <th>#</th>
                  <th>Project</th>
                  <th>Branch</th>
                  <th>Image Tag</th>
                  <th>Status</th>
                  <th>Started</th>
                  <th style={{ textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map(run => (
                  <tr key={run.id}>
                    <td className="text-muted text-sm fw-600">#{run.id}</td>
                    <td>
                      <div className="fw-600">{run.project_name}</div>
                      {run.repo_url && (
                        <div className="text-xs text-muted mt-1" style={{ maxWidth: 240, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {run.repo_url}
                        </div>
                      )}
                    </td>
                    <td className="text-sm">{run.branch || 'main'}</td>
                    <td className="text-sm">{run.image_tag || 'latest'}</td>
                    <td>
                      <span className={`badge ${statusBadge(run.status)}`}>{run.status}</span>
                    </td>
                    <td className="text-sm text-muted">{formatDate(run.created_at)}</td>
                    <td style={{ textAlign: 'right' }}>
                      <div className="flex gap-2 justify-end">
                        {run.status === 'COMPLETE' && (
                          <Link to={`/runs/${run.id}/report`} className="btn btn-primary btn-xs">
                            Report
                          </Link>
                        )}
                        <Link to={`/runs/${run.id}/status`} className="btn btn-secondary btn-xs">
                          Status
                        </Link>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </Layout>
  );
}
