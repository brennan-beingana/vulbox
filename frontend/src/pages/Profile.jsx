import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import api from '../api';
import Layout from '../components/Layout';

function formatDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleDateString(undefined, {
    month: 'long', day: 'numeric', year: 'numeric',
  });
}

export default function Profile() {
  const [user, setUser] = useState(null);
  const [runs, setRuns] = useState([]);
  const [error, setError] = useState('');

  useEffect(() => {
    api.get('/auth/me').then(r => setUser(r.data)).catch(() => setError('Failed to load profile.'));
    api.get('/runs').then(r => setRuns(r.data)).catch(() => {});
  }, []);

  const initial = user?.email?.[0]?.toUpperCase() || '?';
  const complete = runs.filter(r => r.status === 'COMPLETE').length;
  const failed   = runs.filter(r => r.status === 'FAILED').length;

  return (
    <Layout title="Profile" breadcrumb="Account">
      {error && <div className="alert alert-error">{error}</div>}

      <div className="profile-grid">
        {/* Left: identity card */}
        <div>
          <div className="card card-pad" style={{ textAlign: 'center', marginBottom: '1rem' }}>
            <div className="avatar-lg">{initial}</div>
            <div className="fw-700" style={{ fontSize: '1.0625rem' }}>{user?.email || '…'}</div>
            <div className="mt-2">
              <span className={`badge ${user?.role === 'admin' ? 'badge-purple' : 'badge-info'}`}>
                {user?.role || '…'}
              </span>
            </div>
            <div className="divider" />
            <div className="text-muted text-sm">User ID: {user?.id || '—'}</div>
          </div>

          <div className="card card-pad">
            <div className="card-title mb-4">Quick Actions</div>
            <div className="flex flex-col gap-2">
              <Link to="/" className="btn btn-primary btn-sm btn-full">New Assessment</Link>
              <Link to="/reports" className="btn btn-secondary btn-sm btn-full">View Reports</Link>
              <Link to="/guides" className="btn btn-secondary btn-sm btn-full">Read Guides</Link>
            </div>
          </div>
        </div>

        {/* Right: details + stats */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          {/* Account info */}
          <div className="card card-pad">
            <div className="card-title mb-4">Account Details</div>
            <div className="info-row">
              <span className="info-label">Email</span>
              <span className="info-value">{user?.email || '—'}</span>
            </div>
            <div className="info-row">
              <span className="info-label">Role</span>
              <span className="info-value" style={{ textTransform: 'capitalize' }}>{user?.role || '—'}</span>
            </div>
            <div className="info-row">
              <span className="info-label">User ID</span>
              <span className="info-value">{user?.id || '—'}</span>
            </div>
            <div className="info-row">
              <span className="info-label">Authentication</span>
              <span className="info-value">JWT / Bearer token</span>
            </div>
          </div>

          {/* Assessment stats */}
          <div className="card card-pad">
            <div className="card-title mb-4">Assessment Statistics</div>
            <div className="stats-grid" style={{ marginBottom: 0 }}>
              <div className="stat-card" style={{ border: 'none', padding: '0.875rem', background: 'var(--bg)' }}>
                <div className="stat-label">Total Runs</div>
                <div className="stat-value">{runs.length}</div>
              </div>
              <div className="stat-card" style={{ border: 'none', padding: '0.875rem', background: 'var(--bg)' }}>
                <div className="stat-label">Completed</div>
                <div className="stat-value" style={{ color: 'var(--success)' }}>{complete}</div>
              </div>
              <div className="stat-card" style={{ border: 'none', padding: '0.875rem', background: 'var(--bg)' }}>
                <div className="stat-label">Failed</div>
                <div className="stat-value" style={{ color: 'var(--danger)' }}>{failed}</div>
              </div>
              <div className="stat-card" style={{ border: 'none', padding: '0.875rem', background: 'var(--bg)' }}>
                <div className="stat-label">Success Rate</div>
                <div className="stat-value">
                  {runs.length > 0 ? Math.round((complete / runs.length) * 100) : '—'}
                  {runs.length > 0 && <span style={{ fontSize: '1rem', fontWeight: 400, color: 'var(--text-muted)' }}>%</span>}
                </div>
              </div>
            </div>
          </div>

          {/* Security notice */}
          <div className="card card-pad" style={{ background: 'var(--info-bg)', border: '1px solid #93c5fd' }}>
            <div className="flex gap-3 items-start">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#2563eb" strokeWidth="2" strokeLinecap="round" style={{ flexShrink: 0, marginTop: 2 }}>
                <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
              </svg>
              <div>
                <div className="fw-600 mb-1" style={{ color: '#1e40af' }}>Security Notice</div>
                <div className="text-sm" style={{ color: '#1e40af', lineHeight: 1.6 }}>
                  Your JWT token is stored in browser localStorage. Clear it on shared or public devices.
                  All assessment tests run in isolated containers with no outbound network access.
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </Layout>
  );
}
