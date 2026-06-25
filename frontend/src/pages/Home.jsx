import { Link } from 'react-router-dom';

function ShieldIcon({ size = 20, stroke = 'white' }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={stroke} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  );
}

// Requirements & restrictions surfaced from the real pipeline (see CLAUDE.md):
// consent gate, accepted repo URL forms, sandbox isolation, host prereqs,
// the severity slider, and per-account run scoping.
const REQUIREMENTS = [
  {
    title: 'Authorization & consent',
    accent: '#dc2626',
    body: 'Only submit repositories you own or are explicitly authorized to test. Every run is intentionally adversarial, so you must tick the consent box — the pipeline refuses to start without it.',
  },
  {
    title: 'Accepted repository inputs',
    accent: '#4f46e5',
    body: 'A plain repo URL, or a GitHub tree/blob link pointing at a subdirectory (e.g. github.com/vulhub/vulhub/tree/master/node/CVE-2017-14849), or the GitLab /-/tree/ form. Branch names containing a slash are not supported. Leave the URL blank to scan a pre-built image tag instead.',
  },
  {
    title: 'Isolation & safety',
    accent: '#059669',
    body: 'Your code is built into a throwaway Docker image and run in a sandbox with no network access, then destroyed when the assessment ends. VulBox never touches your production environment.',
  },
  {
    title: 'Host prerequisites (full mode)',
    accent: '#d97706',
    body: 'A real assessment needs Docker, Trivy, and Falco installed on the host. Dev mode replays bundled fixture outputs instead, so the dashboard and reports work without that toolchain.',
  },
  {
    title: 'Controlling report size',
    accent: '#2563eb',
    body: 'The “minimum severity to test” slider (default High) governs how many findings get a full exploitability verdict — lower it to test everything, raise it for a focused, smaller report.',
  },
  {
    title: 'Your runs are private',
    accent: '#7c3aed',
    body: 'You only see assessments you submitted; results are scoped to your account. Administrators can review every run for oversight.',
  },
];

const PHASES = ['Submitted', 'Building', 'Scanning', 'Testing', 'Reporting', 'Complete'];

export default function Home() {
  const authed = !!localStorage.getItem('token');

  return (
    <div style={{ minHeight: '100vh', background: 'var(--bg)' }}>
      {/* Top bar */}
      <header
        style={{
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          padding: '1rem 2rem', background: 'var(--sidebar-bg)', position: 'sticky', top: 0, zIndex: 10,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.625rem' }}>
          <div style={{ width: 34, height: 34, background: 'var(--accent)', borderRadius: 9, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <ShieldIcon />
          </div>
          <span style={{ color: 'white', fontWeight: 700, fontSize: '1.125rem', letterSpacing: '-0.01em' }}>VulBox</span>
        </div>
        <div style={{ display: 'flex', gap: '0.625rem' }}>
          {authed ? (
            <>
              <Link to="/guides" className="btn btn-ghost btn-sm" style={{ color: '#cbd5e1' }}>Guide</Link>
              <Link to="/dashboard" className="btn btn-primary btn-sm">Go to Dashboard</Link>
            </>
          ) : (
            <>
              <Link to="/login" className="btn btn-ghost btn-sm" style={{ color: '#cbd5e1' }}>Sign In</Link>
              <Link to="/register" className="btn btn-primary btn-sm">Create Account</Link>
            </>
          )}
        </div>
      </header>

      <main style={{ maxWidth: 980, margin: '0 auto', padding: '2.5rem 1.5rem 4rem' }}>
        {/* Hero */}
        <section
          className="card"
          style={{ background: 'linear-gradient(135deg, #0b1120, #1e3a5f)', border: 'none', padding: '3rem 2.5rem', marginBottom: '2.5rem' }}
        >
          <div className="badge badge-purple" style={{ marginBottom: '1rem' }}>Automated Application Security Assessment</div>
          <h1 style={{ color: 'white', fontSize: '2rem', lineHeight: 1.2, letterSpacing: '-0.02em', maxWidth: 640, marginBottom: '1rem' }}>
            See whether your vulnerabilities are present, exploitable, and detectable.
          </h1>
          <p style={{ color: '#94a3b8', fontSize: '1rem', lineHeight: 1.7, maxWidth: 620, marginBottom: '1.75rem' }}>
            VulBox builds your repository into a container, scans it with Trivy, runs Atomic Red Team attack
            simulations in an isolated sandbox under Falco monitoring, and produces a three-dimensional
            Security Matrix with prioritized remediations.
          </p>
          <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
            {authed ? (
              <Link to="/dashboard" className="btn btn-primary">Start an Assessment</Link>
            ) : (
              <Link to="/register" className="btn btn-primary">Get Started</Link>
            )}
            <Link to={authed ? '/guides' : '/login'} className="btn btn-secondary">
              {authed ? 'Read the Guide' : 'Sign In'}
            </Link>
          </div>
        </section>

        {/* Requirements & restrictions */}
        <div className="section-heading" style={{ marginBottom: '1rem' }}>Requirements &amp; Restrictions</div>
        <p className="text-sm text-muted mb-6" style={{ maxWidth: 640, lineHeight: 1.65 }}>
          Read these before submitting a run — they cover what you may scan, what the pipeline needs, and how
          your results are handled.
        </p>
        <div className="grid-2" style={{ alignItems: 'stretch', marginBottom: '2.5rem' }}>
          {REQUIREMENTS.map(r => (
            <div key={r.title} className="card card-pad" style={{ borderLeft: `3px solid ${r.accent}` }}>
              <div className="fw-600 mb-2" style={{ fontSize: '0.9375rem', color: r.accent }}>{r.title}</div>
              <p className="text-sm" style={{ color: 'var(--text-secondary)', lineHeight: 1.65 }}>{r.body}</p>
            </div>
          ))}
        </div>

        {/* Pipeline overview */}
        <div className="card card-pad" style={{ marginBottom: '2.5rem' }}>
          <div className="section-heading">How a Run Flows</div>
          <p className="text-sm text-muted mb-4" style={{ lineHeight: 1.65 }}>
            Each assessment moves through six phases. The Live Status screen streams these in real time.
          </p>
          <div style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
            {PHASES.map((p, i) => (
              <span key={p} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <span className="badge badge-neutral">{p}</span>
                {i < PHASES.length - 1 && <span style={{ color: 'var(--text-muted)' }}>→</span>}
              </span>
            ))}
          </div>
          <p className="text-xs text-muted mt-4">
            Want the full walkthrough — the Security Matrix, risk scoring, and FAQs? See the{' '}
            <Link to={authed ? '/guides' : '/login'} style={{ color: 'var(--accent)', fontWeight: 600 }}>detailed guide</Link>.
          </p>
        </div>

        {/* Closing CTA */}
        <div className="card card-pad" style={{ textAlign: 'center', padding: '2rem' }}>
          <div className="fw-700 mb-2" style={{ fontSize: '1.125rem' }}>Ready to assess a repository?</div>
          <p className="text-sm text-muted mb-4">
            {authed ? 'Head to your dashboard to submit a new run.' : 'Create a provider account to submit your first run.'}
          </p>
          <Link to={authed ? '/dashboard' : '/register'} className="btn btn-primary">
            {authed ? 'Open Dashboard' : 'Create Account'}
          </Link>
        </div>
      </main>
    </div>
  );
}
