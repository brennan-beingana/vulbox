import { Link } from 'react-router-dom';
import Layout from '../components/Layout';

const STEPS = [
  {
    num: '01',
    title: 'Register & Sign In',
    body: 'Create a provider account and sign in. VulBox uses JWT authentication — your token is valid for the current session and stored locally in your browser.',
  },
  {
    num: '02',
    title: 'Submit a Repository',
    body: 'From the Dashboard, enter a project name and optionally a GitHub repository URL, branch, and image tag. You must explicitly consent to adversarial testing before the pipeline can start.',
  },
  {
    num: '03',
    title: 'Monitor the Pipeline',
    body: 'The pipeline moves through six phases: Submitted → Building → Scanning → Testing → Reporting → Complete. The status page streams live WebSocket events so you can watch each phase in real time.',
  },
  {
    num: '04',
    title: 'Review the Security Report',
    body: 'Once complete, open the Security Report. It shows the three-dimensional Security Matrix, individual Trivy CVEs, Atomic Red Team test outcomes, and AI-generated remediation actions.',
  },
  {
    num: '05',
    title: 'Export & Share',
    body: 'Download the report as a PDF or CSV from the Report page. Use these exports to share findings with your team, file tickets, or track remediation progress.',
  },
];

const DIMS = [
  {
    label: 'Presence',
    color: '#4f46e5',
    bg: '#ede9fe',
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#4f46e5" strokeWidth="2" strokeLinecap="round">
        <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
      </svg>
    ),
    desc: 'Whether a vulnerability or weakness is actually present in the scanned image. Detected by Trivy static analysis on the built container.',
  },
  {
    label: 'Exploitability',
    color: '#dc2626',
    bg: '#fee2e2',
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#dc2626" strokeWidth="2" strokeLinecap="round">
        <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>
      </svg>
    ),
    desc: 'Whether the weakness can actually be triggered in the running application. Measured by Atomic Red Team technique execution — if the ART test causes impact, the finding is exploitable.',
  },
  {
    label: 'Detectability',
    color: '#059669',
    bg: '#d1fae5',
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#059669" strokeWidth="2" strokeLinecap="round">
        <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>
      </svg>
    ),
    desc: 'Whether an exploit attempt would be caught by your runtime defences. Falco monitors the container during each ART test and raises alerts — detection is confirmed when a Falco alert matches the test.',
  },
];

const RISK_ROWS = [
  { range: '40 – 75', color: '#dc2626', label: 'Critical', desc: 'Present, exploited, and undetected — immediate remediation required.' },
  { range: '25 – 39', color: '#ea580c', label: 'High',     desc: 'Exploited but partially detected or a severe static finding.' },
  { range: '15 – 24', color: '#d97706', label: 'Medium',   desc: 'Present and either exploitable or undetected, but not both.' },
  { range: '0  – 14', color: '#059669', label: 'Low',      desc: 'Present but not exploitable or fully detected by Falco.' },
];

// Accepted repository inputs (DockerManager._parse_repo_url). Kept in sync with
// the restrictions surfaced on the public Home page.
const REPO_FORMATS = [
  { label: 'Plain repository URL', example: 'https://github.com/org/repo' },
  { label: 'GitHub subdirectory (tree/blob)', example: 'https://github.com/vulhub/vulhub/tree/master/node/CVE-2017-14849' },
  { label: 'GitLab subdirectory (/-/tree/)', example: 'https://gitlab.com/group/repo/-/tree/main/service' },
  { label: 'No URL — scan a pre-built image', example: 'Leave blank and set the Image Tag field' },
];

// What the New-Run severity slider controls (min_severity → matrix attribution).
const SEVERITY_SLIDER = [
  { stop: 'Critical', color: '#dc2626', desc: 'Smallest report — only Critical CVEs get an exploitability row.' },
  { stop: 'High', color: '#ea580c', desc: 'Default — Critical & High findings are attributed.' },
  { stop: 'Medium', color: '#d97706', desc: 'Adds Medium findings to the matrix.' },
  { stop: 'Low', color: '#059669', desc: 'Largest report — every finding is tested, including unknown severity.' },
];

const FAQS = [
  {
    q: 'Does VulBox touch my production environment?',
    a: 'No. VulBox clones your repository and builds a fresh Docker image in an isolated sandbox. No network access is permitted during testing, and the container is destroyed after the assessment.',
  },
  {
    q: 'What are Atomic Red Team tests?',
    a: 'Atomic Red Team (ART) is an open-source library of small, focused attack simulations mapped to the MITRE ATT&CK framework. Each "atomic" test exercises one specific technique — for example, credential dumping or privilege escalation — in a controlled way.',
  },
  {
    q: 'What does Falco monitor?',
    a: 'Falco is a cloud-native runtime security tool. During testing it watches system calls made by the container and raises alerts when behaviour matches known attack patterns (file reads in sensitive paths, unexpected network calls, privilege changes, etc.).',
  },
  {
    q: 'How is the risk score calculated?',
    a: 'Base 10 for any present finding, +30 if the ART test succeeded (exploited), +10 if Falco did not raise an alert (undetected), plus a severity weight (Critical 20 / High 15 / Medium 10 / Low 5). The score is capped at 75.',
  },
  {
    q: 'Can I run VulBox against a private repository?',
    a: 'Yes — provide the repository URL and ensure the server has the appropriate SSH key or token configured as an environment variable before starting the assessment.',
  },
  {
    q: 'What is dev mode?',
    a: 'When VULBOX_DEV_MODE=true, all adapters read from fixture files in data/sample_outputs/ instead of running real Docker, Trivy, Falco, or ART processes. This is useful for UI development and testing without a full environment.',
  },
  {
    q: 'What export formats are available?',
    a: 'From the Report screen you can download the full assessment as JSON (machine-readable), CSV (the Security Matrix as a spreadsheet), or PDF (a formatted report for sharing). All three follow the same critical-to-low ordering as the on-screen report.',
  },
];

export default function Guides() {
  return (
    <Layout title="Guides" breadcrumb="VulBox">
      {/* Hero intro */}
      <div className="card mb-6" style={{ background: 'linear-gradient(135deg, #0b1120, #1e3a5f)', border: 'none', padding: '2rem 2.5rem' }}>
        <div className="fw-700" style={{ fontSize: '1.375rem', color: 'white', marginBottom: '0.5rem', letterSpacing: '-0.02em' }}>
          Getting Started with VulBox
        </div>
        <p style={{ color: '#94a3b8', fontSize: '0.9375rem', lineHeight: 1.7, maxWidth: 600, marginBottom: '1.5rem' }}>
          VulBox is an automated application security assessment pipeline. It builds your repository into a Docker
          container, scans it with Trivy, runs Atomic Red Team adversarial tests, and measures presence,
          exploitability, and detectability — producing a three-dimensional Security Matrix.
        </p>
        <Link to="/dashboard" className="btn btn-primary btn-sm">Launch an Assessment</Link>
      </div>

      <div className="grid-2" style={{ alignItems: 'start', marginBottom: '2rem' }}>
        {/* How it works */}
        <div className="card card-pad">
          <div className="section-heading">How It Works</div>
          {STEPS.map(s => (
            <div key={s.num} className="guide-step">
              <div className="guide-num" style={{ fontSize: '0.75rem' }}>{s.num}</div>
              <div className="guide-content">
                <h3>{s.title}</h3>
                <p>{s.body}</p>
              </div>
            </div>
          ))}
        </div>

        {/* Security Matrix */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div className="card card-pad">
            <div className="section-heading">The Security Matrix</div>
            <p className="text-sm text-muted mb-4" style={{ lineHeight: 1.65 }}>
              Every finding is assessed across three independent dimensions. The combination determines
              the risk score (0 – 75) and the priority of remediation.
            </p>
            {DIMS.map(d => (
              <div key={d.label} className="dim-card mb-3">
                <div className="dim-icon" style={{ background: d.bg }}>
                  {d.icon}
                </div>
                <div className="dim-title" style={{ color: d.color }}>{d.label}</div>
                <div className="dim-desc">{d.desc}</div>
              </div>
            ))}
          </div>

          {/* Risk Score legend */}
          <div className="card card-pad">
            <div className="section-heading">Risk Score Legend</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.625rem' }}>
              {RISK_ROWS.map(r => (
                <div key={r.label} className="flex items-center gap-3">
                  <span className="risk-chip" style={{ background: r.color, minWidth: 52 }}>{r.range}</span>
                  <div>
                    <div className="fw-600 text-sm" style={{ color: r.color }}>{r.label}</div>
                    <div className="text-xs text-muted">{r.desc}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Pipeline stages */}
      <div className="card card-pad mb-6">
        <div className="section-heading">Pipeline Stages</div>
        <div className="table-wrap" style={{ border: 'none', borderRadius: 0 }}>
          <table className="tbl">
            <thead>
              <tr>
                <th>Stage</th>
                <th>What Happens</th>
                <th>Tool</th>
              </tr>
            </thead>
            <tbody>
              {[
                ['SUBMITTED',  'Run record created, consent verified', 'API / Orchestrator'],
                ['BUILDING',   'Repository cloned and Docker image built', 'Docker'],
                ['SCANNING',   'Image scanned for known CVEs', 'Trivy'],
                ['TESTING',    'Controlled attack techniques executed in sandbox under Falco monitoring', 'ART + Falco'],
                ['REBUILDING', 'If a crash was detected, container is rebuilt for retry', 'Docker'],
                ['REPORTING',  'Security Matrix computed, remediations generated', 'LLM / Orchestrator'],
                ['COMPLETE',   'Full report available for download', '—'],
              ].map(([stage, what, tool]) => (
                <tr key={stage}>
                  <td><span className="badge badge-neutral">{stage}</span></td>
                  <td className="text-sm">{what}</td>
                  <td className="text-sm text-muted">{tool}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Requirements & restrictions (detailed — the Home page carries the summary) */}
      <div className="card card-pad mb-6">
        <div className="flex items-center justify-between mb-4">
          <div className="section-heading" style={{ margin: 0, border: 'none', padding: 0 }}>Requirements &amp; Restrictions</div>
          <Link to="/" className="btn btn-secondary btn-xs">Summary on Home</Link>
        </div>
        <div className="grid-2" style={{ alignItems: 'start' }}>
          <div>
            <div className="fw-600 mb-2" style={{ fontSize: '0.9375rem', color: '#dc2626' }}>Authorization &amp; consent</div>
            <p className="text-sm" style={{ color: 'var(--text-secondary)', lineHeight: 1.65 }}>
              Only submit repositories you own or are explicitly authorized to test. Every run is
              intentionally adversarial, so the <strong>consent checkbox is mandatory</strong> — the API
              rejects a run (HTTP&nbsp;400) without it.
            </p>
          </div>
          <div>
            <div className="fw-600 mb-2" style={{ fontSize: '0.9375rem', color: '#d97706' }}>Host prerequisites</div>
            <p className="text-sm" style={{ color: 'var(--text-secondary)', lineHeight: 1.65 }}>
              A real (full-mode) assessment needs <strong>Docker, Trivy, and Falco</strong> installed on the
              host. Dev mode replays bundled fixtures instead, so the UI and reports work without that
              toolchain.
            </p>
          </div>
          <div>
            <div className="fw-600 mb-2" style={{ fontSize: '0.9375rem', color: '#059669' }}>Isolation</div>
            <p className="text-sm" style={{ color: 'var(--text-secondary)', lineHeight: 1.65 }}>
              Your code is built into a throwaway image and run in a sandbox with <strong>no network
              access</strong>, then destroyed when the assessment ends. Production is never touched.
            </p>
          </div>
          <div>
            <div className="fw-600 mb-2" style={{ fontSize: '0.9375rem', color: '#7c3aed' }}>Private results</div>
            <p className="text-sm" style={{ color: 'var(--text-secondary)', lineHeight: 1.65 }}>
              You only see assessments you submitted — results are scoped to your account. Administrator
              accounts can review every run for oversight.
            </p>
          </div>
        </div>
      </div>

      <div className="grid-2" style={{ alignItems: 'start', marginBottom: '1.5rem' }}>
        {/* Accepted repository inputs */}
        <div className="card card-pad">
          <div className="section-heading">Accepted Repository Inputs</div>
          <p className="text-sm text-muted mb-4" style={{ lineHeight: 1.65 }}>
            The repository field accepts several forms. Branch names containing a slash are not supported.
          </p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.875rem' }}>
            {REPO_FORMATS.map(f => (
              <div key={f.label}>
                <div className="fw-600 text-sm mb-1">{f.label}</div>
                <code
                  style={{
                    display: 'block', fontSize: '0.8125rem', color: 'var(--text-secondary)',
                    background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 6,
                    padding: '0.5rem 0.625rem', wordBreak: 'break-all',
                  }}
                >
                  {f.example}
                </code>
              </div>
            ))}
          </div>
        </div>

        {/* Controlling report size */}
        <div className="card card-pad">
          <div className="section-heading">Controlling Report Size</div>
          <p className="text-sm text-muted mb-4" style={{ lineHeight: 1.65 }}>
            The <strong>Minimum Severity to Test</strong> slider on the New Run form governs which findings
            get a full exploitability row in the Security Matrix — the main lever on report size. The
            technique still runs regardless; this only changes how many CVEs are attributed.
          </p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.625rem' }}>
            {SEVERITY_SLIDER.map(s => (
              <div key={s.stop} className="flex items-center gap-3">
                <span className="badge" style={{ background: s.color, color: '#fff', minWidth: 64, justifyContent: 'center' }}>{s.stop}</span>
                <div className="text-xs text-muted">{s.desc}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Running modes */}
      <div className="card card-pad mb-6">
        <div className="section-heading">Running Modes</div>
        <div className="table-wrap" style={{ border: 'none', borderRadius: 0 }}>
          <table className="tbl">
            <thead>
              <tr><th>Mode</th><th>What runs</th><th>When to use</th></tr>
            </thead>
            <tbody>
              <tr>
                <td><span className="badge badge-info">Dev</span></td>
                <td className="text-sm">Adapters replay fixture outputs from <code>data/sample_outputs/</code>; no Docker, Trivy, Falco, or ART processes are launched.</td>
                <td className="text-sm text-muted">UI work, demos, and trying VulBox without the toolchain.</td>
              </tr>
              <tr>
                <td><span className="badge badge-success">Production</span></td>
                <td className="text-sm">Real Docker build, Trivy scan, Falco monitoring, and Atomic Red Team execution against the target.</td>
                <td className="text-sm text-muted">Actual assessments on a host with Docker + Trivy + Falco.</td>
              </tr>
            </tbody>
          </table>
        </div>
        <p className="text-xs text-muted mt-4">
          The live mode is shown on the API <code>/health</code> endpoint and echoed in the startup logs.
        </p>
      </div>

      {/* FAQ */}
      <div className="card card-pad">
        <div className="section-heading">Frequently Asked Questions</div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          {FAQS.map(f => (
            <div key={f.q}>
              <div className="fw-600 mb-2" style={{ fontSize: '0.9375rem' }}>{f.q}</div>
              <div className="text-sm" style={{ color: 'var(--text-secondary)', lineHeight: 1.7 }}>{f.a}</div>
              <div className="divider" style={{ margin: '1.25rem 0 0' }} />
            </div>
          ))}
        </div>
      </div>
    </Layout>
  );
}
