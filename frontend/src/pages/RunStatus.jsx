import { useEffect, useRef, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { WS_BASE } from '../api';
import Layout from '../components/Layout';

const PHASES = ['SUBMITTED', 'BUILDING', 'SCANNING', 'TESTING', 'REPORTING', 'COMPLETE'];

const PHASE_LABELS = {
  SUBMITTED:  'Submitted',
  BUILDING:   'Building',
  SCANNING:   'Scanning',
  TESTING:    'Testing',
  REBUILDING: 'Rebuilding',
  REPORTING:  'Reporting',
  COMPLETE:   'Complete',
  FAILED:     'Failed',
};

const PHASE_SHORT = {
  SUBMITTED:  '1',
  BUILDING:   '2',
  SCANNING:   '3',
  TESTING:    '4',
  REPORTING:  '5',
  COMPLETE:   '✓',
};

function statusBadge(status) {
  if (status === 'COMPLETE') return 'badge-success';
  if (status === 'FAILED')   return 'badge-danger';
  return 'badge-warning';
}

function fmt(evt) {
  const { event, status, msg, ...rest } = evt;
  if (event === 'ws_error')  return '⚠ WebSocket error';
  if (event === 'ws_closed') return '— Connection closed';
  const parts = [];
  if (event)  parts.push(`[${event}]`);
  if (status) parts.push(`status=${status}`);
  if (msg)    parts.push(msg);
  const extra = Object.entries(rest);
  if (extra.length) parts.push(extra.map(([k, v]) => `${k}=${JSON.stringify(v)}`).join(' '));
  return parts.join(' ') || JSON.stringify(evt);
}

export default function RunStatus() {
  const { runId } = useParams();
  const [status, setStatus] = useState('SUBMITTED');
  const [events, setEvents] = useState([]);
  const [done, setDone] = useState(false);
  const logsRef = useRef(null);

  useEffect(() => {
    const ws = new WebSocket(`${WS_BASE}/ws/runs/${runId}/status`);

    ws.onmessage = (msg) => {
      try {
        const evt = JSON.parse(msg.data);
        if (evt.event === 'ping') return;
        if (evt.status) setStatus(evt.status);
        if (evt.event === 'complete' || evt.event === 'failed') setDone(true);
        setEvents(prev => [...prev, { ...evt, _ts: new Date().toLocaleTimeString() }]);
        setTimeout(() => logsRef.current?.scrollTo(0, logsRef.current.scrollHeight), 50);
      } catch {
        /* ignore parse errors */
      }
    };

    ws.onerror = () => setEvents(prev => [...prev, { event: 'ws_error', _ts: new Date().toLocaleTimeString() }]);
    ws.onclose = () => setEvents(prev => [...prev, { event: 'ws_closed', _ts: new Date().toLocaleTimeString() }]);

    return () => ws.close();
  }, [runId]);

  const phaseIndex = PHASES.indexOf(status);

  return (
    <Layout title={`Assessment #${runId}`} breadcrumb="Runs">
      {/* Status banner */}
      <div className="flex items-center gap-3 mb-6">
        <span className={`badge ${statusBadge(status)}`} style={{ fontSize: '0.8125rem', padding: '0.375rem 0.875rem' }}>
          {PHASE_LABELS[status] || status}
        </span>
        {!done && (
          <span className="text-muted text-sm">Pipeline is running — updates appear below</span>
        )}
        {done && status === 'COMPLETE' && (
          <span className="text-sm" style={{ color: 'var(--success)' }}>Assessment complete</span>
        )}
      </div>

      {/* Phase stepper */}
      <div className="card card-pad mb-6">
        <div className="card-title mb-4">Pipeline Progress</div>
        <div className="phase-stepper">
          {PHASES.map((phase, i) => {
            const isDone   = i < phaseIndex;
            const isActive = i === phaseIndex;
            return (
              <div key={phase} className="flex items-center flex-1">
                <div className="phase-step-wrap" style={{ flex: 'none' }}>
                  <div className={`phase-dot ${isDone ? 'done' : ''} ${isActive ? 'active' : ''}`}>
                    {isDone ? '✓' : (PHASE_SHORT[phase] || (i + 1))}
                  </div>
                  <div className={`phase-lbl ${isDone ? 'done' : ''} ${isActive ? 'active' : ''}`}>
                    {PHASE_LABELS[phase]}
                  </div>
                </div>
                {i < PHASES.length - 1 && (
                  <div className={`phase-connector ${isDone ? 'done' : ''}`} />
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Alert messages */}
      {done && status === 'COMPLETE' && (
        <div className="alert alert-success mb-4">
          Assessment completed successfully.{' '}
          <Link to={`/runs/${runId}/report`} style={{ fontWeight: 700, color: 'inherit', textDecoration: 'underline' }}>
            View the full security report →
          </Link>
        </div>
      )}
      {done && status === 'FAILED' && (
        <div className="alert alert-error mb-4">
          Assessment failed during the <strong>BUILDING</strong> phase. Check server logs for details.
        </div>
      )}

      {/* Action buttons */}
      {done && status === 'COMPLETE' && (
        <div className="flex gap-3 mb-6">
          <Link to={`/runs/${runId}/report`} className="btn btn-primary">View Security Report</Link>
          <Link to="/" className="btn btn-secondary">New Assessment</Link>
        </div>
      )}

      {/* Event Log */}
      <div className="card card-pad">
        <div className="flex items-center justify-between mb-4">
          <div>
            <div className="card-title">Event Log</div>
            <div className="card-desc">{events.length} events received</div>
          </div>
          {!done && (
            <div className="flex items-center gap-2" style={{ color: 'var(--warning)' }}>
              <span style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--warning)', display: 'inline-block', animation: 'pulseDot 1.8s infinite' }} />
              <span className="text-sm fw-600">Live</span>
            </div>
          )}
        </div>
        <div className="event-log" ref={logsRef}>
          {events.length === 0
            ? <div className="log-empty">Waiting for pipeline events…</div>
            : events.map((evt, i) => {
                const { _ts, ...rest } = evt;
                return (
                  <div key={i} className="log-entry">
                    <span className="log-ts">{_ts}</span>
                    <span className="log-msg">{fmt(rest)}</span>
                  </div>
                );
              })
          }
        </div>
      </div>
    </Layout>
  );
}
