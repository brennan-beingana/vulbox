import { useEffect, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";

const WS_BASE = "ws://127.0.0.1:8000";

const PHASE_ORDER = ["SUBMITTED", "BUILDING", "SCANNING", "TESTING", "REPORTING", "COMPLETE"];

const PHASE_LABELS = {
  SUBMITTED: "Submitted",
  BUILDING: "Building image",
  SCANNING: "Running Trivy scan",
  TESTING: "Executing ART tests",
  REBUILDING: "Rebuilding after crash",
  REPORTING: "Generating report",
  COMPLETE: "Complete",
  FAILED: "Failed",
};

export default function RunStatus() {
  const { runId } = useParams();
  const [status, setStatus] = useState("SUBMITTED");
  const [events, setEvents] = useState([]);
  const [done, setDone] = useState(false);
  const wsRef = useRef(null);
  const logsRef = useRef(null);

  useEffect(() => {
    const ws = new WebSocket(`${WS_BASE}/ws/runs/${runId}/status`);
    wsRef.current = ws;

    ws.onmessage = (msg) => {
      try {
        const evt = JSON.parse(msg.data);
        if (evt.event === "ping") return;
        if (evt.status) setStatus(evt.status);
        if (evt.event === "complete" || evt.event === "failed") setDone(true);
        setEvents(prev => [...prev, evt]);
        setTimeout(() => logsRef.current?.scrollTo(0, logsRef.current.scrollHeight), 50);
      } catch {
        /* ignore parse errors */
      }
    };

    ws.onerror = () => setEvents(prev => [...prev, { event: "ws_error", msg: "WebSocket error" }]);
    ws.onclose = () => setEvents(prev => [...prev, { event: "ws_closed" }]);

    return () => ws.close();
  }, [runId]);

  const phaseIndex = PHASE_ORDER.indexOf(status);

  return (
    <main className="page">
      <section className="hero">
        <h1>Assessment #{runId}</h1>
        <p>Live pipeline status</p>
      </section>

      <div className="card">
        <h2>Current Phase: {PHASE_LABELS[status] || status}</h2>
        <div className="phase-bar">
          {PHASE_ORDER.map((phase, i) => (
            <div
              key={phase}
              className={`phase-step ${i < phaseIndex ? "done" : ""} ${i === phaseIndex ? "active" : ""}`}
            >
              {PHASE_LABELS[phase]}
            </div>
          ))}
        </div>

        {done && status === "COMPLETE" && (
          <Link to={`/runs/${runId}/report`} className="btn-primary" style={{ display: "inline-block", marginTop: "1rem" }}>
            View Report
          </Link>
        )}
        {done && status === "FAILED" && (
          <p className="error" style={{ marginTop: "1rem" }}>Assessment failed during BUILDING phase. Check server logs.</p>
        )}
      </div>

      <div className="card">
        <h2>Event Log</h2>
        <div className="event-log" ref={logsRef}>
          {events.length === 0 && <p className="muted">Waiting for events…</p>}
          {events.map((evt, i) => (
            <div key={i} className="log-entry">
              <code>{JSON.stringify(evt)}</code>
            </div>
          ))}
        </div>
      </div>
    </main>
  );
}
