import { useCallback, useEffect, useState } from "react";
import {
  Activity, AlertTriangle, BrainCircuit, Play, RefreshCw,
  Search, Server, Shield, Terminal, Trash2,
} from "lucide-react";
import {
  Area, AreaChart, CartesianGrid, ResponsiveContainer,
  Tooltip, XAxis, YAxis,
} from "recharts";
import { api } from "./api";
import "./App.css";

const EVENT_LABELS = {
  connection: "Connected",
  login_attempt: "Failed login",
  login_success: "Logged in",
  command: "Command",
  file_download: "Download",
  service_scan: "Scan or probe",
  resource_discovery: "Browsing",
  web_request: "Web request",
};

const RULES = [
  ["After 3 failed logins", "The SSH decoy accepts the next login, like a weak password."],
  ["Logged in and browsing files", "Bait files appear: a database backup and cloud credentials."],
  ["Tries to download a file", "More tools (ps, netstat, ifconfig) start working."],
  ["Opens a bait file", "Higher-value bait appears: a private key and a customer list."],
];

const clock = (ts) =>
  ts ? new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "-";
const minute = (m) =>
  new Date(m + ":00Z").toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

function adaptationText(a) {
  const d = a.detail || {};
  if (a.action === "accept_login") return "now accepts the next login";
  if (a.action === "plant_files") return "planted " + Object.keys(d.files || {}).join(", ");
  if (a.action === "unlock_tools") return "unlocked " + (d.commands || []).join(", ");
  return a.action;
}

function Risk({ level }) {
  return <span className={`risk ${level}`}>{level}</span>;
}

function Meter({ score, level }) {
  return (
    <div className="meter" title={`Score ${score} of 100`}>
      <i className={level} style={{ width: `${score}%` }} />
    </div>
  );
}

export default function App() {
  const [view, setView] = useState("overview");
  const [stats, setStats] = useState(null);
  const [events, setEvents] = useState([]);
  const [sessions, setSessions] = useState([]);
  const [adaptations, setAdaptations] = useState([]);
  const [decoys, setDecoys] = useState([]);
  const [selected, setSelected] = useState("");
  const [error, setError] = useState("");

  const refresh = useCallback(async () => {
    try {
      const [st, ev, se, ad, de] = await Promise.all([
        api.stats(), api.events(), api.sessions(), api.adaptations(), api.decoys(),
      ]);
      setStats(st);
      setEvents(ev.events);
      setSessions(se.sessions);
      setAdaptations(ad.adaptations);
      setDecoys(de.decoys);
      setError("");
    } catch {
      setError("Cannot reach the backend. Start it with: uvicorn app.main:app --reload");
    }
  }, []);

  useEffect(() => {
    refresh();
    const timer = setInterval(refresh, 3000);
    return () => clearInterval(timer);
  }, [refresh]);

  async function simulate() {
    try {
      const result = await api.simulate();
      setSelected(result.session_id);
      await refresh();
    } catch (e) {
      setError(e.message);
    }
  }

  async function reset() {
    if (!window.confirm("Delete all events, adaptations and analyses?")) return;
    try {
      await api.reset();
      setSelected("");
      await refresh();
    } catch (e) {
      setError(e.message);
    }
  }

  function openSession(id) {
    setSelected(id);
    setView("investigate");
  }

  const nav = [
    ["overview", "Overview", Activity],
    ["events", "Event monitor", Terminal],
    ["investigate", "Investigations", BrainCircuit],
    ["decoys", "Decoys and adaptation", Server],
  ];
  const online = decoys.filter((d) => d.status === "online").length;

  return (
    <div className="shell">
      <aside className="rail">
        <div className="brand">
          <Shield size={26} />
          <div>
            <strong>DefenceAI</strong>
            <span>Adaptive honeypot platform</span>
          </div>
        </div>
        <nav>
          {nav.map(([id, label, Icon]) => (
            <button key={id} className={view === id ? "on" : ""} onClick={() => setView(id)}>
              <Icon size={17} /> {label}
            </button>
          ))}
        </nav>
        <p className="rail-note">
          Lab mode. Every event comes from isolated decoys or the built-in simulator.
        </p>
      </aside>

      <main className="main">
        <header className="topbar">
          <h1>{nav.find((n) => n[0] === view)[1]}</h1>
          <div className="actions">
            <button onClick={simulate}><Play size={15} /> Simulate attack</button>
            <button className="ghost" onClick={refresh}><RefreshCw size={15} /> Refresh</button>
            <button className="ghost" onClick={reset}><Trash2 size={15} /> Reset data</button>
          </div>
        </header>

        {error && <div className="error" role="alert">{error}</div>}

        {view === "overview" && (
          <Overview stats={stats} adaptations={adaptations} online={online} openSession={openSession} />
        )}
        {view === "events" && <EventMonitor events={events} openSession={openSession} />}
        {view === "investigate" && (
          <Investigate sessions={sessions} selected={selected} setSelected={setSelected} />
        )}
        {view === "decoys" && (
          <Decoys decoys={decoys} adaptations={adaptations} openSession={openSession} />
        )}
      </main>
    </div>
  );
}

/* ---------------- Overview ---------------- */

function Overview({ stats, adaptations, online, openSession }) {
  if (!stats) return <p className="muted pad">Loading...</p>;
  const figures = [
    ["Events captured", stats.total_events],
    ["Sessions", stats.total_sessions],
    ["High-risk sessions", stats.high_risk_sessions],
    ["Decoy adaptations", stats.adaptations],
    ["Avg. delay to dashboard", stats.avg_ingest_delay_ms == null ? "-" : `${stats.avg_ingest_delay_ms} ms`],
    ["Decoys online", online],
  ];
  const timeline = stats.timeline.map((t) => ({ time: minute(t.minute), events: t.events }));

  return (
    <>
      <section className="figures">
        {figures.map(([label, value]) => (
          <div key={label}>
            <b>{value}</b>
            <span>{label}</span>
          </div>
        ))}
      </section>

      <section className="band two">
        <div>
          <h2>Activity in the last 30 minutes</h2>
          <div className="chart">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={timeline}>
                <CartesianGrid stroke="#c5d0cd" strokeDasharray="2 4" vertical={false} />
                <XAxis dataKey="time" stroke="#5b6e75" fontSize={12} />
                <YAxis allowDecimals={false} stroke="#5b6e75" fontSize={12} />
                <Tooltip />
                <Area type="monotone" dataKey="events" stroke="#12303a" fill="#9bb9b4" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
          {!timeline.length && <p className="muted">No events yet. Press Simulate attack.</p>}
        </div>
        <div>
          <h2>Risk by session</h2>
          {stats.risk_distribution.map((r) => (
            <div className="barrow" key={r.risk}>
              <Risk level={r.risk} />
              <div className="bar">
                <i className={r.risk} style={{ width: `${stats.total_sessions ? (r.sessions / stats.total_sessions) * 100 : 0}%` }} />
              </div>
              <span>{r.sessions}</span>
            </div>
          ))}
        </div>
      </section>

      <section className="band three">
        <TopList title="Most active sources" items={stats.top_ips} />
        <TopList title="Usernames tried" items={stats.top_usernames} />
        <TopList title="Commands typed" items={stats.top_commands} mono />
      </section>

      <section className="band">
        <h2>Latest decoy adaptations</h2>
        {adaptations.length === 0 && <p className="muted">The decoys have not changed yet.</p>}
        <ul className="plain">
          {adaptations.slice(0, 5).map((a) => (
            <li key={a.id}>
              <time>{clock(a.timestamp)}</time>
              <span>
                Decoy for <code>{a.source_ip}</code> {adaptationText(a)}
              </span>
              <button className="link" onClick={() => openSession(a.session_id)}>View session</button>
            </li>
          ))}
        </ul>
      </section>
    </>
  );
}

function TopList({ title, items, mono }) {
  const max = Math.max(1, ...items.map((i) => i.count));
  return (
    <div>
      <h2>{title}</h2>
      {items.length === 0 && <p className="muted">Nothing yet.</p>}
      {items.map((i) => (
        <div className="toprow" key={i.value}>
          <span className={mono ? "mono" : ""} title={i.value}>{i.value}</span>
          <div className="bar"><i style={{ width: `${(i.count / max) * 100}%` }} /></div>
          <b>{i.count}</b>
        </div>
      ))}
    </div>
  );
}

/* ---------------- Event monitor ---------------- */

function EventMonitor({ events, openSession }) {
  const [type, setType] = useState("");
  const [query, setQuery] = useState("");
  const q = query.trim().toLowerCase();
  const rows = events.filter(
    (e) =>
      (!type || e.event_type === type) &&
      (!q ||
        [e.source_ip, e.session_id, e.username, e.command, e.details]
          .filter(Boolean)
          .some((v) => v.toLowerCase().includes(q))),
  );

  return (
    <section className="band">
      <div className="filters">
        <label className="search">
          <Search size={15} />
          <input placeholder="Search IP, session, user or command" value={query}
            onChange={(e) => setQuery(e.target.value)} />
        </label>
        <select value={type} onChange={(e) => setType(e.target.value)} aria-label="Event type">
          <option value="">All event types</option>
          {Object.entries(EVENT_LABELS).map(([k, v]) => (
            <option key={k} value={k}>{v}</option>
          ))}
        </select>
        <span className="muted">{rows.length} of {events.length} shown</span>
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr><th>Time</th><th>Source</th><th>Event</th><th>What happened</th><th>Session</th></tr>
          </thead>
          <tbody>
            {rows.map((e) => (
              <tr key={e.id}>
                <td>{clock(e.timestamp)}</td>
                <td className="mono">{e.source_ip}</td>
                <td>{EVENT_LABELS[e.event_type] || e.event_type}</td>
                <td className="mono wrap">{e.command || e.details || "-"}{e.username ? ` (${e.username})` : ""}</td>
                <td><button className="link" onClick={() => openSession(e.session_id)}>{e.session_id}</button></td>
              </tr>
            ))}
          </tbody>
        </table>
        {rows.length === 0 && <p className="muted pad">No matching events.</p>}
      </div>
    </section>
  );
}

/* ---------------- Investigations ---------------- */

function Investigate({ sessions, selected, setSelected }) {
  const [detail, setDetail] = useState(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [err, setErr] = useState("");
  const current = selected || sessions[0]?.session_id || "";
  const count = sessions.find((s) => s.session_id === current)?.event_count;

  useEffect(() => {
    if (!current) return undefined;
    let live = true;
    api.session(current).then((d) => live && setDetail(d)).catch(() => {});
    return () => { live = false; };
  }, [current, count]);

  async function analyze(refresh) {
    setAnalyzing(true);
    setErr("");
    try {
      const ai = await api.analyze(current, refresh);
      setDetail((d) => ({ ...d, ai }));
    } catch (e) {
      setErr(e.message);
    } finally {
      setAnalyzing(false);
    }
  }

  if (!sessions.length) {
    return <p className="muted pad">No sessions yet. Press Simulate attack, or attack the decoys.</p>;
  }
  const shown = detail && detail.session_id === current ? detail : null;

  return (
    <div className="split">
      <ul className="sessions">
        {sessions.map((s) => (
          <li key={s.session_id}>
            <button className={s.session_id === current ? "on" : ""} onClick={() => setSelected(s.session_id)}>
              <span className="sid">{s.session_id}</span>
              <span className="mono muted">{s.source_ips.join(", ")}</span>
              <span className="row">
                <Meter score={s.analysis.score} level={s.analysis.rule_based_risk} />
                <Risk level={s.analysis.rule_based_risk} />
              </span>
            </button>
          </li>
        ))}
      </ul>

      <div className="detail">
        {!shown && <p className="muted">Loading session...</p>}
        {shown && (
          <>
            <div className="dhead">
              <div>
                <h2>{shown.session_id}</h2>
                <p className="muted mono">{shown.source_ips.join(", ")} - {shown.events.length} events</p>
              </div>
              <div className="score">
                <b>{shown.analysis.score}</b><span>of 100</span>
                <Risk level={shown.analysis.rule_based_risk} />
              </div>
            </div>

            {shown.analysis.techniques.length > 0 && (
              <p className="chips">
                {shown.analysis.techniques.map((t) => (
                  <span key={t.id} className="chip">{t.id} {t.name}</span>
                ))}
              </p>
            )}
            <ul className="evidence">
              {shown.analysis.evidence.map((x, i) => <li key={i}>{x}</li>)}
            </ul>

            <h3>Trace</h3>
            <Trace events={shown.events} adaptations={shown.adaptations} />

            <h3>AI incident assessment</h3>
            <div className="actions left">
              <button onClick={() => analyze(false)} disabled={analyzing}>
                <BrainCircuit size={15} /> {analyzing ? "Analyzing..." : shown.ai ? "Show assessment" : "Analyze with AI"}
              </button>
              {shown.ai && (
                <button className="ghost" onClick={() => analyze(true)} disabled={analyzing}>Re-run</button>
              )}
            </div>
            {err && <div className="error">{err}</div>}
            {shown.ai && <Assessment ai={shown.ai} />}
          </>
        )}
      </div>
    </div>
  );
}

function Trace({ events, adaptations }) {
  const items = [
    ...events.map((e) => ({ kind: "event", ts: e.timestamp, key: `e${e.id}`, e })),
    ...adaptations.map((a) => ({ kind: "adapt", ts: a.timestamp, key: `a${a.id}`, a })),
  ].sort((x, y) => new Date(x.ts) - new Date(y.ts));

  return (
    <ol className="trace">
      {items.map((it) =>
        it.kind === "event" ? (
          <li key={it.key} className="step">
            <time>{clock(it.ts)}</time>
            <div>
              <span className="etype">{EVENT_LABELS[it.e.event_type] || it.e.event_type}</span>
              {it.e.command ? <code>{it.e.command}</code> : <span> {it.e.details}</span>}
              {it.e.username && <span className="muted"> as {it.e.username}</span>}
            </div>
          </li>
        ) : (
          <li key={it.key} className="step adapt">
            <time>{clock(it.ts)}</time>
            <div>
              <strong>Decoy adapted:</strong> {adaptationText(it.a)}
              <em>{it.a.detail?.reason}</em>
            </div>
          </li>
        ),
      )}
    </ol>
  );
}

function show(value) {
  if (Array.isArray(value)) {
    return <ul>{value.map((x, i) => <li key={i}>{typeof x === "string" ? x : JSON.stringify(x)}</li>)}</ul>;
  }
  if (value && typeof value === "object") return JSON.stringify(value);
  return String(value ?? "-");
}

function Assessment({ ai }) {
  const a = ai.assessment || {};
  const rows = [
    ["Summary", a.summary],
    ["Likely intent", a.likely_intent],
    ["Risk level", a.risk_level],
    ["Supporting evidence", a.supporting_evidence],
    ["Recommended action", a.recommended_defensive_action],
  ];
  return (
    <div className="assessment">
      {ai.warning && <p className="warn"><AlertTriangle size={14} /> {ai.warning}</p>}
      <dl>
        {rows.map(([k, v]) => (
          <div key={k}><dt>{k}</dt><dd>{show(v)}</dd></div>
        ))}
      </dl>
      <p className="muted small">Source: {ai.source}</p>
    </div>
  );
}

/* ---------------- Decoys ---------------- */

function Decoys({ decoys, adaptations, openSession }) {
  return (
    <>
      <section className="band">
        <h2>Decoy services</h2>
        {decoys.length === 0 && (
          <p className="muted">
            No decoy has reported in. Start them with <code>python ssh_honeypot.py</code> and{" "}
            <code>python web_honeypot.py</code> in the honeypot folder.
          </p>
        )}
        <ul className="plain">
          {decoys.map((d) => (
            <li key={d.name}>
              <span className={`dot ${d.status}`} aria-hidden="true" />
              <strong>{d.name}</strong>
              <span>{d.kind} on port {d.port}</span>
              <span className="muted">{d.status}, last seen {d.seconds_since_seen}s ago</span>
            </li>
          ))}
        </ul>
      </section>

      <section className="band two">
        <div>
          <h2>How the decoys adapt</h2>
          <ul className="rules">
            {RULES.map(([when, then]) => (
              <li key={when}><strong>{when}</strong><span>{then}</span></li>
            ))}
          </ul>
        </div>
        <div>
          <h2>Adaptation log</h2>
          {adaptations.length === 0 && <p className="muted">No adaptations yet.</p>}
          <ul className="plain">
            {adaptations.slice(0, 12).map((a) => (
              <li key={a.id}>
                <time>{clock(a.timestamp)}</time>
                <span><code>{a.source_ip}</code> {adaptationText(a)}</span>
                <button className="link" onClick={() => openSession(a.session_id)}>Open</button>
              </li>
            ))}
          </ul>
        </div>
      </section>
    </>
  );
}
