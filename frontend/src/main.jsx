import { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { Activity, Bot, Database, Gauge, Radio, ShieldAlert, Server, Settings2, Wifi, Workflow } from "lucide-react";
import "./styles.css";

const API = import.meta.env.VITE_API_URL || "http://127.0.0.1:8000";

function Metric({ icon: Icon, label, value, tone = "blue" }) {
  return (
    <article className={`metric metric-${tone}`}>
      <div className="metric-icon"><Icon size={18} /></div>
      <div><span>{label}</span><strong>{value}</strong></div>
    </article>
  );
}

function App() {
  const [health, setHealth] = useState(null);
  const [events, setEvents] = useState([]);
  const [predictions, setPredictions] = useState([]);
  const [streaming, setStreaming] = useState(false);
  const [deceptions, setDeceptions] = useState([]);
  const [policy, setPolicy] = useState(null);
  const [federated, setFederated] = useState([]);

  useEffect(() => {
    const load = async () => {
      const [healthResponse, eventResponse, predictionResponse, deceptionResponse, policyResponse, federatedResponse] = await Promise.all([
        fetch(`${API}/api/v1/system/health`),
        fetch(`${API}/api/v1/events?limit=20`),
        fetch(`${API}/api/v1/detection/predictions?limit=20`),
        fetch(`${API}/api/v1/deception/actions?limit=20`),
        fetch(`${API}/api/v1/zerotrust/policy`),
        fetch(`${API}/api/v1/federated/rounds?limit=20`),
      ]);
      setHealth(await healthResponse.json());
      setEvents(await eventResponse.json());
      setPredictions(await predictionResponse.json());
      setDeceptions(await deceptionResponse.json());
      setPolicy(await policyResponse.json());
      setFederated(await federatedResponse.json());
    };
    load().catch(() => setHealth({ status: "OFFLINE" }));

    const socket = new WebSocket(API.replace(/^http/, "ws") + "/ws/events");
    socket.onopen = () => setStreaming(true);
    socket.onclose = () => setStreaming(false);
    socket.onmessage = (message) => {
      const payload = JSON.parse(message.data);
      if (payload.type === "event_snapshot") setEvents(payload.events);
    };
    return () => socket.close();
  }, []);

  const malicious = predictions.filter((item) => item.prediction === "MALICIOUS").length;
  const panelData = [
    ["Detection confidence", predictions.length ? `${Math.round(predictions.reduce((sum, item) => sum + item.confidence, 0) / predictions.length * 100)}%` : "--", ShieldAlert],
    ["Deception actions", deceptions.length, Bot],
    ["Policy threshold", policy ? `${Math.round(policy.threshold_deceive * 100)}%` : "--", Settings2],
    ["Federated rounds", federated.length, Workflow],
    ["Event throughput", streaming ? "LIVE" : "PAUSED", Gauge],
    ["Database", health?.database?.startsWith("HEALTHY") ? "HEALTHY" : "--", Database],
  ];
  return (
    <main className="dashboard-shell">
      <header className="topbar">
        <div className="brand"><span className="brand-mark">S</span><div><b>SENTINEL</b><small>CYBER DECEPTION SOC</small></div></div>
        <div className="connection"><span className={streaming ? "live-dot" : "dead-dot"}></span>{streaming ? "LIVE STREAM" : "OFFLINE"}</div>
      </header>
      <section className="intro"><div><p className="eyebrow">OPERATIONS CONSOLE / 01</p><h1>Threat posture</h1><p className="lede">Continuous visibility across event ingestion, detection, and adaptive response.</p></div><div className="status-chip"><Wifi size={15} /> {health?.status || "CONNECTING"}</div></section>
      <section className="metrics">
        <Metric icon={Activity} label="Events observed" value={events.length} />
        <Metric icon={ShieldAlert} label="Malicious signals" value={malicious} tone="red" />
        <Metric icon={Server} label="Active components" value={health?.status === "ONLINE" ? "9 / 9" : "--"} tone="green" />
        <Metric icon={Radio} label="Stream cadence" value={streaming ? "2 sec" : "--"} tone="amber" />
      </section>
      <section className="content-grid">
        <article className="panel event-panel"><div className="panel-head"><div><p className="eyebrow">LIVE TELEMETRY</p><h2>Recent network events</h2></div><span className="count">{events.length} records</span></div><div className="table-wrap"><table><thead><tr><th>Source</th><th>Destination</th><th>Protocol</th><th>Time</th></tr></thead><tbody>{events.map((event) => <tr key={event.id}><td className="mono">{event.source_ip}</td><td className="mono">{event.dest_ip}:{event.dest_port}</td><td><span className="tag">{event.protocol}</span></td><td>{new Date(event.event_time).toLocaleTimeString()}</td></tr>)}</tbody></table></div></article>
        <aside className="panel posture-panel"><p className="eyebrow">SYSTEM POSTURE</p><h2>Components</h2>{Object.entries(health?.active_components || {}).map(([name, status]) => <div className="component" key={name}><span>{name.replaceAll("_", " ")}</span><b className={status === "ONLINE" ? "online" : "standby"}>{status}</b></div>)}</aside>
      </section>
      <section className="monitor-grid">
        {panelData.map(([label, value, Icon]) => <article className="panel mini-panel" key={label}><Icon size={18} /><span>{label}</span><strong>{value}</strong></article>)}
      </section>
    </main>
  );
}

export default App;

createRoot(document.getElementById("root")).render(<App />);