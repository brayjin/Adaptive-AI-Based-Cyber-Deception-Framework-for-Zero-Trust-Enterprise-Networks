import { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { Activity, Bot, Database, Gauge, Radio, ShieldAlert, Server, Settings2, Wifi, Workflow, CheckCircle2 } from "lucide-react";
import "./styles.css";

const API = import.meta.env.VITE_API_URL || "http://127.0.0.1:8000";

async function api(path) {
  const res = await fetch(`${API}${path}`);
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

function Metric({ icon: Icon, label, value, tone = "blue" }) {
  return (
    <article className={`metric metric-${tone}`}>
      <div className="metric-icon"><Icon size={18} /></div>
      <div><span>{label}</span><strong>{value}</strong></div>
    </article>
  );
}

function Panel({ title, count, children }) {
  return (
    <section className="panel">
      <div className="panel-head">
        <h2>{title}</h2>
        {count !== undefined && <span className="count">{count}</span>}
      </div>
      {children}
    </section>
  );
}

function State({ loading, error, empty, children }) {
  if (loading) return <p className="lede">Loading…</p>;
  if (error) return <p className="lede" style={{ color: "#ef947a" }}>{error}</p>;
  if (empty) return <p className="lede">No data available.</p>;
  return children;
}

function App() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [health, setHealth] = useState(null);
  const [events, setEvents] = useState([]);
  const [eventCount, setEventCount] = useState(0);
  const [predictions, setPredictions] = useState([]);
  const [evaluations, setEvaluations] = useState([]);
  const [deceptions, setDeceptions] = useState([]);
  const [policy, setPolicy] = useState(null);
  const [federated, setFederated] = useState([]);
  const [modelMetrics, setModelMetrics] = useState(null);
  const [honeypotStatus, setHoneypotStatus] = useState(null);
  const [streaming, setStreaming] = useState(false);
  const [latestExplanation, setLatestExplanation] = useState(null);

  useEffect(() => {
    const load = async () => {
      try {
        const [
          healthRes,
          eventsRes,
          countRes,
          predRes,
          evalRes,
          decRes,
          policyRes,
          fedRes,
          metricsRes,
          twinRes,
        ] = await Promise.all([
          api("/api/v1/system/health"),
          api("/api/v1/events?limit=50"),
          api("/api/v1/events/count"),
          api("/api/v1/detection/predictions?limit=50"),
          api("/api/v1/zerotrust/evaluations?limit=50"),
          api("/api/v1/deception/actions?limit=50"),
          api("/api/v1/zerotrust/policy"),
          api("/api/v1/federated/rounds?limit=20"),
          api("/api/v1/detection/models/metrics"),
          api("/api/v1/deception/twin/status"),
        ]);
        setHealth(healthRes);
        setEvents(eventsRes);
        setEventCount(countRes.total_events || eventsRes.length);
        setPredictions(predRes);
        setEvaluations(evalRes);
        setDeceptions(decRes);
        setPolicy(policyRes);
        setFederated(fedRes);
        setModelMetrics(metricsRes);
        setHoneypotStatus(twinRes);

        if (predRes.length > 0 && predRes[0].id) {
          try {
            const expl = await api(`/api/v1/detection/predictions/${predRes[0].id}/explain`);
            setLatestExplanation(expl);
          } catch (e) {
            setLatestExplanation(null);
          }
        }
        setError(null);
      } catch (e) {
        setError(e.message || "Failed to load dashboard data");
      } finally {
        setLoading(false);
      }
    };
    load();

    const socket = new WebSocket(API.replace(/^http/, "ws") + "/ws/events");
    socket.onopen = () => setStreaming(true);
    socket.onclose = () => setStreaming(false);
    socket.onmessage = (message) => {
      try {
        const payload = JSON.parse(message.data);
        if (payload.type === "event_snapshot") setEvents(payload.events);
      } catch (e) {
        // ignore malformed messages
      }
    };
    return () => socket.close();
  }, []);

  const malicious = predictions.filter((p) => p.prediction === "MALICIOUS").length;
  const benign = predictions.filter((p) => p.prediction === "BENIGN").length;

  const policyDistribution = evaluations.reduce((acc, e) => {
    acc[e.trust_decision] = (acc[e.trust_decision] || 0) + 1;
    return acc;
  }, {});

  const latestEval = evaluations[0] || null;

  return (
    <main className="dashboard-shell">
      <header className="topbar">
        <div className="brand">
          <span className="brand-mark">S</span>
          <div><b>SENTINEL</b><small>CYBER DECEPTION SOC</small></div>
        </div>
        <div className="connection">
          <span className={streaming ? "live-dot" : "dead-dot"}></span>
          {streaming ? "LIVE STREAM" : "OFFLINE"}
        </div>
      </header>

      <section className="intro">
        <div>
          <p className="eyebrow">OPERATIONS CONSOLE / 01</p>
          <h1>Threat posture</h1>
          <p className="lede">Continuous visibility across event ingestion, detection, and adaptive response.</p>
        </div>
        <div className="status-chip">
          <Wifi size={15} /> {health?.status || "CONNECTING"}
        </div>
      </section>

      {error && <p className="lede" style={{ color: "#ef947a" }}>{error}</p>}

      <section className="metrics">
        <Metric icon={Activity} label="Events observed" value={loading ? "…" : eventCount} />
        <Metric icon={ShieldAlert} label="Malicious signals" value={loading ? "…" : malicious} tone="red" />
        <Metric icon={CheckCircle2} label="Benign signals" value={loading ? "…" : benign} tone="green" />
        <Metric icon={Server} label="Active components" value={health?.status === "ONLINE" ? "9 / 9" : "--"} tone="green" />
      </section>

      <div className="content-grid">
        <div>
          <Panel title="Overview: policy distribution" count={evaluations.length}>
            <State loading={loading} error={error} empty={!evaluations.length}>
              <div className="table-wrap">
                <table>
                  <thead><tr><th>DECISION</th><th>COUNT</th></tr></thead>
                  <tbody>
                    {Object.entries(policyDistribution).map(([k, v]) => (
                      <tr key={k}><td className="mono">{k}</td><td>{v}</td></tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </State>
          </Panel>

          <Panel title="Threat detection" count={predictions.length}>
            <State loading={loading} error={error} empty={!predictions.length}>
              <div className="table-wrap">
                <table>
                  <thead><tr><th>PREDICTION</th><th>CONFIDENCE</th><th>MODEL</th><th>EVENT</th></tr></thead>
                  <tbody>
                    {predictions.slice(0, 10).map((p) => (
                      <tr key={p.id}>
                        <td className="mono">{p.prediction}</td>
                        <td>{(p.confidence * 100).toFixed(1)}%</td>
                        <td>{p.model_version}</td>
                        <td className="mono">{p.event_id}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </State>
          </Panel>

          <Panel title="Zero Trust (latest evaluation)" count={latestEval ? 1 : 0}>
            <State loading={loading} error={error} empty={!latestEval}>
              {latestEval && (
                <div className="table-wrap">
                  <table>
                    <thead><tr><th>FACTOR</th><th>SCORE</th></tr></thead>
                    <tbody>
                      <tr><td>Identity</td><td>{latestEval.identity_score}</td></tr>
                      <tr><td>Device</td><td>{latestEval.device_score}</td></tr>
                      <tr><td>Behaviour</td><td>{latestEval.behaviour_score}</td></tr>
                      <tr><td>Context</td><td>{latestEval.context_score}</td></tr>
                      <tr><td>Network</td><td>{latestEval.network_score}</td></tr>
                      <tr><td>Composite risk</td><td>{latestEval.composite_risk_score}</td></tr>
                      <tr><td>Decision</td><td className="mono">{latestEval.trust_decision}</td></tr>
                    </tbody>
                  </table>
                </div>
              )}
            </State>
          </Panel>

          <Panel title="Explainability (top 5 SHAP features)" count={latestExplanation?.top_features?.length || 0}>
            <State loading={loading} error={error} empty={!latestExplanation?.top_features?.length}>
              {latestExplanation && (
                <div className="table-wrap">
                  <table>
                    <thead><tr><th>FEATURE</th><th>VALUE</th><th>CONTRIBUTION</th><th>DIRECTION</th></tr></thead>
                    <tbody>
                      {latestExplanation.top_features.map((f, i) => (
                        <tr key={i}>
                          <td>{f.display_name || f.feature}</td>
                          <td>{typeof f.value === "number" ? f.value.toFixed(3) : f.value}</td>
                          <td className="mono">{f.contribution}</td>
                          <td className="mono">{f.direction}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  <p className="lede" style={{ marginTop: 12 }}>{latestExplanation.explanation}</p>
                </div>
              )}
            </State>
          </Panel>

          <Panel title="Deception monitoring" count={deceptions.length}>
            <State loading={loading} error={error} empty={!deceptions.length}>
              <div className="table-wrap">
                <table>
                  <thead><tr><th>STRATEGY</th><th>TARGET</th><th>INTERACTIONS</th><th>SUCCESS</th></tr></thead>
                  <tbody>
                    {deceptions.slice(0, 10).map((d) => (
                      <tr key={d.id}>
                        <td className="mono">{d.strategy_selected}</td>
                        <td>{d.deception_target}</td>
                        <td>{(d.interaction_log || []).length}</td>
                        <td>{String(d.deception_success)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {deceptions[0]?.interaction_log?.length > 0 && (
                <div style={{ marginTop: 12 }}>
                  <h3 style={{ fontSize: 14 }}>Latest interaction</h3>
                  {(() => {
                    const last = deceptions[0].interaction_log.slice(-1)[0];
                    return (
                      <div className="table-wrap">
                        <table>
                          <tbody>
                            <tr><td>Attacker input</td><td className="mono">{last.input}</td></tr>
                            <tr><td>Decoy response</td><td className="mono">{last.response_text}</td></tr>
                            <tr><td>Duration (ms)</td><td>{last.latency_ms}</td></tr>
                            <tr><td>Canary signal</td><td>{String(last.canary_triggered)}</td></tr>
                          </tbody>
                        </table>
                      </div>
                    );
                  })()}
                </div>
              )}
            </State>
          </Panel>

          <Panel title="Audit logs" count={evaluations.length}>
            <State loading={loading} error={error} empty={!evaluations.length}>
              <div className="table-wrap">
                <table>
                  <thead><tr><th>EVENT ID</th><th>PREDICTION</th><th>RISK</th><th>DECISION</th><th>DECEPTION</th><th>TIMESTAMP</th></tr></thead>
                  <tbody>
                    {evaluations.slice(0, 10).map((e) => {
                      const dec = deceptions.find((d) => d.evaluation_id === e.id);
                      return (
                        <tr key={e.id}>
                          <td className="mono">{e.event_id}</td>
                          <td>{e.trust_decision}</td>
                          <td>{e.composite_risk_score}</td>
                          <td className="mono">{e.trust_decision}</td>
                          <td className="mono">{dec ? dec.strategy_selected : "-"}</td>
                          <td className="mono">{e.created_at}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </State>
          </Panel>
        </div>

        <aside>
          <Panel title="System health">
            <State loading={loading} error={error} empty={false}>
              <div>
                <div className="component"><span>Backend</span><b className="online">{health?.status || "--"}</b></div>
                <div className="component"><span>Database</span><b className={health?.database?.startsWith("HEALTHY") ? "online" : "standby"}>{health?.database || "--"}</b></div>
                <div className="component"><span>Model availability</span><b className={modelMetrics && modelMetrics.status !== "NOT_TRAINED" ? "online" : "standby"}>{modelMetrics && modelMetrics.status !== "NOT_TRAINED" ? "TRAINED" : "STANDBY"}</b></div>
                <div className="component"><span>Decoy services</span><b className="online">{honeypotStatus ? Object.keys(honeypotStatus.services || {}).length : 0}</b></div>
                <div className="component"><span>Stream</span><b className={streaming ? "online" : "standby"}>{streaming ? "LIVE" : "PAUSED"}</b></div>
                {(health?.active_components) && Object.entries(health.active_components).map(([k, v]) => (
                  <div className="component" key={k}><span>{k.replace(/_/g, " ")}</span><b className={v === "ONLINE" ? "online" : "standby"}>{v}</b></div>
                ))}
              </div>
            </State>
          </Panel>

          <Panel title="Policy">
            <State loading={loading} error={error} empty={!policy}>
              {policy && (
                <div>
                  <div className="component"><span>Allow</span><b>{policy.threshold_allow}</b></div>
                  <div className="component"><span>Verify</span><b>{policy.threshold_verify}</b></div>
                  <div className="component"><span>Restrict</span><b>{policy.threshold_restrict}</b></div>
                  <div className="component"><span>Deceive</span><b>{policy.threshold_deceive}</b></div>
                  <div className="component"><span>Behaviour weight</span><b>{policy.weight_behaviour}</b></div>
                </div>
              )}
            </State>
          </Panel>

          <Panel title="Federated rounds" count={federated.length}>
            <State loading={loading} error={error} empty={!federated.length}>
              <div className="table-wrap">
                <table>
                  <thead><tr><th>ROUND</th><th>CLIENTS</th><th>MEAN ACC</th></tr></thead>
                  <tbody>
                    {federated.slice(0, 5).map((r, i) => (
                      <tr key={i}>
                        <td>{r.round_number}</td>
                        <td>{r.num_clients}</td>
                        <td>{r.global_metrics?.mean_client_accuracy?.toFixed?.(3) ?? "-"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </State>
          </Panel>
        </aside>
      </div>

      <section className="monitor-grid">
        {[
          ["Detection confidence", predictions.length ? `${Math.round(predictions.reduce((s, p) => s + p.confidence, 0) / predictions.length * 100)}%` : "--", ShieldAlert],
          ["Deception actions", deceptions.length, Bot],
          ["Policy threshold", policy ? `${Math.round(policy.threshold_deceive * 100)}%` : "--", Settings2],
          ["Federated rounds", federated.length, Workflow],
          ["Event throughput", streaming ? "LIVE" : "PAUSED", Gauge],
          ["Database", health?.database?.startsWith("HEALTHY") ? "HEALTHY" : "--", Database],
        ].map(([label, value, Icon]) => (
          <article className="panel mini-panel" key={label}>
            <Icon size={18} />
            <span>{label}</span>
            <strong>{value}</strong>
          </article>
        ))}
      </section>
    </main>
  );
}

createRoot(document.getElementById("root")).render(<App />);
