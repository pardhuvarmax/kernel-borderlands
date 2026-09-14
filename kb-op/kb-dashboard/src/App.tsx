import { useState, useEffect, useMemo, useRef, useCallback } from 'react';
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid
} from 'recharts';
import {
  Shield, AlertTriangle, Activity, Lock, Unlock,
  Search, RefreshCw, Cpu, Layers, Terminal, Bell, Settings,
  Server, Wifi, WifiOff, Map, Users, ShieldAlert
} from 'lucide-react';

// ── Types ────────────────────────────────────────────────────────────────────
type Zone = 'SAFE' | 'SUSPICIOUS' | 'BORDERLANDS' | 'QUARANTINED';
type Sev  = 'INFO' | 'WARNING' | 'CRITICAL';

interface Process {
  pid: number; ppid: number; comm: string;
  uid: number; score: number; zone: Zone;
  startedAt: string; quorumPending?: boolean;
}

interface KBAlert {
  id: string; type: string; pid: number; comm: string;
  severity: Sev; ts: string; evidence: string[];
}

interface ChartPoint { t: string; safe: number; sus: number; bl: number; }

// kbd's HTTP/SSE API base. Configurable via VITE_KB_API_BASE (e.g. for a
// remote deployment behind TLS/a different port); defaults to the same
// host the dashboard was loaded from, port 8080 — a hardcoded "localhost"
// here would resolve to the browser's own machine instead of the dev host
// whenever the dashboard is opened remotely (e.g. over Tailscale/VM
// port-forwarding).
const API_BASE = import.meta.env.VITE_KB_API_BASE || `http://${window.location.hostname}:8080`;

// Bearer token sent as Authorization on state-mutating requests
// (/api/isolate, /api/restore) — kbd refuses those routes without one
// (KB_HTTP_API_TOKEN on the server side, see BUG-001).
const API_TOKEN = import.meta.env.VITE_KB_API_TOKEN || '';

// ── Helpers ──────────────────────────────────────────────────────────────────
const ts = () =>
  new Date().toLocaleTimeString('en-US', { hour12: false });

const scoreColor = (s: number) =>
  s < 0.3 ? 'var(--safe)' : s < 0.65 ? 'var(--warn)' : 'var(--danger)';

const zoneClass = (z: Zone) =>
  ({ SAFE: 'safe', SUSPICIOUS: 'suspicious', BORDERLANDS: 'borderlands', QUARANTINED: 'quarantined' }[z]);

// ── Static seed data ──────────────────────────────────────────────────────────
const SEED: Process[] = [
  { pid: 1,    ppid: 0,   comm: 'systemd',    uid: 0,    score: 0.02, zone: 'SAFE',        startedAt: '00:00:01' },
  { pid: 450,  ppid: 1,   comm: 'sshd',       uid: 0,    score: 0.10, zone: 'SAFE',        startedAt: '00:00:04' },
  { pid: 812,  ppid: 1,   comm: 'postgres',   uid: 70,   score: 0.07, zone: 'SAFE',        startedAt: '00:00:05' },
  { pid: 915,  ppid: 1,   comm: 'nginx',      uid: 33,   score: 0.09, zone: 'SAFE',        startedAt: '00:00:06' },
  { pid: 1205, ppid: 1,   comm: 'kbd',        uid: 0,    score: 0.01, zone: 'SAFE',        startedAt: '00:00:07' },
  { pid: 1210, ppid: 1,   comm: 'kb-checker', uid: 0,    score: 0.01, zone: 'SAFE',        startedAt: '00:00:07' },
  { pid: 3102, ppid: 450, comm: 'bash',       uid: 1000, score: 0.22, zone: 'SAFE',        startedAt: '11:40:12' },
];

const HEALTH_SERVICES = [
  { name: 'kb-core (eBPF Sensor)',     desc: 'Ring 0 syscall hooks',          status: 'ok'  },
  { name: 'kbd (Go Control Plane)',    desc: '/run/kb/kba.sock',              status: 'ok'  },
  { name: 'kb-checker (Rust Watchdog)',desc: 'Hard fallback containment',     status: 'ok'  },
  { name: 'AADS Agent Swarm',          desc: 'ZeroMQ + Ray consensus',        status: 'ok'  },
  { name: 'gRPC Health Service',       desc: 'Standard grpc_health_v1',       status: 'ok'  },
  { name: 'SQLite L2 Store',           desc: 'WAL journal mode',              status: 'ok'  },
];

// ── App ───────────────────────────────────────────────────────────────────────
export default function App() {
  const [simulated, setSimulated]   = useState(true);
  const [processes,  setProcesses]  = useState<Process[]>(SEED);
  const [alerts,     setAlerts]     = useState<KBAlert[]>([]);
  const [log,        setLog]        = useState<{ text: string; cls: string }[]>([]);
  const [chart,      setChart]      = useState<ChartPoint[]>([]);
  const [search,     setSearch]     = useState('');
  const [zoneFilter, setZoneFilter] = useState<string>('ALL');
  const [activeNav,  setActiveNav]  = useState('Processes');

  const [services, setServices] = useState<any[]>(HEALTH_SERVICES);
  const [metricsData, setMetricsData] = useState({
    ebpf_latency_ns: 430,
    grpc_rtt_ms: 0.1,
    aads_latency_ms: 0.75,
    events_per_second: 0
  });

  // Rogue Management — real data from kbd's /api/agents proxy (see
  // kb-control-plane/internal/controlplane/http.go's handleAgents), which
  // itself proxies kb-aads/api/status_server.py. `agentsError` distinguishes
  // "swarm not running" (a routine dev state) from a genuinely empty roster.
  const [agents, setAgents] = useState<{ agent_id: string; role: string; registry_status: string; uptime: number; error_count: number; last_action: string }[]>([]);
  const [agentsError, setAgentsError] = useState<string | null>(null);

  // Settings — real data from kbd's /api/policy (see policy.Engine's
  // DefaultSuspiciousThreshold/DefaultBorderlandsThreshold, display-only).
  const [policyInfo, setPolicyInfo] = useState<{ suspicious_threshold: number; borderlands_threshold: number; sensitive_paths_count: number; policy_path: string } | null>(null);
  const [policyError, setPolicyError] = useState<string | null>(null);
  const [reloadStatus, setReloadStatus] = useState<string | null>(null);

  const termRef = useRef<HTMLDivElement>(null);
  const alertKeySet = useRef<Set<string>>(new Set());

  // Log helper
  const addLog = useCallback((text: string, cls = 'normal') => {
    setLog(prev => [...prev.slice(-120), { text: `[${ts()}] ${text}`, cls }]);
  }, []);

  // Add alert helper (dedup by id)
  const addAlert = useCallback((a: KBAlert) => {
    if (alertKeySet.current.has(a.id)) return;
    alertKeySet.current.add(a.id);
    setAlerts(prev => [a, ...prev].slice(0, 60));
  }, []);

  // Bootstrap
  useEffect(() => {
    addLog('[CORE] eBPF CO-RE telemetry hooks loaded.', 'success');
    addLog('[WATCHDOG] kb-checker safety daemon active.', 'success');
    addLog('[CONTROL] kbd listening on /run/kb/kba.sock.', 'success');
    addLog('[HEALTH] gRPC health check: SERVING (kba.sock)', 'success');
    addLog('[STORE] SQLite L2 WAL journal mode: active.', 'success');

    // Seed chart
    const now = new Date();
    setChart(Array.from({ length: 10 }, (_, i) => {
      const d = new Date(now.getTime() - (9 - i) * 4000);
      return {
        t: d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }),
        safe: 7, sus: 0, bl: 0
      };
    }));
  }, [addLog]);

  // Auto-scroll terminal
  useEffect(() => {
    termRef.current?.scrollTo({ top: termRef.current.scrollHeight, behavior: 'smooth' });
  }, [log]);

  // Fetch agent roster when Rogue Management is opened — real data via
  // kbd's /api/agents proxy, not gated on the simulated/live toggle since
  // it reflects kb-aads's actual process state independent of whether the
  // rest of the dashboard is showing simulated process/alert data.
  useEffect(() => {
    if (activeNav !== 'Rogue Management') return;
    let active = true;
    fetch(`${API_BASE}/api/agents`)
      .then(res => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return res.json();
      })
      .then(data => {
        if (!active) return;
        if (data.error) { setAgentsError(data.error); setAgents([]); }
        else { setAgents(data.agents || []); setAgentsError(null); }
      })
      .catch(err => { if (active) { setAgentsError(`AADS swarm status unreachable: ${err.message}`); setAgents([]); } });
    return () => { active = false; };
  }, [activeNav]);

  // Fetch policy defaults when Settings is opened.
  const fetchPolicy = useCallback(() => {
    fetch(`${API_BASE}/api/policy`)
      .then(res => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return res.json();
      })
      .then(data => { setPolicyInfo(data); setPolicyError(null); })
      .catch(err => { setPolicyError(`kbd unreachable: ${err.message}`); setPolicyInfo(null); });
  }, []);

  useEffect(() => {
    if (activeNav === 'Settings') fetchPolicy();
  }, [activeNav, fetchPolicy]);

  const reloadPolicy = () => {
    setReloadStatus('Reloading…');
    fetch(`${API_BASE}/api/policy/reload`, {
      method: 'POST',
      headers: API_TOKEN ? { 'Authorization': `Bearer ${API_TOKEN}` } : {},
    })
      .then(res => res.json().then(data => ({ ok: res.ok, data })))
      .then(({ ok, data }) => {
        setReloadStatus(ok ? `${data.message}` : `Failed: ${data.message || 'unknown error'}`);
        if (ok) fetchPolicy();
      })
      .catch(err => setReloadStatus(`Failed: ${err.message}`));
  };

  // Simulation loop
  useEffect(() => {
    if (!simulated) return;
    const id = setInterval(() => {
      setProcesses(prev => {
        let procs = [...prev];

        // Maybe spawn short-lived process
        if (procs.length < 18 && Math.random() > 0.6) {
          const comms = ['curl', 'wget', 'python3', 'node', 'sh', 'awk', 'gcc', 'make'];
          const name  = comms[Math.floor(Math.random() * comms.length)];
          const parent = procs[Math.floor(Math.random() * procs.length)];
          const pid    = 4000 + Math.floor(Math.random() * 3000);
          procs.push({ pid, ppid: parent.pid, comm: name, uid: Math.random() > 0.5 ? 1000 : 0, score: 0.05, zone: 'SAFE', startedAt: ts() });
          addLog(`[CORE] sched_fork: PID ${pid} (${name}) from PPID ${parent.pid}`, 'dim');
        }

        // Maybe escalate a safe → suspicious
        procs = procs.map(p => {
          if (p.zone === 'SAFE' && !p.quorumPending && Math.random() > 0.92) {
            addLog(`[SENSOR] Privilege anomaly on PID ${p.pid} (${p.comm}) — score rising`, 'warn');
            return { ...p, score: 0.66, zone: 'SUSPICIOUS' as Zone };
          }
          // suspicious → borderlands → quorum
          if (p.zone === 'SUSPICIOUS' && !p.quorumPending && Math.random() > 0.75) {
            addLog(`[AADS] Quorum vote requested — PID ${p.pid} (${p.comm})`, 'info');
            addLog(`[AADS] ├ Patroller: COMPROMISED (91%)`, 'info');
            addLog(`[AADS] ├ Hunter:    COMPROMISED (88%)`, 'info');
            addLog(`[AADS] └ VERDICT: ISOLATE — confidence 89.5%`, 'warn');

            const id = `al-${p.pid}-${Date.now()}`;
            addAlert({
              id, type: 'BORDERLANDS_ENTRY', pid: p.pid, comm: p.comm,
              severity: 'CRITICAL', ts: ts(),
              evidence: [`ema_score=${(p.score * 100).toFixed(1)}`, 'privilege_escalation', 'namespace_drift']
            });
            return { ...p, score: 0.91, zone: 'BORDERLANDS' as Zone, quorumPending: true };
          }
          return p;
        });

        // Auto-terminate borderlands processes (simulating SIGKILL)
        procs.forEach(p => {
          if (p.zone === 'BORDERLANDS' && p.quorumPending) {
            setTimeout(() => {
              setProcesses(cur => {
                const still = cur.find(c => c.pid === p.pid && c.zone === 'BORDERLANDS');
                if (!still) return cur;
                addLog(`[WATCHDOG] Layer 1 — SIGKILL → PID ${p.pid}`, 'err');
                addLog(`[CORE] sched_exit: PID ${p.pid} (${p.comm}) evicted.`, 'success');
                return cur.filter(c => c.pid !== p.pid);
              });
            }, 3500 + Math.random() * 1500);
          }
        });

        return procs;
      });

      // Chart tick
      setProcesses(cur => {
        const cnts = cur.reduce((a, p) => {
          if (p.zone === 'SAFE') a.safe++;
          else if (p.zone === 'SUSPICIOUS') a.sus++;
          else a.bl++;
          return a;
        }, { safe: 0, sus: 0, bl: 0 });
        setChart(prev => [...prev.slice(1), {
          t: ts(), safe: cnts.safe, sus: cnts.sus, bl: cnts.bl
        }]);
        return cur;
      });

      // Periodic health audit log
      if (Math.random() > 0.72) {
        addLog('[HEALTH] UDS gRPC audit: SERVING (< 100ms)', 'success');
        addLog('[WATCHDOG] BPF map integrity: 0 tampered links', 'success');
      }
    }, 4200);

    return () => clearInterval(id);
  }, [simulated, addLog, addAlert]);

  // Live API Connection Loop
  useEffect(() => {
    if (simulated) return;

    let active = true;
    let eventSource: EventSource | null = null;

    addLog(`[CONSOLE] Connecting to live API endpoint at ${API_BASE}...`, 'info');

    // Helper to fetch initial state
    const fetchInitialState = async () => {
      try {
        // Fetch active processes
        const resProcs = await fetch(`${API_BASE}/api/processes`);
        if (!resProcs.ok) throw new Error('Failed to fetch processes');
        const procsData = await resProcs.json();
        if (active) {
          setProcesses(procsData.map((p: any) => ({
            pid: p.pid,
            ppid: p.ppid,
            comm: p.comm,
            uid: p.uid,
            score: p.score,
            zone: p.zone as Zone,
            startedAt: ts()
          })));
          addLog(`[CONSOLE] Synced ${procsData.length} live processes from kbd.`, 'success');
        }

        // Fetch recent alerts
        const resAlerts = await fetch(`${API_BASE}/api/alerts`);
        if (!resAlerts.ok) throw new Error('Failed to fetch alerts');
        const alertsData = await resAlerts.json();
        if (active) {
          alertsData.forEach((a: any) => {
            addAlert({
              id: a.alertId,
              type: a.alertType,
              pid: a.pid,
              comm: a.comm,
              severity: a.severity as Sev,
              ts: a.timestamp,
              evidence: a.evidence
            });
          });
          addLog(`[CONSOLE] Synced ${alertsData.length} alerts from L2 store.`, 'success');
        }

        // Fetch recent logs
        const resLogs = await fetch(`${API_BASE}/api/logs`);
        if (!resLogs.ok) throw new Error('Failed to fetch logs');
        const logsData = await resLogs.json();
        if (active) {
          const formatted = logsData.map((l: any) => ({
            text: `[${l.time}] [${l.action}] ${l.subject} (${l.actor}) ${l.reason ? '— ' + l.reason : ''}`,
            cls: l.action.includes('TERMINATE') || l.action.includes('CRITICAL') ? 'err' : l.action.includes('NONE') ? 'success' : 'info'
          })).reverse();
          setLog(prev => [...prev.slice(-40), ...formatted]);
        }

        // Fetch services health
        const resServ = await fetch(`${API_BASE}/api/services`);
        if (resServ.ok) {
          const servData = await resServ.json();
          if (active) setServices(servData);
        }

        // Fetch performance metrics
        const resMet = await fetch(`${API_BASE}/api/metrics`);
        if (resMet.ok) {
          const metData = await resMet.json();
          if (active) setMetricsData(metData);
        }
      } catch (err: any) {
        if (active) {
          addLog(`[CONSOLE] Connection error: ${err.message}`, 'err');
        }
      }
    };

    fetchInitialState();

    // Setup SSE connection
    try {
      eventSource = new EventSource(`${API_BASE}/api/events`);

      eventSource.addEventListener('connected', () => {
        addLog('[CONSOLE] SSE Connection established.', 'success');
      });

      eventSource.addEventListener('telemetry', (e) => {
        if (!active) return;
        try {
          const payload = JSON.parse(e.data);
          const { type, data } = payload;

          if (type === 'event') {
            if (data.eventType === 'process_state') {
              setProcesses(prev => {
                const idx = prev.findIndex(p => p.pid === data.pid);
                const zoneVal = data.metadata?.zone || 'SAFE';
                const uidVal = data.metadata?.uid ? parseInt(data.metadata.uid) : data.uid || 0;
                const updatedProcess: Process = {
                  pid: data.pid,
                  ppid: data.ppid,
                  comm: data.comm,
                  uid: uidVal,
                  score: data.score,
                  zone: zoneVal as Zone,
                  startedAt: ts()
                };

                if (idx >= 0) {
                  const next = [...prev];
                  next[idx] = { ...next[idx], ...updatedProcess };
                  return next;
                } else {
                  return [...prev, updatedProcess];
                }
              });
            } else if (data.eventType === 'zone_transition') {
              const fromZone = data.metadata?.from_zone || 'SAFE';
              const toZone = data.metadata?.to_zone || 'SAFE';
              addLog(`[SENSOR] Zone transition: PID ${data.pid} (${data.comm}) ${fromZone} ➔ ${toZone}`, 'warn');
              setProcesses(prev => prev.map(p => p.pid === data.pid ? { ...p, zone: toZone as Zone, score: data.score } : p));
            }
          } else if (type === 'alert') {
            addAlert({
              id: data.alertId,
              type: data.alertType,
              pid: data.pid,
              comm: data.comm,
              severity: data.severity as Sev,
              ts: data.timestamp,
              evidence: data.evidence
            });
            addLog(`[ALERT] BORDERLANDS ENTRY: PID ${data.pid} (${data.comm})`, 'err');
          }
        } catch (err) {
          // ignore parsing issues
        }
      });

      eventSource.onerror = () => {
        if (active) {
          addLog('[CONSOLE] SSE Connection lost. Retrying...', 'warn');
        }
      };

    } catch (err: any) {
      addLog(`[CONSOLE] SSE initialization failed: ${err.message}`, 'err');
    }

    // Chart update ticker for live mode
    const chartTicker = setInterval(() => {
      if (!active) return;
      setProcesses(cur => {
        const cnts = cur.reduce((a, p) => {
          if (p.zone === 'SAFE') a.safe++;
          else if (p.zone === 'SUSPICIOUS') a.sus++;
          else a.bl++;
          return a;
        }, { safe: 0, sus: 0, bl: 0 });
        setChart(prev => [...prev.slice(1), {
          t: ts(), safe: cnts.safe, sus: cnts.sus, bl: cnts.bl
        }]);
        return cur;
      });
    }, 4000);

    // Services update ticker
    const servicesTicker = setInterval(async () => {
      try {
        const res = await fetch(`${API_BASE}/api/services`);
        if (!res.ok) throw new Error();
        const data = await res.json();
        if (active) setServices(data);
      } catch (err) {
        // ignore
      }
    }, 5000);

    // Metrics update ticker
    const metricsTicker = setInterval(async () => {
      try {
        const res = await fetch(`${API_BASE}/api/metrics`);
        if (!res.ok) throw new Error();
        const data = await res.json();
        if (active) setMetricsData(data);
      } catch (err) {
        // ignore
      }
    }, 3000);

    return () => {
      active = false;
      if (eventSource) eventSource.close();
      clearInterval(chartTicker);
      clearInterval(servicesTicker);
      clearInterval(metricsTicker);
    };
  }, [simulated, addLog, addAlert]);

  // Filtered processes
  const filtered = useMemo(() => processes.filter(p => {
    const q = search.toLowerCase();
    const matchQ = !q || p.comm.toLowerCase().includes(q) || String(p.pid).includes(q);
    const matchZ = zoneFilter === 'ALL' || p.zone === zoneFilter;
    return matchQ && matchZ;
  }), [processes, search, zoneFilter]);

  // Metrics
  const metrics = useMemo(() => ({
    total:    processes.length,
    safe:     processes.filter(p => p.zone === 'SAFE').length,
    sus:      processes.filter(p => p.zone === 'SUSPICIOUS').length,
    danger:   processes.filter(p => p.zone === 'BORDERLANDS' || p.zone === 'QUARANTINED').length,
    alerts:   alerts.filter(a => a.severity === 'CRITICAL').length,
  }), [processes, alerts]);

  // Operator: isolate
  const isolate = (pid: number, comm: string) => {
    if (simulated) {
      setProcesses(prev => prev.map(p => p.pid === pid ? { ...p, zone: 'QUARANTINED', score: 1.0 } : p));
      const id = `al-${pid}-${Date.now()}`;
      addAlert({ id, type: 'MANUAL_QUARANTINE', pid, comm, severity: 'CRITICAL', ts: ts(), evidence: ['manual_operator_action', 'containment_level_4'] });
      addLog(`[OPERATOR] Manual quarantine — PID ${pid} (${comm})`, 'err');
    } else {
      fetch(`${API_BASE}/api/isolate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...(API_TOKEN ? { 'Authorization': `Bearer ${API_TOKEN}` } : {}) },
        body: JSON.stringify({ pid })
      }).then(res => {
        if (res.ok) {
          setProcesses(prev => prev.map(p => p.pid === pid ? { ...p, zone: 'QUARANTINED', score: 1.0 } : p));
          addLog(`[OPERATOR] manual isolate request sent for PID ${pid} (${comm})`, 'success');
        } else {
          addLog(`[OPERATOR] manual isolate failed for PID ${pid}`, 'err');
        }
      }).catch(err => {
        addLog(`[OPERATOR] isolation error: ${err.message}`, 'err');
      });
    }
  };

  // Operator: restore
  const restore = (pid: number, comm: string) => {
    if (simulated) {
      setProcesses(prev => prev.map(p => p.pid === pid ? { ...p, zone: 'SAFE', score: 0.04, quorumPending: false } : p));
      addLog(`[OPERATOR] Restored PID ${pid} (${comm}) → SAFE`, 'success');
    } else {
      fetch(`${API_BASE}/api/restore`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...(API_TOKEN ? { 'Authorization': `Bearer ${API_TOKEN}` } : {}) },
        body: JSON.stringify({ pid })
      }).then(res => {
        if (res.ok) {
          setProcesses(prev => prev.map(p => p.pid === pid ? { ...p, zone: 'SAFE', score: 0.04, quorumPending: false } : p));
          addLog(`[OPERATOR] manual restore request sent for PID ${pid} (${comm})`, 'success');
        } else {
          addLog(`[OPERATOR] manual restore failed for PID ${pid}`, 'err');
        }
      }).catch(err => {
        addLog(`[OPERATOR] restore error: ${err.message}`, 'err');
      });
    }
  };

  // Nav items, grouped by platform area — expanded so the sidebar reads as
  // a full multi-section control panel rather than 5 flat items. Every
  // group still maps to real app state (processes/alerts/services/log);
  // Rogue Management and Settings are the two pages with no live backend
  // yet and are explicitly labeled as such in their own view, rather than
  // silently presenting placeholder data as if it were real.
  const NAV_GROUPS = [
    {
      label: 'Core Monitoring',
      items: [
        { label: 'Processes',     icon: <Cpu size={14} />,      badge: metrics.danger > 0 ? metrics.danger : null },
        { label: 'Zone Topology', icon: <Map size={14} />,      badge: null },
        { label: 'Alerts',        icon: <Bell size={14} />,     badge: metrics.alerts > 0 ? metrics.alerts : null },
        { label: 'Telemetry',     icon: <Activity size={14} />, badge: null },
      ],
    },
    {
      label: 'Platform Management',
      items: [
        { label: 'Services',    icon: <Server size={14} />, badge: null },
        { label: 'Containment', icon: <Lock size={14} />,   badge: metrics.danger > 0 ? metrics.danger : null },
      ],
    },
    {
      label: 'Intelligence & Consensus',
      items: [
        { label: 'Consensus Log',      icon: <Users size={14} />,       badge: null },
        { label: 'Rogue Management',   icon: <ShieldAlert size={14} />, badge: null },
      ],
    },
    {
      label: 'System & Governance',
      items: [
        { label: 'Console',  icon: <Terminal size={14} />, badge: null },
        { label: 'Settings', icon: <Settings size={14} />, badge: null },
      ],
    },
  ];

  const SECTION_TITLES: Record<string, string> = {
    Processes:         'System Overview',
    'Zone Topology':    'Zone Topology',
    Alerts:             'Threat & Alert Center',
    Telemetry:          'Telemetry & Performance',
    Services:           'Platform Services',
    Containment:         'Containment Actions',
    'Consensus Log':     'AADS Consensus Log',
    'Rogue Management':  'Rogue Agent Management',
    Console:             'Audit Console',
    Settings:            'Settings',
  };

  return (
    <div className="shell">

      {/* ── Top Bar ─────────────────────────────────────────────── */}
      <header className="topbar">
        <div className="topbar-brand">
          <div className="brand-icon">
            <Shield size={16} />
          </div>
          <div>
            <div className="brand-name">Kernel Borderlands</div>
            <div className="brand-sub">Kernel-Level Runtime Defense Platform</div>
          </div>
        </div>

        <div className="topbar-center">
          codename&nbsp;<span style={{ color: 'var(--accent)' }}>kryo</span>
        </div>

        <div className="topbar-right">
          <div className="role-tag">
            Role: <span className="role-tag-val">Operator</span>
          </div>
          <div className="topbar-sep" />

          <div
            className={`live-indicator ${simulated ? 'sim' : 'live'}`}
            onClick={() => { setSimulated(!simulated); addLog(`[CONSOLE] Backend mode toggled → ${simulated ? 'LIVE' : 'SIMULATION'}`, 'info'); }}
            title="Toggle feed mode"
          >
            {simulated ? <WifiOff size={11} /> : <Wifi size={11} />}
            <span className="live-dot" />
            {simulated ? 'SIMULATION' : 'LIVE FEED'}
          </div>

          <button className="btn-icon" title="Refresh"><RefreshCw size={13} /></button>
          <button className="btn-icon" title="Settings"><Settings size={13} /></button>
        </div>
      </header>

      {/* ── Sidebar ─────────────────────────────────────────────── */}
      <aside className="sidebar">
        {NAV_GROUPS.map(group => (
          <div className="nav-group" key={group.label}>
            <div className="nav-section-label">{group.label}</div>
            {group.items.map(n => (
              <div
                key={n.label}
                className={`nav-item ${activeNav === n.label ? 'active' : ''}`}
                onClick={() => setActiveNav(n.label)}
              >
                {n.icon} {n.label}
                {n.badge != null && (
                  <span className={`nav-badge ${n.badge === 0 ? 'ok' : ''}`}>{n.badge}</span>
                )}
              </div>
            ))}
          </div>
        ))}

        <div className="sidebar-footer">
          <div className="nav-section-label" style={{ padding: '0 0 10px' }}>System</div>
          <div className="system-summary-row">
            <span className="summary-dot ok" />
            <span className="system-summary-label">Zone: Safe</span>
            <span className="system-summary-val ok">{metrics.safe}</span>
          </div>
          <div className="system-summary-row">
            <span className={`summary-dot ${metrics.sus > 0 ? 'warn' : ''}`} />
            <span className="system-summary-label">Zone: Suspicious</span>
            <span className="system-summary-val">{metrics.sus}</span>
          </div>
          <div className="system-summary-row">
            <span className={`summary-dot ${metrics.danger > 0 ? 'bad' : ''}`} />
            <span className="system-summary-label">Zone: Critical</span>
            <span className={`system-summary-val ${metrics.danger > 0 ? 'bad' : ''}`}>{metrics.danger}</span>
          </div>
          <div className="system-summary-row">
            <span className="summary-dot ok" />
            <span className="system-summary-label">L1 Cache</span>
            <span className="system-summary-val ok">OK</span>
          </div>
        </div>
      </aside>

      {/* ── Main ─────────────────────────────────────────────────── */}
      <main className="main">

        <h1 className="section-heading">{SECTION_TITLES[activeNav]}</h1>

        {/* Persistent stat cards — visible in all views */}
        <div className="stat-row">
          <div className="stat-card">
            <div className="stat-top">
              <div className="stat-label">Tracked Processes</div>
              <div className="stat-icon"><Cpu size={15} /></div>
            </div>
            <div className="stat-info">
              <div className="stat-value">{metrics.total}</div>
              <div className="stat-sub">L1 in-memory cache</div>
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-top">
              <div className="stat-label">Safe Zone</div>
              <div className="stat-icon"><Shield size={15} /></div>
            </div>
            <div className="stat-info">
              <div className="stat-value">{metrics.safe}</div>
              <div className="stat-sub">
                {metrics.total > 0 ? `${Math.round((metrics.safe / metrics.total) * 100)}% of tracked` : 'Nominal processes'}
              </div>
              <div className="stat-bar-bg">
                <div className="stat-bar-fill" style={{ width: `${metrics.total > 0 ? (metrics.safe / metrics.total) * 100 : 0}%` }} />
              </div>
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-top">
              <div className="stat-label">Suspicious</div>
              <div className="stat-icon"><AlertTriangle size={15} /></div>
            </div>
            <div className="stat-info">
              <div className="stat-value yellow">{metrics.sus}</div>
              <div className="stat-sub">Elevated EMA score</div>
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-top">
              <div className="stat-label">Borderlands / Quarantine</div>
              <div className="stat-icon"><Layers size={15} /></div>
            </div>
            <div className="stat-info">
              <div className="stat-value red">{metrics.danger}</div>
              <div className="stat-sub">Active containment</div>
            </div>
          </div>
        </div>

        {/* ══ VIEW: Processes ══════════════════════════════════════════ */}
        {activeNav === 'Processes' && (
          <div className="content-grid">
            <div className="col-left">

              {/* Zone Trend Chart */}
              <div className="panel" style={{ flexShrink: 0 }}>
                <div className="panel-head">
                  <div className="panel-title">
                    <span className="panel-title-dot" />
                    Zone Distribution — Real-time
                  </div>
                  <span className="panel-tag">last 10 ticks</span>
                </div>
                <div className="chart-wrap">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={chart} margin={{ top: 8, right: 8, left: -24, bottom: 0 }}>
                      <defs>
                        <linearGradient id="gSafe" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="0%" stopColor="var(--safe)"  stopOpacity={0.25} />
                          <stop offset="100%" stopColor="var(--safe)" stopOpacity={0} />
                        </linearGradient>
                        <linearGradient id="gSus" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="0%" stopColor="var(--warn)"  stopOpacity={0.25} />
                          <stop offset="100%" stopColor="var(--warn)" stopOpacity={0} />
                        </linearGradient>
                        <linearGradient id="gBl" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="0%" stopColor="var(--danger)"  stopOpacity={0.3} />
                          <stop offset="100%" stopColor="var(--danger)" stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid stroke="rgba(255,255,255,0.04)" strokeDasharray="3 3" />
                      <XAxis dataKey="t" tick={{ fill: 'var(--tx-dim)', fontSize: 9 }} />
                      <YAxis tick={{ fill: 'var(--tx-dim)', fontSize: 9 }} allowDecimals={false} />
                      <Tooltip contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 6, fontSize: 11 }} labelStyle={{ color: 'var(--tx-secondary)' }} itemStyle={{ color: 'var(--tx-primary)' }} />
                      <Area type="monotone" dataKey="safe" name="Safe"        stroke="var(--safe)"  fill="url(#gSafe)" strokeWidth={1.5} />
                      <Area type="monotone" dataKey="sus"  name="Suspicious"  stroke="var(--warn)"  fill="url(#gSus)"  strokeWidth={1.5} />
                      <Area type="monotone" dataKey="bl"   name="Borderlands" stroke="var(--danger)" fill="url(#gBl)"  strokeWidth={1.5} />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </div>

              {/* Process Table */}
              <div className="panel" style={{ flex: 1, minHeight: 0 }}>
                <div className="panel-head">
                  <div className="panel-title"><span className="panel-title-dot green" />Tracked Processes</div>
                  <span className="panel-tag">{filtered.length} / {processes.length} shown</span>
                </div>
                <div className="filter-bar">
                  <div className="input-wrap">
                    <Search size={12} className="input-icon" />
                    <input className="search-input" placeholder="Search PID or name…" value={search} onChange={e => setSearch(e.target.value)} />
                  </div>
                  <select className="zone-filter" value={zoneFilter} onChange={e => setZoneFilter(e.target.value)}>
                    <option value="ALL">All Zones</option>
                    <option value="SAFE">Safe</option>
                    <option value="SUSPICIOUS">Suspicious</option>
                    <option value="BORDERLANDS">Borderlands</option>
                    <option value="QUARANTINED">Quarantined</option>
                  </select>
                </div>
                <div className="table-scroll">
                  <table className="proc-table">
                    <thead><tr><th>Process</th><th>PID</th><th>PPID</th><th>UID</th><th>Zone</th><th>Risk Index</th><th>Action</th></tr></thead>
                    <tbody>
                      {filtered.map(p => {
                        const fill = scoreColor(p.score);
                        return (
                          <tr key={p.pid}>
                            <td><span className="proc-comm">{p.comm}</span></td>
                            <td><span className="proc-pid">{p.pid}</span></td>
                            <td><span className="proc-pid">{p.ppid}</span></td>
                            <td><span className="proc-pid">{p.uid}</span></td>
                            <td><span className={`zone-badge ${zoneClass(p.zone)}`}>{p.zone}</span></td>
                            <td>
                              <div className="score-bar-wrap">
                                <div className="score-bar-bg"><div className="score-bar-fill" style={{ width: `${p.score * 100}%`, background: fill, color: fill }} /></div>
                                <span className="score-val" style={{ color: fill }}>{p.score.toFixed(2)}</span>
                              </div>
                            </td>
                            <td>
                              {p.zone === 'QUARANTINED'
                                ? <button className="act-btn restore" onClick={() => restore(p.pid, p.comm)}><Unlock size={10} />Restore</button>
                                : <button className="act-btn isolate" onClick={() => isolate(p.pid, p.comm)}><Lock size={10} />Isolate</button>}
                            </td>
                          </tr>
                        );
                      })}
                      {filtered.length === 0 && <tr><td colSpan={7}><div className="empty-state">No processes match filter</div></td></tr>}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>

            <div className="col-right">
              {/* Right sidebar: services + terminal only now */}
              <div className="panel" style={{ flexShrink: 0 }}>
                <div className="panel-head">
                  <div className="panel-title"><span className="panel-title-dot green" />Service Health</div>
                  <span className="panel-tag">6 services</span>
                </div>
                <div className="health-list">
                  {services.map(s => (
                    <div key={s.name} className="health-item">
                      <div className="health-left">
                        <div className="health-name">{s.name}</div>
                        <div className="health-desc">{s.desc}</div>
                      </div>
                      <span className={`health-badge ${s.status}`}>{s.status === 'ok' ? 'ACTIVE' : 'DOWN'}</span>
                    </div>
                  ))}
                </div>
              </div>
              <div className="panel" style={{ flex: 1, minHeight: 0 }}>
                <div className="panel-head">
                  <div className="panel-title"><span className="panel-title-dot" />Audit Console</div>
                  <span className="panel-tag">live journal</span>
                </div>
                <div className="terminal" ref={termRef} style={{ flex: 1 }}>
                  {log.map((l, i) => <div key={i} className={`t-line ${l.cls}`}>{l.text}</div>)}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ══ VIEW: Zone Topology ═══════════════════════════════════════ */}
        {activeNav === 'Zone Topology' && (
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, flex: 1, minHeight: 0 }}>
            {([
              ['SAFE', 'safe', 'Nominal — no elevated behavioral signal'],
              ['SUSPICIOUS', 'suspicious', 'Elevated EMA score, under active watch'],
              ['BORDERLANDS', 'borderlands', 'Quorum-flagged, pending containment decision'],
              ['QUARANTINED', 'quarantined', 'Manually or automatically isolated'],
            ] as const).map(([zone, cls, desc]) => {
              const inZone = processes.filter(p => p.zone === zone);
              return (
                <div className="panel" key={zone} style={{ minHeight: 0 }}>
                  <div className="panel-head">
                    <div className="panel-title"><span className={`panel-title-dot ${cls === 'safe' ? 'green' : cls === 'suspicious' ? 'yellow' : 'red'}`} />{zone}</div>
                    <span className="panel-tag">{inZone.length} processes</span>
                  </div>
                  <div style={{ padding: '0 20px 12px', fontSize: 11, color: 'var(--tx-secondary)' }}>{desc}</div>
                  <div className="table-scroll">
                    {inZone.length === 0 && <div className="empty-state">No processes in this zone</div>}
                    {inZone.map(p => (
                      <div className="health-item" key={p.pid}>
                        <div className="health-left">
                          <div className="health-name">{p.comm}</div>
                          <div className="health-desc">PID {p.pid} · UID {p.uid}</div>
                        </div>
                        <span className={`zone-badge ${zoneClass(p.zone)}`}>{p.score.toFixed(2)}</span>
                      </div>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {/* ══ VIEW: Alerts ════════════════════════════════════════════ */}
        {activeNav === 'Alerts' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16, flex: 1, minHeight: 0 }}>
            <div className="panel" style={{ flexShrink: 0 }}>
              <div className="panel-head">
                <div className="panel-title"><span className="panel-title-dot" />Severity Breakdown</div>
                <span className="panel-tag">{alerts.length} tracked</span>
              </div>
              <div style={{ padding: '4px 20px 18px', display: 'flex', flexDirection: 'column' }}>
                {[
                  { label: 'Critical', dot: 'bad',  count: alerts.filter(a => a.severity === 'CRITICAL').length },
                  { label: 'Warning',  dot: 'warn', count: alerts.filter(a => a.severity === 'WARNING').length },
                  { label: 'Info',     dot: '',     count: alerts.filter(a => a.severity === 'INFO').length },
                ].map(r => (
                  <div className="system-summary-row" key={r.label}>
                    <span className={`summary-dot ${r.dot}`} />
                    <span className="system-summary-label">{r.label}</span>
                    <span className={`system-summary-val ${r.dot}`}>{r.count}</span>
                  </div>
                ))}
              </div>
            </div>
            <div className="content-grid" style={{ flex: 1, minHeight: 0 }}>
            <div className="col-left">
              <div className="panel" style={{ flex: 1, minHeight: 0 }}>
                <div className="panel-head">
                  <div className="panel-title"><span className="panel-title-dot red" />All Threat Alerts</div>
                  <span className="panel-tag">{alerts.length} total</span>
                </div>
                <div className="table-scroll">
                  <table className="proc-table">
                    <thead><tr><th>Severity</th><th>Type</th><th>PID</th><th>Comm</th><th>Time</th><th>Evidence</th></tr></thead>
                    <tbody>
                      {alerts.length === 0 && <tr><td colSpan={6}><div className="empty-state"><Shield size={22} style={{ color: 'var(--tx-dim)' }} />No alerts yet</div></td></tr>}
                      {alerts.map(a => (
                        <tr key={a.id}>
                          <td><span className={`zone-badge ${a.severity === 'CRITICAL' ? 'quarantined' : a.severity === 'WARNING' ? 'suspicious' : 'safe'}`}>{a.severity}</span></td>
                          <td><span className="proc-comm" style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>{a.type}</span></td>
                          <td><span className="proc-pid">{a.pid}</span></td>
                          <td><span className="proc-comm">{a.comm}</span></td>
                          <td><span className="proc-pid">{a.ts}</span></td>
                          <td><div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>{a.evidence.map((e, i) => <span key={i} className="alert-tag">{e}</span>)}</div></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
            <div className="col-right">
              <div className="panel" style={{ flex: 1, minHeight: 0 }}>
                <div className="panel-head">
                  <div className="panel-title"><span className="panel-title-dot red" />Threat Feed</div>
                  <span className="panel-tag">live</span>
                </div>
                <div className="alert-feed">
                  {alerts.length === 0 && <div className="empty-state"><Shield size={24} style={{ color: 'var(--tx-dim)' }} />No active threats</div>}
                  {alerts.map(a => (
                    <div key={a.id} className={`alert-item ${a.severity.toLowerCase()}`}>
                      <div className="alert-top">
                        <span className={`alert-type ${a.severity.toLowerCase()}`}>{a.type}</span>
                        <span className="alert-ts">{a.ts}</span>
                      </div>
                      <div className="alert-body">PID <strong>{a.pid}</strong> (<strong>{a.comm}</strong>) — {a.severity}</div>
                      <div className="alert-tags">{a.evidence.map((e, i) => <span key={i} className="alert-tag">{e}</span>)}</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
            </div>
          </div>
        )}

        {/* ══ VIEW: Services ══════════════════════════════════════════ */}
        {activeNav === 'Services' && (
          <div className="content-grid">
            <div className="col-left">
              <div className="panel" style={{ flex: 1, minHeight: 0 }}>
                <div className="panel-head">
                  <div className="panel-title"><span className="panel-title-dot green" />System Services</div>
                  <span className="panel-tag">kb-op subsystem</span>
                </div>
                <div className="table-scroll">
                  <table className="proc-table">
                    <thead><tr><th>Service</th><th>Description</th><th>Socket / Endpoint</th><th>Status</th></tr></thead>
                    <tbody>
                      {[
                        { name: 'kb-core (eBPF Sensor)',      desc: 'Ring 0 syscall hooks via CO-RE',       sock: 'kernel ring buffer' },
                        { name: 'kbd (Go Control Plane)',      desc: 'Central event router & gRPC host',     sock: '/run/kb/kba.sock' },
                        { name: 'kb-checker (Rust Watchdog)', desc: 'Hard-stop containment daemon',         sock: '/run/kb/kbc.sock' },
                        { name: 'AADS Agent Swarm',           desc: 'ZeroMQ pub/sub + Ray Actor IPC',       sock: 'ipc:///run/kb/aads.ipc' },
                        { name: 'gRPC Health Service',        desc: 'Standard grpc_health_v1 probe',        sock: 'kba.sock — 100ms timeout' },
                        { name: 'SQLite L2 Store',            desc: 'WAL journal — persistent alert log',   sock: '/var/lib/kb/alerts.db' },
                        { name: 'kbctl CLI',                  desc: 'Operator shell interface',             sock: 'stdout / /run/kb/kbd.sock' },
                      ].map(s => {
                        const statusObj = services.find(srv => srv.name === s.name);
                        const status = statusObj ? statusObj.status : 'offline';
                        return (
                          <tr key={s.name}>
                            <td><span className="proc-comm">{s.name}</span></td>
                            <td style={{ color: 'var(--tx-secondary)' }}>{s.desc}</td>
                            <td><span className="proc-pid">{s.sock}</span></td>
                            <td><span className={`health-badge ${status}`}>{status === 'ok' ? 'ACTIVE' : 'DOWN'}</span></td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
            <div className="col-right">
              <div className="panel" style={{ flexShrink: 0 }}>
                <div className="panel-head">
                  <div className="panel-title"><span className="panel-title-dot" />Platform Composition</div>
                  <span className="panel-tag">7 services</span>
                </div>
                <div style={{ padding: '2px 20px 14px', display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                  {[
                    ['kb-core', 'C / eBPF'], ['kbd', 'Go'], ['kb-checker', 'Rust'],
                    ['AADS Swarm', 'Python'], ['gRPC Health', 'Go'], ['SQLite L2', 'Go'], ['kbctl', 'Go'],
                  ].map(([name, lang]) => (
                    <span className="alert-tag" key={name}>{name} · {lang}</span>
                  ))}
                </div>
                <div style={{ padding: '4px 20px 16px', display: 'flex', flexDirection: 'column', borderTop: '1px solid var(--border)' }}>
                  {(() => {
                    const names = ['kb-core (eBPF Sensor)', 'kbd (Go Control Plane)', 'kb-checker (Rust Watchdog)', 'AADS Agent Swarm', 'gRPC Health Service', 'SQLite L2 Store', 'kbctl CLI'];
                    const activeCount = names.filter(n => services.find(s => s.name === n)?.status === 'ok').length;
                    const downCount = names.length - activeCount;
                    return [
                      { label: 'Active', dot: 'ok',  count: activeCount },
                      { label: 'Down',   dot: downCount > 0 ? 'bad' : '', count: downCount },
                    ].map(r => (
                      <div className="system-summary-row" key={r.label} style={{ paddingTop: 10 }}>
                        <span className={`summary-dot ${r.dot}`} />
                        <span className="system-summary-label">{r.label}</span>
                        <span className={`system-summary-val ${r.dot}`}>{r.count}</span>
                      </div>
                    ));
                  })()}
                </div>
              </div>
              <div className="panel" style={{ flex: 1, minHeight: 0 }}>
                <div className="panel-head">
                  <div className="panel-title"><span className="panel-title-dot" />Audit Console</div>
                  <span className="panel-tag">health probes</span>
                </div>
                <div className="terminal" ref={termRef} style={{ flex: 1 }}>
                  {log.map((l, i) => <div key={i} className={`t-line ${l.cls}`}>{l.text}</div>)}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ══ VIEW: Containment ═══════════════════════════════════════ */}
        {activeNav === 'Containment' && (
          <div className="content-grid">
            <div className="col-left">
              <div className="panel" style={{ flex: 1, minHeight: 0 }}>
                <div className="panel-head">
                  <div className="panel-title"><span className="panel-title-dot red" />Active Containment</div>
                  <span className="panel-tag">{metrics.danger} isolated / flagged</span>
                </div>
                <div className="table-scroll">
                  <table className="proc-table">
                    <thead><tr><th>Process</th><th>PID</th><th>UID</th><th>Zone</th><th>Risk Index</th><th>Action</th></tr></thead>
                    <tbody>
                      {processes.filter(p => p.zone === 'BORDERLANDS' || p.zone === 'QUARANTINED').length === 0 && (
                        <tr><td colSpan={6}><div className="empty-state"><Shield size={22} style={{ color: 'var(--tx-dim)' }} />No active containment — all processes nominal</div></td></tr>
                      )}
                      {processes.filter(p => p.zone === 'BORDERLANDS' || p.zone === 'QUARANTINED').map(p => {
                        const fill = scoreColor(p.score);
                        return (
                          <tr key={p.pid}>
                            <td><span className="proc-comm">{p.comm}</span></td>
                            <td><span className="proc-pid">{p.pid}</span></td>
                            <td><span className="proc-pid">{p.uid}</span></td>
                            <td><span className={`zone-badge ${zoneClass(p.zone)}`}>{p.zone}</span></td>
                            <td>
                              <div className="score-bar-wrap">
                                <div className="score-bar-bg"><div className="score-bar-fill" style={{ width: `${p.score * 100}%`, background: fill, color: fill }} /></div>
                                <span className="score-val" style={{ color: fill }}>{p.score.toFixed(2)}</span>
                              </div>
                            </td>
                            <td>
                              {p.zone === 'QUARANTINED'
                                ? <button className="act-btn restore" onClick={() => restore(p.pid, p.comm)}><Unlock size={10} />Restore</button>
                                : <button className="act-btn isolate" onClick={() => isolate(p.pid, p.comm)}><Lock size={10} />Isolate</button>}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
            <div className="col-right">
              <div className="panel" style={{ flex: 1, minHeight: 0 }}>
                <div className="panel-head">
                  <div className="panel-title"><span className="panel-title-dot red" />Containment History</div>
                  <span className="panel-tag">recent</span>
                </div>
                <div className="terminal" ref={termRef} style={{ flex: 1 }}>
                  {log.filter(l => /isolate|restore|quarantine|WATCHDOG|SIGKILL/i.test(l.text)).map((l, i) => (
                    <div key={i} className={`t-line ${l.cls}`}>{l.text}</div>
                  ))}
                  {log.filter(l => /isolate|restore|quarantine|WATCHDOG|SIGKILL/i.test(l.text)).length === 0 && (
                    <div className="empty-state">No containment actions logged yet</div>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ══ VIEW: Telemetry ═════════════════════════════════════════ */}
        {activeNav === 'Telemetry' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16, flex: 1 }}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 300px', gap: 16, flex: 1, minHeight: 0 }}>
            <div className="panel">
              <div className="panel-head">
                <div className="panel-title"><span className="panel-title-dot" />Zone Distribution — Extended</div>
                <span className="panel-tag">rolling window</span>
              </div>
              <div style={{ height: 340, padding: '12px 8px 16px' }}>
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={chart} margin={{ top: 8, right: 16, left: -16, bottom: 0 }}>
                    <defs>
                      <linearGradient id="gSafe2" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="var(--safe)"  stopOpacity={0.3} />
                        <stop offset="100%" stopColor="var(--safe)" stopOpacity={0} />
                      </linearGradient>
                      <linearGradient id="gSus2" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="var(--warn)"  stopOpacity={0.3} />
                        <stop offset="100%" stopColor="var(--warn)" stopOpacity={0} />
                      </linearGradient>
                      <linearGradient id="gBl2" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="var(--danger)"  stopOpacity={0.35} />
                        <stop offset="100%" stopColor="var(--danger)" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid stroke="rgba(255,255,255,0.05)" strokeDasharray="4 4" />
                    <XAxis dataKey="t" tick={{ fill: 'var(--tx-dim)', fontSize: 10 }} />
                    <YAxis tick={{ fill: 'var(--tx-dim)', fontSize: 10 }} allowDecimals={false} />
                    <Tooltip contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 6, fontSize: 11 }} labelStyle={{ color: 'var(--tx-secondary)' }} itemStyle={{ color: 'var(--tx-primary)' }} />
                    <Area type="monotone" dataKey="safe" name="Safe"        stroke="var(--safe)"  fill="url(#gSafe2)" strokeWidth={2} />
                    <Area type="monotone" dataKey="sus"  name="Suspicious"  stroke="var(--warn)"  fill="url(#gSus2)"  strokeWidth={2} />
                    <Area type="monotone" dataKey="bl"   name="Borderlands" stroke="var(--danger)" fill="url(#gBl2)"  strokeWidth={2} />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>
            <div className="panel">
              <div className="panel-head">
                <div className="panel-title"><span className="panel-title-dot" />Zone Summary</div>
              </div>
              <div style={{ padding: '4px 20px 16px', display: 'flex', flexDirection: 'column' }}>
                {[
                  { label: 'Safe',        dot: 'ok',   count: metrics.safe },
                  { label: 'Suspicious',  dot: metrics.sus > 0 ? 'warn' : '',    count: metrics.sus },
                  { label: 'Danger',      dot: metrics.danger > 0 ? 'bad' : '',  count: metrics.danger },
                ].map(r => (
                  <div className="system-summary-row" key={r.label}>
                    <span className={`summary-dot ${r.dot}`} />
                    <span className="system-summary-label">{r.label}</span>
                    <span className={`system-summary-val ${r.dot}`}>{r.count}</span>
                  </div>
                ))}
              </div>
            </div>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 1fr', gap: 16 }}>
              {[
                {
                  label: 'eBPF Intercept Latency',
                  val: simulated ? '430 ns' : `${metricsData.ebpf_latency_ns} ns`,
                  sub: 'avg over last 1000 events',
                  color: !simulated && metricsData.ebpf_latency_ns > 450 ? 'var(--warn)' : 'var(--tx-primary)'
                },
                {
                  label: 'gRPC Health Probe RTT',
                  val: simulated ? '< 100ms' : (metricsData.grpc_rtt_ms >= 0 ? `${metricsData.grpc_rtt_ms.toFixed(2)} ms` : 'OFFLINE'),
                  sub: 'kba.sock timeout threshold',
                  color: !simulated && metricsData.grpc_rtt_ms < 0 ? 'var(--danger)' : 'var(--tx-primary)'
                },
                {
                  label: 'AADS Consensus Latency',
                  val: simulated ? '< 1ms' : (metricsData.aads_latency_ms > 0 ? `${metricsData.aads_latency_ms.toFixed(2)} ms` : 'OFFLINE'),
                  sub: 'shared memory Arrow IPC',
                  color: !simulated && metricsData.aads_latency_ms === 0 ? 'var(--danger)' : 'var(--tx-primary)'
                },
                {
                  label: 'Event Rate',
                  val: simulated ? '0.0/s' : `${metricsData.events_per_second.toFixed(1)}/s`,
                  sub: 'ingested telemetry events',
                  color: 'var(--tx-primary)'
                },
              ].map(m => (
                <div key={m.label} className="panel">
                  <div style={{ padding: '20px 20px 16px' }}>
                    <div style={{ fontSize: 11, color: 'var(--tx-secondary)', marginBottom: 8 }}>{m.label}</div>
                    <div style={{ fontSize: 28, fontWeight: 700, fontFamily: 'var(--font-mono)', color: m.color, lineHeight: 1 }}>{m.val}</div>
                    <div style={{ fontSize: 10, color: 'var(--tx-dim)', marginTop: 6 }}>{m.sub}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ══ VIEW: Consensus Log ═════════════════════════════════════ */}
        {activeNav === 'Consensus Log' && (
          <div className="content-grid">
            <div className="col-left">
              <div className="panel" style={{ flex: 1, minHeight: 0 }}>
                <div className="panel-head">
                  <div className="panel-title"><span className="panel-title-dot" />AADS Quorum Feed</div>
                  <span className="panel-tag">Judge / Jury / Executor</span>
                </div>
                <div className="terminal" ref={termRef} style={{ flex: 1 }}>
                  {log.filter(l => /\[AADS\]/.test(l.text)).map((l, i) => (
                    <div key={i} className={`t-line ${l.cls}`}>{l.text}</div>
                  ))}
                  {log.filter(l => /\[AADS\]/.test(l.text)).length === 0 && (
                    <div className="empty-state">No quorum votes logged yet — appears when a process is escalated to BORDERLANDS</div>
                  )}
                </div>
              </div>
            </div>
            <div className="col-right">
              <div className="panel" style={{ flexShrink: 0 }}>
                <div className="panel-head">
                  <div className="panel-title"><span className="panel-title-dot" />Verdict Summary</div>
                </div>
                <div style={{ padding: '4px 20px 16px', display: 'flex', flexDirection: 'column' }}>
                  {[
                    { label: 'ISOLATE verdicts', dot: 'bad', count: log.filter(l => /VERDICT: ISOLATE/.test(l.text)).length },
                    { label: 'Quorum requests',  dot: '',    count: log.filter(l => /Quorum vote requested/.test(l.text)).length },
                  ].map(r => (
                    <div className="system-summary-row" key={r.label}>
                      <span className={`summary-dot ${r.dot}`} />
                      <span className="system-summary-label">{r.label}</span>
                      <span className={`system-summary-val ${r.dot}`}>{r.count}</span>
                    </div>
                  ))}
                </div>
              </div>
              <div className="panel" style={{ flex: 1, minHeight: 0 }}>
                <div style={{ padding: 20, fontSize: 12, color: 'var(--tx-secondary)', lineHeight: 1.7 }}>
                  Reflects <code style={{ color: 'var(--tx-primary)' }}>kb-aads</code>'s Judge/Jury consensus
                  round each time a process crosses into BORDERLANDS — Patroller and Hunter votes feed the
                  Judge's verdict, which either escalates to isolation or returns the process to monitoring.
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ══ VIEW: Rogue Management ══════════════════════════════════ */}
        {activeNav === 'Rogue Management' && (
          <div className="content-grid">
            <div className="col-left">
              <div className="panel" style={{ flex: 1, minHeight: 0 }}>
                <div className="panel-head">
                  <div className="panel-title"><span className={`panel-title-dot ${agentsError ? 'red' : 'green'}`} />Live Agent Roster</div>
                  <span className="panel-tag">{agentsError ? 'unreachable' : `${agents.length} registered`}</span>
                </div>
                <div style={{ padding: '4px 20px 8px', fontSize: 11, color: 'var(--tx-secondary)', lineHeight: 1.6 }}>
                  Raw <code style={{ color: 'var(--tx-primary)' }}>SwarmRegistry</code> status via kbd's{' '}
                  <code style={{ color: 'var(--tx-primary)' }}>/api/agents</code> proxy. Does not call{' '}
                  <code style={{ color: 'var(--tx-primary)' }}>JudgeAgent.assess_severity</code> per agent
                  (its liveness check sleeps per-agent — too slow for a page load), so no computed health tier
                  is shown here, only registry status/uptime/error_count.
                </div>
                {agentsError && (
                  <div className="empty-state"><ShieldAlert size={22} style={{ color: 'var(--tx-dim)' }} />{agentsError}<br />Start kb-aads (`python3 main.py`) to populate this.</div>
                )}
                {!agentsError && (
                  <div className="health-list">
                    {agents.length === 0 && <div className="empty-state">No agents registered</div>}
                    {agents.map(a => (
                      <div key={a.agent_id} className="health-item">
                        <div className="health-left">
                          <div className="health-name">{a.agent_id}</div>
                          <div className="health-desc">{a.role} · uptime {a.uptime} · errors {a.error_count}</div>
                        </div>
                        <span className={`health-badge ${a.registry_status === 'active' ? 'ok' : 'offline'}`}>{a.registry_status?.toUpperCase()}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
            <div className="col-right">
              <div className="panel" style={{ flex: 1, minHeight: 0 }}>
                <div className="panel-head">
                  <div className="panel-title"><span className="panel-title-dot yellow" />Health Ladder (reference)</div>
                </div>
                <div className="health-list">
                  {[
                    { name: 'healthy',   desc: 'Normal error-count and liveness window',      status: 'ok' },
                    { name: 'restart',   desc: 'Elevated error_count — stop then re-start()',  status: 'warn' },
                    { name: 'terminate', desc: 'ray.kill + unregister — last resort',           status: 'offline' },
                  ].map(t => (
                    <div key={t.name} className="health-item">
                      <div className="health-left">
                        <div className="health-name">{t.name}</div>
                        <div className="health-desc">{t.desc}</div>
                      </div>
                      <span className={`health-badge ${t.status}`}>TIER</span>
                    </div>
                  ))}
                </div>
                <div style={{ padding: 16, fontSize: 11, color: 'var(--tx-dim)', borderTop: '1px solid var(--border)' }}>
                  These tiers are computed by `enforce_verdict`, not shown live above — see panel note.
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ══ VIEW: Settings ══════════════════════════════════════════ */}
        {activeNav === 'Settings' && (
          <div className="content-grid">
            <div className="col-left">
              <div className="panel" style={{ flexShrink: 0 }}>
                <div className="panel-head">
                  <div className="panel-title"><span className="panel-title-dot" />Connection</div>
                </div>
                <div className="health-list">
                  <div className="health-item">
                    <div className="health-left"><div className="health-name">Data source</div><div className="health-desc">{API_BASE}</div></div>
                    <span
                      className={`live-indicator ${simulated ? 'sim' : 'live'}`}
                      onClick={() => { setSimulated(!simulated); addLog(`[CONSOLE] Backend mode toggled → ${simulated ? 'LIVE' : 'SIMULATION'}`, 'info'); }}
                    >
                      {simulated ? <WifiOff size={11} /> : <Wifi size={11} />}
                      <span className="live-dot" />
                      {simulated ? 'SIMULATION' : 'LIVE FEED'}
                    </span>
                  </div>
                  <div className="health-item">
                    <div className="health-left"><div className="health-name">Operator role</div><div className="health-desc">Fixed for this build — no RBAC yet</div></div>
                    <span className="health-badge ok">OPERATOR</span>
                  </div>
                  <div className="health-item">
                    <div className="health-left"><div className="health-name">Codename</div><div className="health-desc">Build identifier</div></div>
                    <span className="health-badge ok">KRYO</span>
                  </div>
                </div>
              </div>

              <div className="panel" style={{ flexShrink: 0 }}>
                <div className="panel-head">
                  <div className="panel-title"><span className={`panel-title-dot ${policyError ? 'red' : 'green'}`} />Policy Configuration</div>
                  <span className="panel-tag">{policyError ? 'unreachable' : 'live from kbd'}</span>
                </div>
                {policyError && <div className="empty-state">{policyError}</div>}
                {!policyError && policyInfo && (
                  <div className="health-list">
                    <div className="health-item">
                      <div className="health-left"><div className="health-name">Suspicious threshold</div><div className="health-desc">defaults.suspicious — informational only, see policy.go</div></div>
                      <span className="proc-pid">{policyInfo.suspicious_threshold}</span>
                    </div>
                    <div className="health-item">
                      <div className="health-left"><div className="health-name">Borderlands threshold</div><div className="health-desc">defaults.borderlands — informational only</div></div>
                      <span className="proc-pid">{policyInfo.borderlands_threshold}</span>
                    </div>
                    <div className="health-item">
                      <div className="health-left"><div className="health-name">Sensitive paths (operator-added)</div><div className="health-desc">{policyInfo.policy_path}</div></div>
                      <span className="proc-pid">{policyInfo.sensitive_paths_count}</span>
                    </div>
                  </div>
                )}
                <div style={{ padding: 16, display: 'flex', alignItems: 'center', gap: 12, borderTop: '1px solid var(--border)' }}>
                  <button className="act-btn restore" onClick={reloadPolicy}><RefreshCw size={10} />Reload from disk</button>
                  {reloadStatus && <span style={{ fontSize: 11, color: 'var(--tx-secondary)' }}>{reloadStatus}</span>}
                </div>
              </div>
            </div>
            <div className="col-right">
              <div className="panel" style={{ flex: 1, minHeight: 0 }}>
                <div style={{ padding: 20, fontSize: 12, color: 'var(--tx-secondary)', lineHeight: 1.7 }}>
                  Reload calls kbd's <code style={{ color: 'var(--tx-primary)' }}>POST /api/policy/reload</code>,
                  the HTTP-facing equivalent of the existing <code style={{ color: 'var(--tx-primary)' }}>ReloadPolicy</code> gRPC
                  RPC — it re-reads <code style={{ color: 'var(--tx-primary)' }}>policy.yaml</code> from the path
                  kbd was started with and swaps it in atomically. No other settings are persisted or
                  configurable yet — alert thresholds, theme, and notification routing remain unbuilt.
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ══ VIEW: Console ═══════════════════════════════════════════ */}
        {activeNav === 'Console' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16, flex: 1, minHeight: 0 }}>
            <div className="stat-row" style={{ gridTemplateColumns: 'repeat(4, 1fr)' }}>
              {[
                { label: 'Total Lines', count: log.length,                                dot: '' },
                { label: 'Errors',      count: log.filter(l => l.cls === 'err').length,     dot: 'bad' },
                { label: 'Warnings',    count: log.filter(l => l.cls === 'warn').length,    dot: 'warn' },
                { label: 'Confirmed OK',count: log.filter(l => l.cls === 'success').length, dot: 'ok' },
              ].map(s => (
                <div className="stat-card" key={s.label} style={{ flexDirection: 'row', alignItems: 'center', gap: 12 }}>
                  <span className={`summary-dot ${s.dot}`} />
                  <div>
                    <div className="stat-label">{s.label}</div>
                    <div className="stat-value" style={{ fontSize: 20 }}>{s.count}</div>
                  </div>
                </div>
              ))}
            </div>
            <div className="panel" style={{ flex: 1, minHeight: 0 }}>
              <div className="panel-head">
                <div className="panel-title"><span className="panel-title-dot" />Audit Console — Full Feed</div>
                <span className="panel-tag">{log.length} lines</span>
              </div>
              <div className="terminal" ref={termRef} style={{ flex: 1, maxHeight: 'none', height: '100%' }}>
                {log.map((l, i) => <div key={i} className={`t-line ${l.cls}`}>{l.text}</div>)}
              </div>
            </div>
          </div>
        )}

      </main>
    </div>
  );
}
