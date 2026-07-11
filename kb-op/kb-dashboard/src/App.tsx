import { useState, useEffect, useMemo, useRef } from 'react';
import { 
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer
} from 'recharts';
import { 
  AlertTriangle, Terminal, RefreshCw, Cpu, Activity, Database, Lock, Unlock
} from 'lucide-react';
import './App.css';

// Types
interface Process {
  pid: number;
  ppid: number;
  comm: string;
  uid: number;
  score: number;
  zone: 'SAFE' | 'SUSPICIOUS' | 'BORDERLANDS' | 'QUARANTINED';
  isAADSQuorum?: boolean;
}

interface Alert {
  alertId: string;
  alertType: string;
  pid: number;
  comm: string;
  severity: 'INFO' | 'WARNING' | 'CRITICAL';
  timestamp: string;
  evidence: string[];
}

interface ChartPoint {
  time: string;
  safe: number;
  suspicious: number;
  borderlands: number;
}

export default function App() {
  const [isSimulated, setIsSimulated] = useState<boolean>(true);
  const [processes, setProcesses] = useState<Process[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [logLines, setLogLines] = useState<string[]>([]);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedZone, setSelectedZone] = useState<string>('ALL');
  const [chartData, setChartData] = useState<ChartPoint[]>([]);
  
  const terminalEndRef = useRef<HTMLDivElement>(null);

  // Initialize process states
  useEffect(() => {
    const initialProcesses: Process[] = [
      { pid: 1, ppid: 0, comm: 'systemd', uid: 0, score: 0.05, zone: 'SAFE' },
      { pid: 450, ppid: 1, comm: 'sshd', uid: 0, score: 0.12, zone: 'SAFE' },
      { pid: 812, ppid: 1, comm: 'postgres', uid: 70, score: 0.08, zone: 'SAFE' },
      { pid: 915, ppid: 1, comm: 'nginx', uid: 33, score: 0.15, zone: 'SAFE' },
      { pid: 1040, ppid: 915, comm: 'nginx worker', uid: 33, score: 0.18, zone: 'SAFE' },
      { pid: 1205, ppid: 1, comm: 'kbd', uid: 0, score: 0.02, zone: 'SAFE' },
      { pid: 1210, ppid: 1, comm: 'kb-checker', uid: 0, score: 0.01, zone: 'SAFE' },
      { pid: 3102, ppid: 450, comm: 'bash', uid: 1000, score: 0.35, zone: 'SAFE' }
    ];
    setProcesses(initialProcesses);

    // Initial logs
    setLogLines([
      `[${new Date().toLocaleTimeString()}] [CORE] eBPF telemetry hooks loaded successfully.`,
      `[${new Date().toLocaleTimeString()}] [WATCHDOG] kb-checker safety daemon active.`,
      `[${new Date().toLocaleTimeString()}] [CONTROL] kbd Go daemon listening on /run/kb/kba.sock.`,
      `[${new Date().toLocaleTimeString()}] [HEALTH] standard gRPC check: SERVING`
    ]);

    // Initial chart data
    const initialChart: ChartPoint[] = Array.from({ length: 8 }, (_, i) => ({
      time: `11:${40 + i * 2}`,
      safe: 8 + Math.floor(Math.random() * 2),
      suspicious: Math.floor(Math.random() * 2),
      borderlands: 0
    }));
    setChartData(initialChart);
  }, []);

  // Auto-scroll diagnostics console
  useEffect(() => {
    terminalEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logLines]);

  // Simulated Telemetry & Attack Event Loop
  useEffect(() => {
    if (!isSimulated) return;

    const interval = setInterval(() => {
      // 1. Randomly update metrics or spawn benign process
      setProcesses(prev => {
        let updated = [...prev];
        
        // Maybe spawn a process
        if (Math.random() > 0.65 && updated.length < 15) {
          const names = ['curl', 'git', 'node', 'python', 'sudo', 'grep', 'awk', 'docker'];
          const randomName = names[Math.floor(Math.random() * names.length)];
          const newPid = 4000 + Math.floor(Math.random() * 2000);
          const ppid = updated[Math.floor(Math.random() * updated.length)].pid;
          updated.push({
            pid: newPid,
            ppid,
            comm: randomName,
            uid: Math.random() > 0.5 ? 1000 : 0,
            score: parseFloat((Math.random() * 0.25).toFixed(2)),
            zone: 'SAFE'
          });
          setLogLines(logs => [...logs, `[${new Date().toLocaleTimeString()}] [CORE] sched_process_fork: PID ${newPid} (${randomName}) spawned.`]);
        }

        // Maybe trigger suspicious activity on bash or curl
        updated = updated.map(p => {
          if (p.zone === 'SAFE' && (p.comm === 'bash' || p.comm === 'curl') && Math.random() > 0.85) {
            setLogLines(logs => [...logs, `[${new Date().toLocaleTimeString()}] [SENSOR] Privilege anomaly detected on PID ${p.pid}.`]);
            return { ...p, score: 0.68, zone: 'SUSPICIOUS' };
          }
          // Escalate suspicious to borderlands
          if (p.zone === 'SUSPICIOUS' && Math.random() > 0.7) {
            // Trigger AADS voting consensus
            setLogLines(logs => [
              ...logs,
              `[${new Date().toLocaleTimeString()}] [AADS] Quorum voting requested for anomaly on PID ${p.pid} (${p.comm}).`,
              `[${new Date().toLocaleTimeString()}] [AADS] [VOTE] Patroller: COMPROMISED (92% confidence)`,
              `[${new Date().toLocaleTimeString()}] [AADS] [VOTE] Hunter: COMPROMISED (89% confidence)`,
              `[${new Date().toLocaleTimeString()}] [AADS] [VERDICT] Quorum reached (COMPROMISED). Triggering isolation.`
            ]);
            
            // Dispatch Alert
            const alertId = `alt-${p.pid}-${Date.now()}`;
            const newAlert: Alert = {
              alertId,
              alertType: 'BORDERLANDS_ENTRY',
              pid: p.pid,
              comm: p.comm,
              severity: 'CRITICAL',
              timestamp: new Date().toLocaleTimeString(),
              evidence: ['ema_score=92.4', 'privilege_escalation_detected', 'namespace_drift']
            };
            setAlerts(al => [newAlert, ...al]);
            
            return { ...p, score: 0.94, zone: 'BORDERLANDS', isAADSQuorum: true };
          }
          return p;
        });

        // Auto-terminate borderlands processes after a short wait (mimicking active watchdog SIGKILL)
        updated.forEach(p => {
          if (p.zone === 'BORDERLANDS' && p.isAADSQuorum) {
            setTimeout(() => {
              setProcesses(current => {
                const isExists = current.some(cp => cp.pid === p.pid && cp.zone === 'BORDERLANDS');
                if (!isExists) return current;
                
                setLogLines(logs => [
                  ...logs,
                  `[${new Date().toLocaleTimeString()}] [WATCHDOG] Integrity violation resolved.`,
                  `[${new Date().toLocaleTimeString()}] [WATCHDOG] [QUARANTINE] Layer 1: SIGKILL sent to PID ${p.pid}.`,
                  `[${new Date().toLocaleTimeString()}] [CORE] sched_process_exit: PID ${p.pid} evicted.`
                ]);
                return current.filter(cp => cp.pid !== p.pid);
              });
            }, 3500);
          }
        });

        return updated;
      });

      // 2. Perform periodic safety audits (Rust watchdog ticks)
      if (Math.random() > 0.75) {
        setLogLines(logs => [
          ...logs,
          `[${new Date().toLocaleTimeString()}] [HEALTH] Performing gRPC availability audit over UDS: /run/kb/kba.sock...`,
          `[${new Date().toLocaleTimeString()}] [HEALTH] Control plane gRPC check: SERVING (100ms deadline)`,
          `[${new Date().toLocaleTimeString()}] [WATCHDOG] BPF map state integrity audit: OK (0 tampered links)`
        ]);
      }

      // 3. Update Chart Statistics
      setChartData(prev => {
        const nextTime = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        const counts = processes.reduce((acc, curr) => {
          if (curr.zone === 'SAFE') acc.safe++;
          else if (curr.zone === 'SUSPICIOUS') acc.suspicious++;
          else if (curr.zone === 'BORDERLANDS' || curr.zone === 'QUARANTINED') acc.borderlands++;
          return acc;
        }, { safe: 0, suspicious: 0, borderlands: 0 });

        const nextPoints = [...prev.slice(1), {
          time: nextTime,
          safe: counts.safe,
          suspicious: counts.suspicious,
          borderlands: counts.borderlands
        }];
        return nextPoints;
      });

    }, 4000);

    return () => clearInterval(interval);
  }, [processes, isSimulated]);

  // Filtered process listing
  const filteredProcesses = useMemo(() => {
    return processes.filter(p => {
      const matchesSearch = p.comm.toLowerCase().includes(searchQuery.toLowerCase()) || p.pid.toString().includes(searchQuery);
      const matchesZone = selectedZone === 'ALL' || p.zone === selectedZone;
      return matchesSearch && matchesZone;
    });
  }, [processes, searchQuery, selectedZone]);

  // Isolate a process manually (Operator action)
  const handleIsolate = (pid: number, comm: string) => {
    setProcesses(prev => 
      prev.map(p => p.pid === pid ? { ...p, zone: 'QUARANTINED', score: 0.99 } : p)
    );
    const alertId = `alt-${pid}-${Date.now()}`;
    const newAlert: Alert = {
      alertId,
      alertType: 'MANUAL_QUARANTINE',
      pid,
      comm,
      severity: 'CRITICAL',
      timestamp: new Date().toLocaleTimeString(),
      evidence: ['manual_operator_isolation', 'force_quarantine_level_4']
    };
    setAlerts(al => [newAlert, ...al]);
    setLogLines(logs => [
      ...logs,
      `[${new Date().toLocaleTimeString()}] [OPERATOR] Manual isolation requested for PID ${pid} (${comm}).`,
      `[${new Date().toLocaleTimeString()}] [CONTAINMENT] Applying Layer 3 UDS Network dropping rule.`
    ]);
  };

  // Restore quarantined process
  const handleRestore = (pid: number, comm: string) => {
    setProcesses(prev => 
      prev.map(p => p.pid === pid ? { ...p, zone: 'SAFE', score: 0.05 } : p)
    );
    setLogLines(logs => [
      ...logs,
      `[${new Date().toLocaleTimeString()}] [OPERATOR] Restoring PID ${pid} (${comm}) to SAFE zone.`,
      `[${new Date().toLocaleTimeString()}] [CONTAINMENT] Evicting isolation rules for PID ${pid}.`
    ]);
  };

  // Key metrics
  const activePidsCount = processes.length;
  const criticalAlertsCount = alerts.filter(a => a.severity === 'CRITICAL').length;

  return (
    <div className="app-container">
      {/* Header */}
      <header className="app-header">
        <div className="brand-section">
          <div className="brand-logo"></div>
          <div className="brand-text">
            <h1>Kernel Borderlands</h1>
            <p>Control Core Operator Console // v1.2.0</p>
          </div>
        </div>

        <div className="header-controls">
          <div className={`system-status ${isSimulated ? 'simulated' : ''}`}>
            <span className="status-dot"></span>
            {isSimulated ? 'SIMULATED FEED' : 'LIVE BACKEND'}
          </div>

          <button 
            className="toggle-button" 
            onClick={() => {
              setIsSimulated(!isSimulated);
              setLogLines(logs => [
                ...logs,
                `[${new Date().toLocaleTimeString()}] [CONSOLE] Toggled backend connector mode.`,
              ]);
            }}
          >
            <RefreshCw size={14} style={{ marginRight: '8px', verticalAlign: 'middle' }} />
            {isSimulated ? 'Connect Live UDS' : 'Use Simulation'}
          </button>
        </div>
      </header>

      {/* Metrics Row */}
      <section className="metrics-row">
        <div className="metric-box">
          <div className="metric-label">
            <Cpu size={14} style={{ marginRight: '6px', verticalAlign: 'middle' }} />
            Active Tracked PIDs
          </div>
          <div className="metric-value">{activePidsCount}</div>
        </div>
        <div className="metric-box">
          <div className="metric-label">
            <Activity size={14} style={{ marginRight: '6px', verticalAlign: 'middle' }} />
            eBPF Intercept Latency
          </div>
          <div className="metric-value highlight-safe">420ns</div>
        </div>
        <div className="metric-box">
          <div className="metric-label">
            <Database size={14} style={{ marginRight: '6px', verticalAlign: 'middle' }} />
            L1 Memory Cache Status
          </div>
          <div className="metric-value highlight-safe">RESTORED</div>
        </div>
        <div className="metric-box">
          <div className="metric-label">
            <AlertTriangle size={14} style={{ marginRight: '6px', verticalAlign: 'middle' }} />
            Active Alerts
          </div>
          <div className={`metric-value ${criticalAlertsCount > 0 ? 'highlight-alert' : ''}`}>
            {criticalAlertsCount}
          </div>
        </div>
      </section>

      {/* Main Grid */}
      <main className="dashboard-grid">
        {/* Left Column: Diagnostics, Health, Swarm */}
        <div className="side-column-left">
          {/* Safety Watchdog */}
          <div className="panel-card accent-safe">
            <div className="panel-header">
              <h2>Watchdog Services</h2>
              <span className="panel-subtitle">Safety & Health checks</span>
            </div>
            <div className="status-list">
              <div className="status-item">
                <div className="status-info">
                  <span className="status-title">kb-core (eBPF Sensor)</span>
                  <span className="status-desc">Ring 0 syscall interception</span>
                </div>
                <span className="status-badge healthy">ACTIVE</span>
              </div>
              <div className="status-item">
                <div className="status-info">
                  <span className="status-title">kbd (Go Control Plane)</span>
                  <span className="status-desc">IPC socket & SQLite store</span>
                </div>
                <span className="status-badge healthy">ACTIVE</span>
              </div>
              <div className="status-item">
                <div className="status-info">
                  <span className="status-title">kb-checker (Rust Safety)</span>
                  <span className="status-desc">Hard fallback containment locks</span>
                </div>
                <span className="status-badge healthy">ACTIVE</span>
              </div>
              <div className="status-item">
                <div className="status-info">
                  <span className="status-title">AADS Agent Swarm</span>
                  <span className="status-desc">ZeroMQ & Ray consensus loops</span>
                </div>
                <span className="status-badge healthy">ACTIVE</span>
              </div>
            </div>
          </div>

          {/* Diagnostics Console */}
          <div className="panel-card" style={{ flex: 1 }}>
            <div className="panel-header">
              <h2>Safety Audit Console</h2>
              <Terminal size={14} style={{ color: 'var(--text-secondary)' }} />
            </div>
            <div className="terminal-console">
              {logLines.map((line, idx) => (
                <div 
                  key={idx} 
                  className={`terminal-line ${
                    line.includes('[AADS]') ? 'cmd' : 
                    line.includes('[WATCHDOG]') ? 'alert' : 
                    line.includes('SERVING') ? 'success' : ''
                  }`}
                >
                  {line}
                </div>
              ))}
              <div ref={terminalEndRef} />
            </div>
          </div>
        </div>

        {/* Center Column: Swarm Visualizer & Process Table */}
        <div className="center-column">
          {/* Swarm Visualizer */}
          <div className="panel-card">
            <div className="panel-header">
              <h2>Autonomous Swarm Visualizer</h2>
              <span className="panel-subtitle">Ray shared-memory process nodes</span>
            </div>
            <div className="swarm-visualizer-container">
              <div className="visualization-grid"></div>
              {processes.map((p) => {
                // Determine layout coordinate based on PID and status
                const randomSeedX = (p.pid * 13) % 80;
                const randomSeedY = (p.pid * 19) % 70;
                const left = 10 + randomSeedX;
                const top = 15 + randomSeedY;

                return (
                  <div
                    key={p.pid}
                    className={`swarm-particle ${p.zone.toLowerCase()}`}
                    style={{ left: `${left}%`, top: `${top}%` }}
                    data-comm={`${p.comm} (${p.pid})`}
                  />
                );
              })}
            </div>
          </div>

          {/* Process Table */}
          <div className="panel-card" style={{ flex: 1 }}>
            <div className="panel-header">
              <h2>Tracked Processes</h2>
              <span className="panel-subtitle">L1 Cache states</span>
            </div>

            {/* Filter controls */}
            <div className="filter-bar">
              <input
                type="text"
                className="search-input"
                placeholder="Search by PID or process name..."
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
              />
              <select
                className="select-input"
                value={selectedZone}
                onChange={e => setSelectedZone(e.target.value)}
              >
                <option value="ALL">All Zones</option>
                <option value="SAFE">Safe</option>
                <option value="SUSPICIOUS">Suspicious</option>
                <option value="BORDERLANDS">Borderlands</option>
                <option value="QUARANTINED">Quarantined</option>
              </select>
            </div>

            {/* Table */}
            <div className="table-wrapper">
              <table className="process-table">
                <thead>
                  <tr>
                    <th>Process Name</th>
                    <th>PID</th>
                    <th>PPID</th>
                    <th>UID</th>
                    <th>Zone</th>
                    <th>Risk Index</th>
                    <th>Mitigation</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredProcesses.map(p => (
                    <tr key={p.pid}>
                      <td className="process-comm">{p.comm}</td>
                      <td className="process-pid">{p.pid}</td>
                      <td className="process-pid">{p.ppid}</td>
                      <td className="process-pid">{p.uid}</td>
                      <td>
                        <span className={`zone-badge ${p.zone.toLowerCase()}`}>
                          {p.zone}
                        </span>
                      </td>
                      <td className={`process-score ${p.zone.toLowerCase()}`}>
                        {p.score}
                      </td>
                      <td>
                        {p.zone === 'QUARANTINED' ? (
                          <button 
                            className="action-btn unblock"
                            onClick={() => handleRestore(p.pid, p.comm)}
                          >
                            <Unlock size={11} style={{ marginRight: '4px', verticalAlign: 'middle' }} />
                            Evict
                          </button>
                        ) : (
                          <button 
                            className="action-btn"
                            onClick={() => handleIsolate(p.pid, p.comm)}
                          >
                            <Lock size={11} style={{ marginRight: '4px', verticalAlign: 'middle' }} />
                            Isolate
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Right Column: Threat Chart & Alerts Log */}
        <div className="side-column-right">
          {/* Threat Distribution Chart */}
          <div className="panel-card">
            <div className="panel-header">
              <h2>Threat Zone Distribution</h2>
              <span className="panel-subtitle">Real-time counts</span>
            </div>
            <div className="chart-container">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart
                  data={chartData}
                  margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
                >
                  <XAxis dataKey="time" stroke="#545b6b" fontSize={10} />
                  <YAxis stroke="#545b6b" fontSize={10} />
                  <Tooltip 
                    contentStyle={{ 
                      background: '#0d0e16', 
                      borderColor: 'rgba(255, 255, 255, 0.08)',
                      borderRadius: '6px',
                      fontSize: '11px',
                      color: '#f1f3f9'
                    }} 
                  />
                  <Area type="monotone" dataKey="safe" stackId="1" stroke="var(--color-safe)" fill="var(--color-safe)" fillOpacity={0.1} />
                  <Area type="monotone" dataKey="suspicious" stackId="1" stroke="var(--color-suspicious)" fill="var(--color-suspicious)" fillOpacity={0.1} />
                  <Area type="monotone" dataKey="borderlands" stackId="1" stroke="var(--color-borderlands)" fill="var(--color-borderlands)" fillOpacity={0.1} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Active Alerts */}
          <div className="panel-card accent-borderlands" style={{ flex: 1 }}>
            <div className="panel-header">
              <h2>Critical Threats Feed</h2>
              <span className="panel-subtitle">Real-time alerts logs</span>
            </div>
            <div className="alert-feed">
              {alerts.length === 0 ? (
                <div style={{ color: 'var(--text-dim)', textAlign: 'center', marginTop: '40px', fontSize: '12px' }}>
                  No active threat vectors detected.
                </div>
              ) : (
                alerts.map(a => (
                  <div key={a.alertId} className={`alert-card ${a.alertType === 'MANUAL_QUARANTINE' ? 'critical' : ''}`}>
                    <div className="alert-card-header">
                      <span className="alert-type" style={{ color: a.alertType === 'MANUAL_QUARANTINE' ? 'var(--color-quarantined)' : 'var(--color-borderlands)' }}>
                        {a.alertType}
                      </span>
                      <span className="alert-time">{a.timestamp}</span>
                    </div>
                    <div className="alert-details">
                      PID <strong>{a.pid}</strong> (<strong>{a.comm}</strong>) entered <strong>BORDERLANDS</strong>.
                    </div>
                    <div className="alert-evidence">
                      {a.evidence.map((ev, i) => (
                        <span key={i} className="evidence-tag">{ev}</span>
                      ))}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}


