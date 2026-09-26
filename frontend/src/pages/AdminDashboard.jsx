import React, { useState, useEffect } from 'react';
import { Users, Settings, TrendingDown, Activity, Server, Database, ShieldAlert } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { health } from '../lib/api';

const latencyData = Array.from({ length: 20 }, (_, i) => ({ time: `10:${i < 10 ? '0' : ''}${i}`, ms: Math.random() * 0.5 + 0.1 }));
const mttrData = [
  { month: 'Jan', critical: 12, weak: 20 }, { month: 'Feb', critical: 9, weak: 18 },
  { month: 'Mar', critical: 7, weak: 15 }, { month: 'Apr', critical: 6, weak: 14 },
  { month: 'May', critical: 4, weak: 12 }, { month: 'Jun', critical: 4.2, weak: 12.5 }
];
const auditLog = [
  { id: 1, user: 'admin', action: 'Exported Compliance Report', time: '2 mins ago' },
  { id: 2, user: 'analyst', action: 'Uploaded external-smtp.pcap', time: '1 hour ago' },
  { id: 3, user: 'auditor', action: 'Viewed NIST SP 800-52r2 Checklist', time: '3 hours ago' },
];

export default function AdminDashboard() {
  const [activeTab, setActiveTab] = useState('system');
  const [apiHealth, setApiHealth] = useState(null);
  const [aiSensitivity, setAiSensitivity] = useState(75);
  const [strictMode, setStrictMode] = useState(false);
  const [users, setUsers] = useState(['admin', 'analyst', 'auditor']);

  useEffect(() => {
    let mounted = true;
    health().then(h => {
      if (mounted) setApiHealth(h);
    });
    return () => { mounted = false; };
  }, []);

  return (
    <div className="space-y-6 animate-fade-in pb-10">
      <div className="bg-surface p-6 rounded-xl border border-line shadow-sm flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <h2 className="text-[24px] font-display font-bold text-ink mb-1">Platform Administration</h2>
          <p className="text-ink-2 text-[14px]">Keep the system running, manage users, and tune the security engine.</p>
        </div>
        {apiHealth?.engine && (
          <div className="flex items-center gap-3 bg-surface-2 px-4 py-2 rounded-lg border border-line">
            <span className="relative flex h-3 w-3"><span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-ok opacity-40"></span><span className="relative inline-flex rounded-full h-3 w-3 bg-ok"></span></span>
            <span className="text-sm font-bold text-ink uppercase tracking-wider">{apiHealth.engine} v{apiHealth.engineVersion}</span>
          </div>
        )}
      </div>

      <div className="flex border-b border-line overflow-x-auto custom-scrollbar">
        {[
          { id: 'system', icon: Activity, label: 'System Health' },
          { id: 'rules', icon: Settings, label: 'Rule Engine Tuning' },
          { id: 'users', icon: Users, label: 'User & Identity' },
          { id: 'metrics', icon: TrendingDown, label: 'Remediation (MTTR)' }
        ].map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`px-4 py-3 text-sm font-bold uppercase tracking-wider whitespace-nowrap transition-colors border-b-2 ${activeTab === tab.id ? 'text-accent border-accent' : 'text-ink-2 border-transparent hover:text-ink hover:border-line'}`}
          >
            <div className="flex items-center gap-2"><tab.icon size={16}/> {tab.label}</div>
          </button>
        ))}
      </div>

      {activeTab === 'system' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="bg-surface p-5 rounded-xl border border-line shadow-sm flex items-center gap-4">
              <div className="p-3 bg-accent-soft text-accent rounded-lg"><Server size={24}/></div>
              <div><div className="text-xs font-bold uppercase tracking-wider text-ink-3">CPU Usage</div><div className="text-2xl font-display font-bold text-ink">14%</div></div>
            </div>
            <div className="bg-surface p-5 rounded-xl border border-line shadow-sm flex items-center gap-4">
              <div className="p-3 bg-info-soft text-info rounded-lg"><Activity size={24}/></div>
              <div><div className="text-xs font-bold uppercase tracking-wider text-ink-3">RAM Usage</div><div className="text-2xl font-display font-bold text-ink">4.2 GB <span className="text-sm font-normal text-ink-3">/ 16 GB</span></div></div>
            </div>
            <div className="bg-surface p-5 rounded-xl border border-line shadow-sm flex items-center gap-4">
              <div className="p-3 bg-warn-soft text-warn rounded-lg"><Database size={24}/></div>
              <div><div className="text-xs font-bold uppercase tracking-wider text-ink-3">DB Storage</div><div className="text-2xl font-display font-bold text-ink">1.8 TB <span className="text-sm font-normal text-ink-3">/ 5 TB</span></div></div>
            </div>
          </div>
          
          <div className="bg-surface rounded-xl border border-line p-6 shadow-sm">
            <h3 className="font-bold text-ink mb-6 text-sm uppercase tracking-wider">Python Engine Processing Latency</h3>
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={latencyData} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
                  <defs>
                    <linearGradient id="colorMs" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="var(--color-accent)" stopOpacity={0.8}/>
                      <stop offset="95%" stopColor="var(--color-accent)" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="var(--color-line)" />
                  <XAxis dataKey="time" stroke="var(--color-ink-3)" tick={{fontSize: 11}} />
                  <YAxis stroke="var(--color-ink-3)" tick={{fontSize: 11}} />
                  <Tooltip contentStyle={{ backgroundColor: 'var(--color-surface)', borderColor: 'var(--color-line)' }} />
                  <Area type="monotone" dataKey="ms" stroke="var(--color-accent)" fillOpacity={1} fill="url(#colorMs)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      )}

      {activeTab === 'rules' && (
        <div className="bg-surface rounded-xl border border-line p-6 shadow-sm space-y-6">
          <h3 className="font-bold text-ink text-sm uppercase tracking-wider">Engine Policy Overrides & Tuning</h3>
          
          <div className="flex items-center justify-between p-5 border border-line rounded-lg bg-surface-2 shadow-sm">
            <div>
              <div className="font-bold text-ink text-[15px]">Force TLS 1.3 Strict Mode</div>
              <div className="text-[13px] text-ink-2 mt-1">Treats TLS 1.2 as a vulnerability. Marks all non-TLS 1.3 traffic as Medium severity.</div>
            </div>
            <label className="relative inline-flex items-center cursor-pointer" onClick={() => setStrictMode(!strictMode)}>
              <input type="checkbox" className="sr-only peer" checked={strictMode} readOnly />
              <div className="w-11 h-6 bg-line peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-accent"></div>
            </label>
          </div>

          <div className="p-5 border border-line rounded-lg bg-surface-2 shadow-sm">
            <div className="flex justify-between items-start mb-4">
              <div>
                <div className="font-bold text-ink text-[15px]">AI Isolation Forest Sensitivity</div>
                <div className="text-[13px] text-ink-2 mt-1">Adjust the anomaly threshold for machine learning verdicts.</div>
              </div>
              <div className="font-mono text-accent font-bold bg-accent-soft px-3 py-1 rounded">{aiSensitivity}%</div>
            </div>
            <input 
              type="range" min="0" max="100" value={aiSensitivity} onChange={(e) => setAiSensitivity(e.target.value)}
              className="w-full h-2 bg-line rounded-lg appearance-none cursor-pointer accent-accent"
            />
            <div className="flex justify-between text-xs text-ink-3 mt-2 font-bold uppercase tracking-wider">
              <span>Low (Fewer FPs)</span><span>Medium</span><span>High (Catch All)</span>
            </div>
          </div>
        </div>
      )}

      {activeTab === 'users' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="bg-surface rounded-xl border border-line p-6 shadow-sm">
            <div className="flex justify-between items-center mb-6">
              <h3 className="font-bold text-ink text-sm uppercase tracking-wider">Active Accounts</h3>
              <button className="bg-accent text-surface px-3 py-1.5 rounded text-xs font-bold uppercase tracking-wider hover:bg-accent/90">Create User</button>
            </div>
            <table className="w-full text-sm text-left">
              <thead className="text-[11px] text-ink-3 uppercase bg-surface-2 border-b border-line tracking-wider">
                <tr><th className="px-4 py-3">Username</th><th className="px-4 py-3">Role</th><th className="px-4 py-3">Actions</th></tr>
              </thead>
              <tbody>
                {users.map((u) => (
                  <tr key={u} className="border-b border-line last:border-0 hover:bg-surface-2/50 transition-colors">
                    <td className="px-4 py-3 font-medium text-ink">{u}</td>
                    <td className="px-4 py-3 font-mono text-[11px] text-ink-2 bg-surface px-2 rounded">ROLE_{u === 'analyst' ? 'SOC_ANALYST' : u.toUpperCase()}</td>
                    <td className="px-4 py-3">
                      <button 
                        onClick={() => setUsers(users.filter(user => user !== u))}
                        className="text-crit text-[11px] font-bold uppercase hover:underline"
                      >
                        Revoke
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          
          <div className="bg-surface rounded-xl border border-line p-6 shadow-sm">
            <h3 className="font-bold text-ink mb-6 text-sm uppercase tracking-wider">Audit Log</h3>
            <div className="space-y-4">
              {auditLog.map(log => (
                <div key={log.id} className="flex gap-4 p-3 bg-surface-2 rounded-lg border border-line items-center">
                  <div className="p-2 bg-surface-3 rounded text-ink-2"><ShieldAlert size={16}/></div>
                  <div className="flex-1">
                    <div className="text-[13px] font-medium text-ink">{log.action}</div>
                    <div className="text-[11px] text-ink-3 font-mono mt-1">By {log.user} · {log.time}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {activeTab === 'metrics' && (
        <div className="bg-surface rounded-xl border border-line p-6 shadow-sm">
          <h3 className="font-bold text-ink mb-6 text-sm uppercase tracking-wider">Mean Time To Remediate (MTTR) Trend</h3>
          <div className="h-[300px]">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={mttrData} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorCrit" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="var(--color-crit)" stopOpacity={0.8}/><stop offset="95%" stopColor="var(--color-crit)" stopOpacity={0}/></linearGradient>
                  <linearGradient id="colorWeak" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="var(--color-high)" stopOpacity={0.8}/><stop offset="95%" stopColor="var(--color-high)" stopOpacity={0}/></linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="var(--color-line)" />
                <XAxis dataKey="month" stroke="var(--color-ink-3)" tick={{fontSize: 11}} />
                <YAxis stroke="var(--color-ink-3)" tick={{fontSize: 11}} />
                <Tooltip contentStyle={{ backgroundColor: 'var(--color-surface)', borderColor: 'var(--color-line)' }} />
                <Area type="monotone" dataKey="critical" stroke="var(--color-crit)" fillOpacity={1} fill="url(#colorCrit)" name="Critical Vulns (Days)" />
                <Area type="monotone" dataKey="weak" stroke="var(--color-high)" fillOpacity={1} fill="url(#colorWeak)" name="Weak Ciphers (Days)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}
    </div>
  );
}
