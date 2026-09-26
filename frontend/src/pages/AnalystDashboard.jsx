import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import Upload from './Upload';
import { Activity, ShieldAlert, Cpu, ArrowRight } from 'lucide-react';
import { listCaptures, getCapture } from '../lib/api';
import { Spinner } from '../components/ui';

export default function AnalystDashboard() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    async function load() {
      try {
        const capturesList = await listCaptures();
        const successful = capturesList.filter(c => c.status === 'COMPLETED').slice(0, 5); // check last 5 captures
        
        let foundAlerts = [];
        for (const c of successful) {
          const detail = await getCapture(c.id);
          const r = detail.report;
          if (!r) continue;
          
          for (const s of (r.sessions || [])) {
            // Find critical/high findings
            for (const f of (s.findings || [])) {
              if (f.severity === 'critical' || f.severity === 'high') {
                foundAlerts.push({
                  id: `${c.id}-${s.tcp_stream}-${f.rule_id}`,
                  captureId: c.id,
                  stream: s.tcp_stream,
                  type: f.title,
                  target: `${s.client?.ip} → ${s.server?.ip}`,
                  time: new Date(c.uploadedAt || c.capturedAt || Date.now()).toLocaleString(),
                  severity: f.severity,
                  score: s.ml?.risk_score || 'N/A'
                });
              }
            }
            // Find ML anomalies
            if (s.ml?.anomaly) {
              foundAlerts.push({
                id: `${c.id}-${s.tcp_stream}-ml-anomaly`,
                captureId: c.id,
                stream: s.tcp_stream,
                type: 'Isolation Forest Anomaly',
                target: `${s.client?.ip} → ${s.server?.ip}`,
                time: new Date(c.uploadedAt || c.capturedAt || Date.now()).toLocaleString(),
                severity: 'warn',
                score: s.ml.risk_score || 'N/A'
              });
            }
          }
        }
        
        if (active) {
          setAlerts(foundAlerts.slice(0, 8)); // Top 8 alerts
          setLoading(false);
        }
      } catch (e) {
        if (active) setLoading(false);
      }
    }
    load();
    return () => { active = false; };
  }, []);

  return (
    <div className="space-y-8 animate-fade-in pb-10">
      <div className="bg-surface p-6 rounded-xl border border-line shadow-sm flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <h2 className="text-[24px] font-display font-bold text-ink mb-1">SOC Analyst Workspace</h2>
          <p className="text-ink-2 text-[14px]">Investigate alerts, upload evidence, and find the exact packet where the attack happened.</p>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        <div className="xl:col-span-2 space-y-6">
          <Upload />
          
          <div className="bg-surface rounded-xl border border-line p-6 shadow-sm">
             <h3 className="font-bold flex items-center gap-2 text-ink mb-4 text-sm uppercase tracking-wider">
              <Cpu size={18} className="text-accent" /> Recent Evidence
            </h3>
             <div className="text-[14px] text-ink-2 leading-relaxed">
                Use the <Link to="/investigations" className="text-accent hover:underline font-bold">Investigations</Link> tab to view detailed packet-level evidence, stream IDs, and hex data for past jobs. When an alert triggers in the feed on the right, you can drill down to the exact session to view the Protocol State Machine and packet data.
             </div>
          </div>
        </div>
        
        <div className="space-y-6">
          <div className="bg-surface rounded-xl border border-line p-6 shadow-sm flex flex-col h-full">
            <h3 className="font-bold flex items-center justify-between text-ink mb-6 text-sm uppercase tracking-wider">
              <div className="flex items-center gap-2"><Activity size={18} className="text-crit" /> Live Anomaly Feed</div>
              <span className="bg-crit-soft text-crit px-2 py-0.5 rounded text-[10px] font-bold">Triage Inbox</span>
            </h3>
            
            <div className="space-y-3 flex-1">
              {loading ? (
                <div className="flex justify-center py-10"><Spinner label="Scanning recent PCAPs..." /></div>
              ) : alerts.length === 0 ? (
                <div className="text-center text-ink-3 text-sm py-10 bg-surface-2 rounded-lg border border-line border-dashed">
                  No high-priority alerts found in recent captures.
                </div>
              ) : (
                alerts.map((alert, i) => (
                  <Link key={i} to={`/report/${alert.captureId}/sessions/${alert.stream}`} className="block group no-underline">
                    <div className="text-sm p-3 border border-line rounded-lg bg-surface-2 flex flex-col gap-2 transition-all hover:border-accent hover:shadow-soft">
                      <div className="flex items-start justify-between gap-2">
                        <div className="flex items-start gap-2">
                          <ShieldAlert size={16} className={`mt-0.5 shrink-0 text-${alert.severity === 'critical' ? 'crit' : alert.severity === 'high' ? 'warn' : 'accent'}`} />
                          <div>
                            <div className="text-ink font-bold group-hover:text-accent transition-colors leading-tight mb-1">{alert.type}</div>
                            <div className="font-mono text-[11px] text-ink-2">{alert.target}</div>
                          </div>
                        </div>
                      </div>
                      <div className="flex justify-between items-center mt-1 pt-2 border-t border-line/50">
                        <span className="text-ink-3 text-[11px]">{alert.time}</span>
                        <div className="flex items-center gap-2">
                          <span className="text-[10px] font-bold uppercase tracking-wider text-ink-3">AI Score: <span className="text-ink">{alert.score}</span></span>
                          <ArrowRight size={14} className="text-ink-3 group-hover:text-accent transition-colors" />
                        </div>
                      </div>
                    </div>
                  </Link>
                ))
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
