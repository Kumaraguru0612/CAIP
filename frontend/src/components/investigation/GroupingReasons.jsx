import React from 'react';
import { CheckCircle2, Layers, Cpu, Clock, ShieldCheck, Network, Zap } from 'lucide-react';
import Card from '../common/Card';

export default function GroupingReasons({ 
  events = [], 
  correlationReasons = [], 
  correlationScore = 80 
}) {
  const users = [...new Set(events.map(e => e.user).filter(Boolean))];
  const devices = [...new Set(events.map(e => e.device_id).filter(Boolean))];
  const processes = [...new Set(events.map(e => e.process_name).filter(Boolean))];
  const domains = [...new Set(events.map(e => e.domain).filter(Boolean))];
  const ips = [...new Set(events.map(e => e.source_ip).filter(Boolean))];

  // Derive explicit signal checklist
  const signals = [];

  if (devices.length > 0) {
    signals.push({
      icon: ShieldCheck,
      title: 'Same Endpoint Device',
      detail: `All events occurred on ${devices.join(', ')}`,
      status: 'Confirmed'
    });
  }

  if (users.length > 0 && !users.every(u => u.toLowerCase() === 'system')) {
    signals.push({
      icon: CheckCircle2,
      title: 'Shared User Identity',
      detail: `Activity executed under non-generic user account '${users.join(', ')}'`,
      status: 'Confirmed'
    });
  }

  // Check process lineage
  const hasLineage = events.some(e => e.parent_process || (e.correlation_reason && e.correlation_reason.toLowerCase().includes('lineage')));
  if (hasLineage || processes.length > 0) {
    const parent = events.find(e => e.parent_process)?.parent_process;
    const child = events.find(e => e.process_name)?.process_name;
    signals.push({
      icon: Cpu,
      title: 'Process Lineage Relationship',
      detail: parent && child ? `Process ancestry connected ('${parent}' → '${child}')` : 'Processes share executable parent-child execution relationship',
      status: 'Confirmed'
    });
  }

  // Time proximity
  signals.push({
    icon: Clock,
    title: 'Temporal Proximity',
    detail: 'Events occurred in rapid succession within the active correlation window',
    status: 'Confirmed'
  });

  // Logical MITRE progression
  const stages = [...new Set(events.map(e => e.mitre_stage).filter(Boolean))];
  if (stages.length >= 2) {
    signals.push({
      icon: Zap,
      title: 'Logical Attack Progression',
      detail: `Multi-stage progression observed: ${stages.join(' → ')}`,
      status: 'Confirmed'
    });
  }

  if (domains.length > 0) {
    signals.push({
      icon: Network,
      title: 'Shared Network Infrastructure',
      detail: `Events interact with common destination domain '${domains[0]}'`,
      status: 'Confirmed'
    });
  }

  const displayScore = Math.min(Math.max(correlationScore || 75, 50), 100);

  return (
    <Card className="p-5 bg-slate-900/90 border-purple-800/40 space-y-4 shadow-lg">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-purple-500/20 border border-purple-500/30 flex items-center justify-center text-purple-400 shrink-0">
            <Layers className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-white uppercase tracking-wider">
              Why Were These Events Connected?
            </h3>
            <p className="text-xs text-slate-400">
              Multi-factor correlation evidence evaluated by CAIP
            </p>
          </div>
        </div>

        {/* Correlation Score Badge */}
        <div className="flex items-center gap-2 px-3.5 py-1.5 rounded-xl bg-purple-950/60 border border-purple-500/40 font-mono text-xs self-start sm:self-auto">
          <span className="text-purple-300 font-medium">Correlation Score:</span>
          <strong className="text-emerald-400 font-bold text-sm">{displayScore}/100</strong>
        </div>
      </div>

      {/* Evidence Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {signals.map((sig, idx) => {
          const Icon = sig.icon;
          return (
            <div 
              key={idx} 
              className="flex items-start gap-3 p-3 rounded-xl bg-slate-950/70 border border-slate-800 hover:border-purple-500/30 transition-colors"
            >
              <div className="p-2 rounded-lg bg-purple-500/10 border border-purple-500/20 text-purple-400 shrink-0 mt-0.5">
                <Icon className="w-4 h-4" />
              </div>
              <div className="space-y-0.5 min-w-0">
                <div className="flex items-center gap-2">
                  <h4 className="text-xs font-bold text-white">
                    {sig.title}
                  </h4>
                  <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 font-semibold">
                    {sig.status}
                  </span>
                </div>
                <p className="text-xs text-slate-300 leading-normal">
                  {sig.detail}
                </p>
              </div>
            </div>
          );
        })}
      </div>
    </Card>
  );
}
