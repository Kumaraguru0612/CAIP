import React from 'react';
import { AlertOctagon, Flame, AlertTriangle, ShieldCheck, Zap } from 'lucide-react';
import Card from '../common/Card';

export default function ThreatSummary({ stats = {} }) {
  const {
    critical = 0,
    high = 0,
    medium = 0,
    low = 0,
    alerts_received = 0,
    alerts_correlated = 0,
    active_campaigns = 0
  } = stats;

  const reductionPct = alerts_received > 0 
    ? Math.round(((alerts_received - active_campaigns) / alerts_received) * 100)
    : 0;

  const tiers = [
    {
      label: 'Critical Threats',
      count: critical,
      sub: 'Immediate action required',
      icon: AlertOctagon,
      bg: 'bg-rose-500/10',
      border: 'border-rose-500/30',
      text: 'text-rose-400',
      glow: 'shadow-[0_0_20px_rgba(244,63,94,0.15)]'
    },
    {
      label: 'High Threats',
      count: high,
      sub: 'Active lateral / cred risk',
      icon: Flame,
      bg: 'bg-orange-500/10',
      border: 'border-orange-500/30',
      text: 'text-orange-400',
      glow: 'shadow-[0_0_20px_rgba(249,115,22,0.15)]'
    },
    {
      label: 'Medium Threats',
      count: medium,
      sub: 'Suspicious anomaly',
      icon: AlertTriangle,
      bg: 'bg-amber-500/10',
      border: 'border-amber-500/30',
      text: 'text-amber-400',
      glow: 'shadow-[0_0_20px_rgba(245,158,11,0.15)]'
    },
    {
      label: 'Low / Info',
      count: low,
      sub: 'Monitored events',
      icon: ShieldCheck,
      bg: 'bg-emerald-500/10',
      border: 'border-emerald-500/30',
      text: 'text-emerald-400',
      glow: 'shadow-[0_0_20px_rgba(16,185,129,0.15)]'
    }
  ];

  return (
    <div className="space-y-4">
      {/* Visual Differentiator Banner: Many Alerts -> One Campaign */}
      <div className="p-4 rounded-xl bg-gradient-to-r from-purple-950/40 via-slate-900/80 to-cyan-950/30 border border-purple-800/30 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-purple-600/20 border border-purple-500/30 flex items-center justify-center text-purple-400 shrink-0">
            <Zap className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-white flex items-center gap-2">
              <span>Automated Alert Correlation Active</span>
              <span className="text-[11px] px-2 py-0.5 rounded-full bg-cyan-500/20 text-cyan-300 font-mono font-normal border border-cyan-500/30">
                {active_campaigns} Active Campaign{active_campaigns !== 1 ? 's' : ''}
              </span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              CAIP ingested <strong className="text-slate-200">{alerts_received} alerts</strong> and synthesized them into <strong className="text-purple-300">{active_campaigns} unified threat threads</strong> ({reductionPct > 0 ? `${reductionPct}% alert reduction` : '100% triage coverage'}).
            </p>
          </div>
        </div>

        <div className="flex items-center gap-4 text-xs font-mono shrink-0 pl-12 sm:pl-0">
          <div className="text-right">
            <span className="text-slate-500 block text-[10px] uppercase">Alerts Ingested</span>
            <span className="text-slate-200 font-bold">{alerts_received}</span>
          </div>
          <div className="text-slate-600 font-sans">→</div>
          <div className="text-right">
            <span className="text-purple-400 block text-[10px] uppercase font-bold">Campaigns</span>
            <span className="text-purple-300 font-bold text-sm">{active_campaigns}</span>
          </div>
        </div>
      </div>

      {/* 4 Threat Tiers */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3.5">
        {tiers.map((tier) => {
          const Icon = tier.icon;
          return (
            <Card key={tier.label} className={`p-4 border ${tier.border} ${tier.bg} ${tier.glow}`}>
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
                  {tier.label}
                </span>
                <Icon className={`w-4 h-4 ${tier.text}`} />
              </div>
              <div className="mt-2 flex items-baseline gap-2">
                <span className={`text-2xl sm:text-3xl font-extrabold font-mono ${tier.text}`}>
                  {tier.count}
                </span>
              </div>
              <p className="text-[11px] text-slate-400 mt-1 truncate">
                {tier.sub}
              </p>
            </Card>
          );
        })}
      </div>
    </div>
  );
}
