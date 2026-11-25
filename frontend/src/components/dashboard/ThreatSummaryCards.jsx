import React from 'react';
import { AlertOctagon, Flame, ShieldAlert, Layers } from 'lucide-react';
import Card from '../common/Card';

export default function ThreatSummaryCards({ stats = {}, alerts = [], campaigns = [] }) {
  const safeStats = stats || {};
  const safeAlerts = Array.isArray(alerts) ? alerts : [];
  const safeCampaigns = Array.isArray(campaigns) ? campaigns : [];

  const criticalCount = safeAlerts.filter(a => (a?.severity || 0) >= 85).length || safeStats.critical || 0;
  const highCount = safeAlerts.filter(a => (a?.severity || 0) >= 70 && (a?.severity || 0) < 85).length || safeStats.high || 0;
  const activeCampaignsCount = safeCampaigns.length || safeStats.active_campaigns || 0;
  const activeIncidentsCount = activeCampaignsCount || (safeAlerts.length > 0 ? 1 : 0);

  const metrics = [
    {
      label: 'ACTIVE INCIDENTS',
      count: activeIncidentsCount,
      sub: 'Threat threads requiring triage',
      icon: ShieldAlert,
      text: 'text-purple-400',
      border: 'border-purple-500/20',
      bg: 'bg-purple-500/10'
    },
    {
      label: 'CRITICAL ALERTS',
      count: criticalCount,
      sub: 'Severity 85+ (Credential/C2)',
      icon: AlertOctagon,
      text: 'text-rose-400',
      border: 'border-rose-500/20',
      bg: 'bg-rose-500/10'
    },
    {
      label: 'HIGH-RISK ALERTS',
      count: highCount,
      sub: 'Severity 70–84 (Execution/Lateral)',
      icon: Flame,
      text: 'text-orange-400',
      border: 'border-orange-500/20',
      bg: 'bg-orange-500/10'
    },
    {
      label: 'ACTIVE CAMPAIGNS',
      count: activeCampaignsCount,
      sub: 'Correlated attack sequences',
      icon: Layers,
      text: 'text-cyan-400',
      border: 'border-cyan-500/20',
      bg: 'bg-cyan-500/10'
    }
  ];

  return (
    <div className="space-y-4 flex flex-col h-full">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-purple-400" />
          <h2 className="text-sm font-bold text-white uppercase tracking-wider">
            Threat & Incident Metrics
          </h2>
        </div>
      </div>

      {/* Single Unified Card */}
      <Card className="p-5 border-slate-800 flex-1 flex flex-col justify-between">
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5 h-full">
          {metrics.map((item) => {
            const Icon = item.icon;
            return (
              <div 
                key={item.label} 
                className={`p-3.5 rounded-lg bg-slate-950/70 border ${item.border} flex flex-col justify-between`}
              >
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-bold text-slate-300 uppercase tracking-wider font-mono">
                    {item.label}
                  </span>
                  <div className={`p-1 rounded ${item.bg}`}>
                    <Icon className={`w-3.5 h-3.5 ${item.text}`} />
                  </div>
                </div>

                <div className="my-1.5 flex items-baseline gap-2">
                  <span className={`text-2xl sm:text-3xl font-extrabold font-mono ${item.text}`}>
                    {item.count}
                  </span>
                </div>

                <p className="text-[11px] text-slate-400 truncate">
                  {item.sub}
                </p>
              </div>
            );
          })}
        </div>
      </Card>
    </div>
  );
}


