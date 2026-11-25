import React from 'react';
import { Layers, ArrowRight, User, Monitor, AlertCircle } from 'lucide-react';
import Card from '../common/Card';
import { SeverityBadge, StatusBadge } from '../common/Badge';

export default function ActiveCampaignsSummary({ campaigns = [], onSelectCampaign, onViewAll }) {
  const activeList = campaigns.slice(0, 3);

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Layers className="w-4 h-4 text-purple-400" />
          <h2 className="text-sm font-bold text-white uppercase tracking-wider">
            Active Threat Campaigns
          </h2>
        </div>
        {campaigns.length > 3 && (
          <button
            onClick={onViewAll}
            className="text-xs font-semibold text-purple-400 hover:text-purple-300 flex items-center gap-1 transition-colors"
          >
            <span>View all ({campaigns.length})</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        )}
      </div>

      {activeList.length === 0 ? (
        <Card className="p-8 text-center text-slate-400">
          <p className="text-sm font-semibold text-slate-300">No active attack campaigns detected.</p>
          <p className="text-xs text-slate-500 mt-1">CAIP is actively monitoring the network. Live telemetry will appear here when an incident is detected.</p>
        </Card>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3.5">
          {activeList.map((c) => {
            const riskScore = c.risk_score || (c.risk === 'HIGH' ? 85 : c.risk === 'MEDIUM' ? 60 : 35);
            return (
              <Card 
                key={c.campaign_id} 
                hover
                onClick={() => onSelectCampaign(c.campaign_id)}
                className="flex flex-col justify-between p-4.5 border-slate-800/90 hover:border-purple-500/40"
              >
                <div>
                  <div className="flex items-start justify-between gap-2 mb-2">
                    <SeverityBadge scoreOrSeverity={riskScore} size="sm" />
                    <span className="text-[11px] font-mono text-slate-500 truncate max-w-[100px]">
                      {c.campaign_id}
                    </span>
                  </div>

                  <h3 className="text-sm font-bold text-slate-100 line-clamp-1 mb-1 group-hover:text-purple-300">
                    {c.attack_type || 'Correlated Multi-Stage Incident'}
                  </h3>

                  <p className="text-xs text-slate-400 line-clamp-2 mb-3">
                    {c.stage ? `Current phase: ${c.stage.replace(/->/g, '→')}` : 'Multi-stage progression in progress'}
                  </p>

                  <div className="space-y-1.5 pt-2 border-t border-slate-800/80 text-xs text-slate-300 font-mono">
                    <div className="flex items-center gap-2 text-slate-400">
                      <User className="w-3.5 h-3.5 text-purple-400 shrink-0" />
                      <span className="truncate">User: <strong className="text-slate-200">{c.target || 'Unknown'}</strong></span>
                    </div>
                  </div>
                </div>

                <div className="mt-4 pt-3 border-t border-slate-800/60 flex items-center justify-between">
                  <div className="flex items-center gap-1.5">
                    <span className="text-[10px] uppercase font-bold text-slate-500">Risk Score:</span>
                    <span className="text-sm font-extrabold font-mono text-white">{riskScore}/100</span>
                  </div>
                  <span className="text-xs font-semibold text-purple-400 hover:text-purple-300 flex items-center gap-1">
                    <span>Investigate</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </span>
                </div>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}
