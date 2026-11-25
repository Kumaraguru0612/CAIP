import React from 'react';
import { 
  ArrowRight, 
  User, 
  Laptop, 
  Calendar,
  Layers,
  Activity,
  ShieldAlert
} from 'lucide-react';
import Card from '../common/Card';
import { SeverityBadge, StatusBadge } from '../common/Badge';
import { formatDateFull } from '../../utils/formatters';

export default function CampaignCard({ campaign, onInvestigate }) {
  const riskScore = campaign.risk_score || (campaign.risk === 'HIGH' ? 85 : campaign.risk === 'MEDIUM' ? 60 : 35);
  const stages = (campaign.stage || '').split('->').map(s => s.trim()).filter(Boolean);
  const status = campaign.status || 'Active Campaign';
  const eventCount = campaign.event_count || 1;
  const targetUser = campaign.target || 'Unknown User';
  const device = campaign.device_id || 'Windows Host';

  return (
    <Card 
      hover 
      onClick={() => onInvestigate(campaign.campaign_id)}
      className="p-5 border-slate-800/90 hover:border-purple-500/50 flex flex-col justify-between group transition-all duration-200 bg-slate-900/80 shadow-lg"
    >
      <div className="space-y-3.5">
        {/* Card Header: Severity Badge + Status + Campaign ID */}
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <SeverityBadge scoreOrSeverity={riskScore} size="sm" />
            <StatusBadge status={status} />
          </div>
          <span className="text-[11px] font-mono font-semibold px-2 py-0.5 rounded bg-slate-950/80 text-purple-300 border border-slate-800">
            {campaign.campaign_id}
          </span>
        </div>

        {/* Title / Attack Type */}
        <div>
          <h3 className="text-base font-bold text-white group-hover:text-purple-300 transition-colors line-clamp-1">
            {campaign.attack_type || 'Correlated Security Campaign'}
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            {eventCount} correlated security {eventCount === 1 ? 'event' : 'events'}
          </p>
        </div>

        {/* Attack Stage Progression */}
        {stages.length > 0 && (
          <div className="p-2.5 rounded-lg bg-slate-950/70 border border-slate-800/80">
            <span className="text-[10px] uppercase font-bold text-slate-500 block mb-1.5 font-mono">
              Observed Attack Stages:
            </span>
            <div className="flex flex-wrap items-center gap-1.5 text-xs font-mono">
              {stages.map((stage, idx) => (
                <React.Fragment key={idx}>
                  <span className="px-2 py-0.5 rounded bg-purple-500/15 text-purple-300 border border-purple-500/30 text-[11px] font-semibold">
                    {stage}
                  </span>
                  {idx < stages.length - 1 && (
                    <span className="text-slate-600 font-sans text-xs">→</span>
                  )}
                </React.Fragment>
              ))}
            </div>
          </div>
        )}

        {/* Affected Entities Metadata (User, Device, Start Time) */}
        <div className="grid grid-cols-2 gap-2 text-xs text-slate-300 pt-2 border-t border-slate-800/80">
          <div className="flex items-center gap-2 min-w-0">
            <User className="w-3.5 h-3.5 text-purple-400 shrink-0" />
            <span className="truncate">User: <strong className="text-white">{targetUser}</strong></span>
          </div>
          <div className="flex items-center gap-2 min-w-0">
            <Laptop className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
            <span className="truncate">Device: <strong className="text-white">{device}</strong></span>
          </div>
          <div className="flex items-center gap-2 col-span-2 text-slate-400">
            <Calendar className="w-3.5 h-3.5 text-slate-500 shrink-0" />
            <span>Started: {formatDateFull(campaign.created_at)}</span>
          </div>
        </div>

      </div>

      {/* Card Footer: Risk Score & Action Button */}
      <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between">
        <div className="flex items-baseline gap-1.5 font-mono">
          <span className="text-[10px] uppercase font-bold text-slate-500">Risk:</span>
          <span className="text-base font-extrabold text-rose-400">{riskScore}</span>
          <span className="text-xs text-slate-500">/100</span>
        </div>

        <button
          onClick={(e) => {
            e.stopPropagation();
            onInvestigate(campaign.campaign_id);
          }}
          className="px-3.5 py-1.5 rounded-lg bg-purple-600/20 group-hover:bg-purple-600 text-purple-300 group-hover:text-white text-xs font-bold border border-purple-500/40 transition-all inline-flex items-center gap-1.5 shadow-sm"
        >
          <span>Investigate</span>
          <ArrowRight className="w-3.5 h-3.5" />
        </button>
      </div>
    </Card>
  );
}
