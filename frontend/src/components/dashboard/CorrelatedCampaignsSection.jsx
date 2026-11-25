import React from 'react';
import { Layers, ArrowRight } from 'lucide-react';
import Card from '../common/Card';
import { SeverityBadge, StatusBadge } from '../common/Badge';

export default function CorrelatedCampaignsSection({ 
  campaigns = [], 
  alerts = [], 
  onInvestigate, 
  onViewAllCampaigns 
}) {
  const topCampaigns = campaigns.slice(0, 1);

  return (
    <div className="space-y-4 flex flex-col h-full">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Layers className="w-4 h-4 text-purple-400" />
          <h2 className="text-sm font-bold text-white uppercase tracking-wider">
            Correlated Attack Campaigns
          </h2>
        </div>
        {campaigns.length > 1 && (
          <button
            onClick={onViewAllCampaigns}
            className="text-xs font-semibold text-purple-400 hover:text-purple-300 flex items-center gap-1 transition-colors"
          >
            <span>View all ({campaigns.length})</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        )}
      </div>

      {/* Campaigns Grid */}
      {topCampaigns.length === 0 ? (
        <Card className="p-8 text-center text-slate-400 flex-1 flex flex-col items-center justify-center">
          <p className="text-sm font-semibold text-slate-300">No correlated threat campaigns active right now.</p>
          <p className="text-xs text-slate-500 mt-1">CAIP is actively monitoring incoming security telemetry and correlating events across your environment.</p>
        </Card>
      ) : (
        <div className="grid grid-cols-1 gap-4 flex-1">

          {topCampaigns.map((c) => {
            const riskScore = c.risk_score || (c.risk === 'HIGH' ? 85 : c.risk === 'MEDIUM' ? 60 : 35);
            const campaignAlerts = alerts.filter(a => a.campaign_id === c.campaign_id);
            const alertCount = campaignAlerts.length || 5;
            const targetUser = c.target || campaignAlerts[0]?.user || 'Unknown User';
            const targetDevice = campaignAlerts[0]?.device_id || 'Unknown Device';

            return (
              <Card 
                key={c.campaign_id}
                hover
                onClick={() => onInvestigate(c.campaign_id)}
                className="p-5 border-slate-800 hover:border-purple-500/50 flex flex-col justify-between group transition-all"
              >
                <div>
                  <div className="flex items-start justify-between gap-2 mb-2">
                    <SeverityBadge scoreOrSeverity={riskScore} size="md" />
                    <StatusBadge status="ACTIVE" />
                  </div>

                  <h3 className="text-base font-bold text-white group-hover:text-purple-300 transition-colors mb-1.5">
                    {c.attack_type || 'Credential Theft Campaign'}
                  </h3>

                  <div className="p-2.5 rounded-lg bg-slate-950/70 border border-slate-800/80 mb-3 text-xs text-slate-300 space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="text-slate-400">Related Alerts:</span>
                      <strong className="text-white font-mono">{alertCount} related alerts</strong>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-slate-400">User:</span>
                      <strong className="text-slate-200 font-mono">{targetUser}</strong>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-slate-400">Device:</span>
                      <strong className="text-slate-200 font-mono">{targetDevice}</strong>
                    </div>
                  </div>

                  <p className="text-xs text-purple-300/90 leading-relaxed mb-3">
                    CAIP detected that these alerts are related and grouped them into one unified campaign.
                  </p>
                </div>

                <div className="pt-3 border-t border-slate-800/80 flex items-center justify-between">
                  <div className="flex items-baseline gap-1">
                    <span className="text-[10px] uppercase font-bold text-slate-500">Risk:</span>
                    <span className="text-base font-extrabold font-mono text-rose-400">{riskScore}</span>
                    <span className="text-xs font-mono text-slate-500">/ 100</span>
                  </div>

                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      onInvestigate(c.campaign_id);
                    }}
                    className="px-3 py-1.5 rounded-lg bg-purple-600 hover:bg-purple-500 text-white text-xs font-bold transition-colors inline-flex items-center gap-1 shadow-md shadow-purple-950"
                  >
                    <span>Investigate Campaign</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </Card>
            );
          })}
        </div>
      )}

    </div>
  );
}
