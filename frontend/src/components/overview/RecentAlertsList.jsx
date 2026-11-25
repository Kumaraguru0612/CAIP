import React from 'react';
import { Bell, ArrowRight, ShieldCheck, Layers } from 'lucide-react';
import Card from '../common/Card';
import { SeverityBadge } from '../common/Badge';
import { formatTimestamp, getFriendlyEventType } from '../../utils/formatters';

export default function RecentAlertsList({ alerts = [], onSelectAlert, onSelectCampaign, onViewAll }) {
  const recent = alerts.slice(0, 6);

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Bell className="w-4 h-4 text-cyan-400" />
          <h2 className="text-sm font-bold text-white uppercase tracking-wider">
            Recent Security Alerts
          </h2>
        </div>
        {alerts.length > 6 && (
          <button
            onClick={onViewAll}
            className="text-xs font-semibold text-cyan-400 hover:text-cyan-300 flex items-center gap-1 transition-colors"
          >
            <span>View all alerts ({alerts.length})</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        )}
      </div>

      {recent.length === 0 ? (
        <Card className="p-8 text-center text-slate-400">
          <p className="text-sm">No raw security alerts in buffer.</p>
          <p className="text-xs text-slate-500 mt-1">Incoming telemetry from EDR, Firewalls, and Cloud SIEM will appear here.</p>
        </Card>
      ) : (
        <Card className="p-0 overflow-hidden divide-y divide-slate-800/80">
          {recent.map((alert) => {
            const hasCampaign = Boolean(alert.campaign_id);
            return (
              <div 
                key={alert.event_id || alert.id}
                className="p-3.5 flex items-center justify-between gap-3 hover:bg-slate-800/40 transition-colors"
              >
                <div className="flex items-center gap-3 min-w-0">
                  <SeverityBadge scoreOrSeverity={alert.severity} showScore={false} />
                  
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-bold text-slate-200 truncate">
                        {getFriendlyEventType(alert.event_type)}
                      </span>
                      {hasCampaign && (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold bg-purple-500/10 text-purple-300 border border-purple-500/20">
                          <Layers className="w-2.5 h-2.5" />
                          Grouped
                        </span>
                      )}
                    </div>
                    
                    <p className="text-[11px] text-slate-400 truncate mt-0.5">
                      Target: <strong className="text-slate-300">{alert.user || alert.source_ip || 'System'}</strong> on{' '}
                      <span className="text-slate-400 font-mono">{alert.device_id || alert.source || 'Endpoint'}</span>
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-3 shrink-0">
                  <span className="text-[11px] font-mono text-slate-500">
                    {formatTimestamp(alert.timestamp)}
                  </span>
                  
                  {hasCampaign ? (
                    <button
                      onClick={() => onSelectCampaign(alert.campaign_id)}
                      className="px-2.5 py-1 rounded bg-purple-600/20 hover:bg-purple-600/30 text-purple-300 text-[11px] font-semibold border border-purple-500/30 transition-colors flex items-center gap-1"
                    >
                      <span>Campaign</span>
                      <ArrowRight className="w-3 h-3" />
                    </button>
                  ) : (
                    <button
                      onClick={() => onSelectAlert(alert)}
                      className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] font-medium transition-colors"
                    >
                      Inspect
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </Card>
      )}
    </div>
  );
}
